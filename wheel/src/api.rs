use crate::run_generator::{run_block_generator, run_block_generator2};
use chia_consensus::allocator::make_allocator;
use chia_consensus::consensus_constants::ConsensusConstants;
use chia_consensus::gen::conditions::MempoolVisitor;
use chia_consensus::gen::flags::{
    AGG_SIG_ARGS, ALLOW_BACKREFS, ANALYZE_SPENDS, COND_ARGS_NIL, DISALLOW_INFINITY_G1,
    ENABLE_MESSAGE_CONDITIONS, ENABLE_SOFTFORK_CONDITION, MEMPOOL_MODE,
    NO_RELATIVE_CONDITIONS_ON_EPHEMERAL, NO_UNKNOWN_CONDS, STRICT_ARGS_COUNT,
};
use chia_consensus::gen::owned_conditions::{OwnedSpend, OwnedSpendBundleConditions};
use chia_consensus::gen::run_puzzle::run_puzzle as native_run_puzzle;
use chia_consensus::gen::solution_generator::solution_generator as native_solution_generator;
use chia_consensus::gen::solution_generator::solution_generator_backrefs as native_solution_generator_backrefs;
use chia_consensus::merkle_set::compute_merkle_set_root as compute_merkle_root_impl;
use chia_consensus::merkle_tree::{validate_merkle_proof, MerkleSet};
use chia_protocol::{
    BlockRecord, Bytes32, ChallengeBlockInfo, ChallengeChainSubSlot, ClassgroupElement, Coin,
    CoinSpend, CoinState, CoinStateFilters, CoinStateUpdate, EndOfSubSlotBundle, Foliage,
    FoliageBlockData, FoliageTransactionBlock, FullBlock, HeaderBlock,
    InfusedChallengeChainSubSlot, NewCompactVDF, NewPeak, NewPeakWallet,
    NewSignagePointOrEndOfSubSlot, NewTransaction, NewUnfinishedBlock, NewUnfinishedBlock2,
    PoolTarget, Program, ProofBlockHeader, ProofOfSpace, PuzzleSolutionResponse, RecentChainData,
    RegisterForCoinUpdates, RegisterForPhUpdates, RejectAdditionsRequest, RejectBlock,
    RejectBlockHeaders, RejectBlocks, RejectCoinState, RejectHeaderBlocks, RejectHeaderRequest,
    RejectPuzzleSolution, RejectPuzzleState, RejectRemovalsRequest, RequestAdditions, RequestBlock,
    RequestBlockHeader, RequestBlockHeaders, RequestBlocks, RequestChildren, RequestCoinState,
    RequestCompactVDF, RequestFeeEstimates, RequestHeaderBlocks, RequestMempoolTransactions,
    RequestPeers, RequestProofOfWeight, RequestPuzzleSolution, RequestPuzzleState, RequestRemovals,
    RequestRemoveCoinSubscriptions, RequestRemovePuzzleSubscriptions, RequestSesInfo,
    RequestSignagePointOrEndOfSubSlot, RequestTransaction, RequestUnfinishedBlock,
    RequestUnfinishedBlock2, RespondAdditions, RespondBlock, RespondBlockHeader,
    RespondBlockHeaders, RespondBlocks, RespondChildren, RespondCoinState, RespondCompactVDF,
    RespondEndOfSubSlot, RespondFeeEstimates, RespondHeaderBlocks, RespondPeers,
    RespondProofOfWeight, RespondPuzzleSolution, RespondPuzzleState, RespondRemovals,
    RespondRemoveCoinSubscriptions, RespondRemovePuzzleSubscriptions, RespondSesInfo,
    RespondSignagePoint, RespondToCoinUpdates, RespondToPhUpdates, RespondTransaction,
    RespondUnfinishedBlock, RewardChainBlock, RewardChainBlockUnfinished, RewardChainSubSlot,
    SendTransaction, SpendBundle, SubEpochChallengeSegment, SubEpochData, SubEpochSegments,
    SubEpochSummary, SubSlotData, SubSlotProofs, TimestampedPeerInfo, TransactionAck,
    TransactionsInfo, UnfinishedBlock, UnfinishedHeaderBlock, VDFInfo, VDFProof, WeightProof,
};
use clvm_utils::tree_hash_from_bytes;
use clvmr::{ENABLE_BLS_OPS_OUTSIDE_GUARD, ENABLE_FIXED_DIV, LIMIT_HEAP, NO_UNKNOWN_OPS};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;
use pyo3::types::PyList;
use pyo3::types::PyTuple;
use pyo3::wrap_pyfunction;
use std::iter::zip;

use crate::run_program::{run_chia_program, serialized_length};

use crate::adapt_response::eval_err_to_pyresult;
use chia_consensus::fast_forward::fast_forward_singleton as native_ff;
use chia_consensus::gen::get_puzzle_and_solution::get_puzzle_and_solution_for_coin as parse_puzzle_solution;
use chia_consensus::gen::validation_error::ValidationErr;
use clvmr::allocator::NodePtr;
use clvmr::cost::Cost;
use clvmr::reduction::EvalErr;
use clvmr::reduction::Reduction;
use clvmr::run_program;
use clvmr::serde::node_to_bytes;
use clvmr::serde::{node_from_bytes, node_from_bytes_backrefs};
use clvmr::ChiaDialect;

use chia_bls::{
    hash_to_g2 as native_hash_to_g2, BlsCache, DerivableKey, GTElement, PublicKey, SecretKey,
    Signature,
};

#[pyfunction]
pub fn compute_merkle_set_root<'p>(
    py: Python<'p>,
    values: Vec<&'p PyBytes>,
) -> PyResult<Bound<'p, PyBytes>> {
    let mut buffer = Vec::<[u8; 32]>::with_capacity(values.len());
    for b in values {
        buffer.push(b.as_bytes().try_into()?);
    }
    Ok(PyBytes::new_bound(
        py,
        &compute_merkle_root_impl(&mut buffer),
    ))
}

#[pyfunction]
pub fn confirm_included_already_hashed(
    root: Bytes32,
    item: Bytes32,
    proof: &[u8],
) -> PyResult<bool> {
    validate_merkle_proof(proof, (&item).into(), (&root).into())
        .map_err(|_| PyValueError::new_err("Invalid proof"))
}

#[pyfunction]
pub fn confirm_not_included_already_hashed(
    root: Bytes32,
    item: Bytes32,
    proof: &[u8],
) -> PyResult<bool> {
    validate_merkle_proof(proof, (&item).into(), (&root).into())
        .map_err(|_| PyValueError::new_err("Invalid proof"))
        .map(|r| !r)
}

#[pyfunction]
pub fn tree_hash(py: Python, blob: PyBuffer<u8>) -> PyResult<Bound<PyBytes>> {
    if !blob.is_c_contiguous() {
        panic!("tree_hash() must be called with a contiguous buffer");
    }
    let slice =
        unsafe { std::slice::from_raw_parts(blob.buf_ptr() as *const u8, blob.len_bytes()) };
    Ok(PyBytes::new_bound(py, &tree_hash_from_bytes(slice)?))
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
pub fn get_puzzle_and_solution_for_coin(
    py: Python<'_>,
    program: PyBuffer<u8>,
    args: PyBuffer<u8>,
    max_cost: Cost,
    find_parent: Bytes32,
    find_amount: u64,
    find_ph: Bytes32,
    flags: u32,
) -> PyResult<(Bound<PyBytes>, Bound<PyBytes>)> {
    let mut allocator = make_allocator(LIMIT_HEAP);

    if !program.is_c_contiguous() {
        panic!("program must be contiguous");
    }
    let program =
        unsafe { std::slice::from_raw_parts(program.buf_ptr() as *const u8, program.len_bytes()) };

    if !args.is_c_contiguous() {
        panic!("args must be contiguous");
    }
    let args = unsafe { std::slice::from_raw_parts(args.buf_ptr() as *const u8, args.len_bytes()) };

    let deserialize = if (flags & ALLOW_BACKREFS) != 0 {
        node_from_bytes_backrefs
    } else {
        node_from_bytes
    };
    let program = deserialize(&mut allocator, program)?;
    let args = deserialize(&mut allocator, args)?;
    let dialect = &ChiaDialect::new(flags);

    let r = py.allow_threads(|| -> Result<(NodePtr, NodePtr), EvalErr> {
        let Reduction(_cost, result) =
            run_program(&mut allocator, dialect, program, args, max_cost)?;
        match parse_puzzle_solution(&allocator, result, find_parent, find_amount, find_ph) {
            Err(ValidationErr(n, _)) => Err(EvalErr(n, "coin not found".to_string())),
            Ok(pair) => Ok(pair),
        }
    });

    // keep serializing normally, until wallets support backrefs
    let serialize = node_to_bytes;
    /*
        let serialize = if (flags & ALLOW_BACKREFS) != 0 {
            node_to_bytes_backrefs
        } else {
            node_to_bytes
        };
    */
    match r {
        Err(eval_err) => eval_err_to_pyresult(eval_err, allocator),
        Ok((puzzle, solution)) => Ok((
            PyBytes::new_bound(py, &serialize(&allocator, puzzle)?),
            PyBytes::new_bound(py, &serialize(&allocator, solution)?),
        )),
    }
}

#[pyfunction]
fn run_puzzle(
    puzzle: &[u8],
    solution: &[u8],
    parent_id: &[u8],
    amount: u64,
    max_cost: Cost,
    flags: u32,
) -> PyResult<OwnedSpendBundleConditions> {
    let mut a = make_allocator(LIMIT_HEAP);
    let conds = native_run_puzzle::<MempoolVisitor>(
        &mut a, puzzle, solution, parent_id, amount, max_cost, flags,
    )?;
    Ok(OwnedSpendBundleConditions::from(&a, conds)?)
}

// this is like a CoinSpend but with references to the puzzle and solution,
// rather than owning them
type CoinSpendRef = (Coin, PyBackedBytes, PyBackedBytes);

fn convert_list_of_tuples(spends: &Bound<PyAny>) -> PyResult<Vec<CoinSpendRef>> {
    let mut native_spends = Vec::<CoinSpendRef>::new();
    for s in spends.iter()? {
        let s = s?;
        let tuple = s.downcast::<PyTuple>()?;
        let coin = tuple.get_item(0)?.extract::<Coin>()?;
        let puzzle = tuple.get_item(1)?.extract::<PyBackedBytes>()?;
        let solution = tuple.get_item(2)?.extract::<PyBackedBytes>()?;
        native_spends.push((coin, puzzle, solution));
    }
    Ok(native_spends)
}

#[pyfunction]
fn solution_generator<'p>(py: Python<'p>, spends: &Bound<PyAny>) -> PyResult<Bound<'p, PyBytes>> {
    let spends = convert_list_of_tuples(spends)?;
    Ok(PyBytes::new_bound(py, &native_solution_generator(spends)?))
}

#[pyfunction]
fn solution_generator_backrefs<'p>(
    py: Python<'p>,
    spends: &Bound<PyAny>,
) -> PyResult<Bound<'p, PyBytes>> {
    let spends = convert_list_of_tuples(spends)?;
    Ok(PyBytes::new_bound(
        py,
        &native_solution_generator_backrefs(spends)?,
    ))
}

#[pyclass]
struct AugSchemeMPL {}

#[pymethods]
impl AugSchemeMPL {
    #[staticmethod]
    #[pyo3(signature = (pk,msg,prepend_pk=None))]
    pub fn sign(pk: &SecretKey, msg: &[u8], prepend_pk: Option<&PublicKey>) -> Signature {
        match prepend_pk {
            Some(prefix) => {
                let mut aug_msg = prefix.to_bytes().to_vec();
                aug_msg.extend_from_slice(msg);
                chia_bls::sign_raw(pk, aug_msg)
            }
            None => chia_bls::sign(pk, msg),
        }
    }

    #[staticmethod]
    pub fn aggregate(sigs: &Bound<PyList>) -> PyResult<Signature> {
        let mut ret = Signature::default();
        for p2 in sigs {
            ret += &p2.extract::<Signature>()?;
        }
        Ok(ret)
    }

    #[staticmethod]
    pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        chia_bls::verify(sig, pk, msg)
    }

    #[staticmethod]
    pub fn aggregate_verify(
        pks: &Bound<PyList>,
        msgs: &Bound<PyList>,
        sig: &Signature,
    ) -> PyResult<bool> {
        let mut data = Vec::<(PublicKey, Vec<u8>)>::new();
        if pks.len() != msgs.len() {
            return Err(PyRuntimeError::new_err(
                "aggregate_verify expects the same number of public keys as messages",
            ));
        }
        for (pk, msg) in zip(pks, msgs) {
            let pk = pk.extract::<PublicKey>()?;
            let msg = msg.extract::<Vec<u8>>()?;
            data.push((pk, msg));
        }

        Ok(chia_bls::aggregate_verify(sig, data))
    }

    #[staticmethod]
    pub fn g2_from_message(msg: &[u8]) -> Signature {
        native_hash_to_g2(msg)
    }

    #[staticmethod]
    pub fn derive_child_sk(sk: &SecretKey, index: u32) -> SecretKey {
        sk.derive_hardened(index)
    }

    #[staticmethod]
    pub fn derive_child_sk_unhardened(sk: &SecretKey, index: u32) -> SecretKey {
        sk.derive_unhardened(index)
    }

    #[staticmethod]
    pub fn derive_child_pk_unhardened(pk: &PublicKey, index: u32) -> PublicKey {
        pk.derive_unhardened(index)
    }

    #[staticmethod]
    pub fn key_gen(seed: &[u8]) -> PyResult<SecretKey> {
        if seed.len() < 32 {
            return Err(PyRuntimeError::new_err(
                "Seed size must be at leat 32 bytes",
            ));
        }
        Ok(SecretKey::from_seed(seed))
    }
}

#[pyfunction]
fn supports_fast_forward(spend: &CoinSpend) -> bool {
    // the test function just attempts the rebase onto a dummy parent coin
    let new_parent = Coin {
        parent_coin_info: [0_u8; 32].into(),
        puzzle_hash: spend.coin.puzzle_hash,
        amount: spend.coin.amount,
    };
    let new_coin = Coin {
        parent_coin_info: new_parent.coin_id(),
        puzzle_hash: spend.coin.puzzle_hash,
        amount: spend.coin.amount,
    };

    let mut a = make_allocator(LIMIT_HEAP);
    let Ok(puzzle) = node_from_bytes(&mut a, spend.puzzle_reveal.as_slice()) else {
        return false;
    };
    let Ok(solution) = node_from_bytes(&mut a, spend.solution.as_slice()) else {
        return false;
    };

    native_ff(
        &mut a,
        puzzle,
        solution,
        &spend.coin,
        &new_coin,
        &new_parent,
    )
    .is_ok()
}

#[pyfunction]
fn fast_forward_singleton<'p>(
    py: Python<'p>,
    spend: &CoinSpend,
    new_coin: &Coin,
    new_parent: &Coin,
) -> PyResult<Bound<'p, PyBytes>> {
    let mut a = make_allocator(LIMIT_HEAP);
    let puzzle = node_from_bytes(&mut a, spend.puzzle_reveal.as_slice())?;
    let solution = node_from_bytes(&mut a, spend.solution.as_slice())?;

    let new_solution = native_ff(&mut a, puzzle, solution, &spend.coin, new_coin, new_parent)?;
    Ok(PyBytes::new_bound(
        py,
        node_to_bytes(&a, new_solution)?.as_slice(),
    ))
}

#[pymodule]
pub fn gold_rs(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    // generator functions
    m.add_function(wrap_pyfunction!(run_block_generator, m)?)?;
    m.add_function(wrap_pyfunction!(run_block_generator2, m)?)?;
    m.add_function(wrap_pyfunction!(run_puzzle, m)?)?;
    m.add_function(wrap_pyfunction!(solution_generator, m)?)?;
    m.add_function(wrap_pyfunction!(solution_generator_backrefs, m)?)?;
    m.add_function(wrap_pyfunction!(supports_fast_forward, m)?)?;
    m.add_function(wrap_pyfunction!(fast_forward_singleton, m)?)?;
    m.add_class::<OwnedSpendBundleConditions>()?;
    m.add(
        "ELIGIBLE_FOR_DEDUP",
        chia_consensus::gen::conditions::ELIGIBLE_FOR_DEDUP,
    )?;
    m.add(
        "ELIGIBLE_FOR_FF",
        chia_consensus::gen::conditions::ELIGIBLE_FOR_FF,
    )?;
    m.add_class::<OwnedSpend>()?;

    // constants
    m.add_class::<ConsensusConstants>()?;

    // merkle tree
    m.add_class::<MerkleSet>()?;
    m.add_function(wrap_pyfunction!(confirm_included_already_hashed, m)?)?;
    m.add_function(wrap_pyfunction!(confirm_not_included_already_hashed, m)?)?;

    // clvm functions
    m.add("COND_ARGS_NIL", COND_ARGS_NIL)?;
    m.add("NO_UNKNOWN_CONDS", NO_UNKNOWN_CONDS)?;
    m.add("STRICT_ARGS_COUNT", STRICT_ARGS_COUNT)?;
    m.add("AGG_SIG_ARGS", AGG_SIG_ARGS)?;
    m.add("ENABLE_FIXED_DIV", ENABLE_FIXED_DIV)?;
    m.add("ENABLE_SOFTFORK_CONDITION", ENABLE_SOFTFORK_CONDITION)?;
    m.add("ENABLE_MESSAGE_CONDITIONS", ENABLE_MESSAGE_CONDITIONS)?;
    m.add(
        "NO_RELATIVE_CONDITIONS_ON_EPHEMERAL",
        NO_RELATIVE_CONDITIONS_ON_EPHEMERAL,
    )?;
    m.add("MEMPOOL_MODE", MEMPOOL_MODE)?;
    m.add("ALLOW_BACKREFS", ALLOW_BACKREFS)?;
    m.add("ANALYZE_SPENDS", ANALYZE_SPENDS)?;
    m.add("DISALLOW_INFINITY_G1", DISALLOW_INFINITY_G1)?;

    // Chia classes
    m.add_class::<Coin>()?;
    m.add_class::<PoolTarget>()?;
    m.add_class::<ClassgroupElement>()?;
    m.add_class::<EndOfSubSlotBundle>()?;
    m.add_class::<TransactionsInfo>()?;
    m.add_class::<FoliageTransactionBlock>()?;
    m.add_class::<FoliageBlockData>()?;
    m.add_class::<Foliage>()?;
    m.add_class::<ProofOfSpace>()?;
    m.add_class::<RewardChainBlockUnfinished>()?;
    m.add_class::<RewardChainBlock>()?;
    m.add_class::<ChallengeBlockInfo>()?;
    m.add_class::<ChallengeChainSubSlot>()?;
    m.add_class::<InfusedChallengeChainSubSlot>()?;
    m.add_class::<RewardChainSubSlot>()?;
    m.add_class::<SubSlotProofs>()?;
    m.add_class::<SpendBundle>()?;
    m.add_class::<Program>()?;
    m.add_class::<CoinSpend>()?;
    m.add_class::<VDFInfo>()?;
    m.add_class::<VDFProof>()?;
    m.add_class::<SubSlotData>()?;
    m.add_class::<SubEpochData>()?;
    m.add_class::<SubEpochChallengeSegment>()?;
    m.add_class::<SubEpochSegments>()?;
    m.add_class::<SubEpochSummary>()?;
    m.add_class::<UnfinishedBlock>()?;
    m.add_class::<FullBlock>()?;
    m.add_class::<BlockRecord>()?;
    m.add_class::<WeightProof>()?;
    m.add_class::<RecentChainData>()?;
    m.add_class::<ProofBlockHeader>()?;
    m.add_class::<TimestampedPeerInfo>()?;

    // wallet protocol
    m.add_class::<RequestPuzzleSolution>()?;
    m.add_class::<PuzzleSolutionResponse>()?;
    m.add_class::<RespondPuzzleSolution>()?;
    m.add_class::<RejectPuzzleSolution>()?;
    m.add_class::<SendTransaction>()?;
    m.add_class::<TransactionAck>()?;
    m.add_class::<NewPeakWallet>()?;
    m.add_class::<RequestBlockHeader>()?;
    m.add_class::<RespondBlockHeader>()?;
    m.add_class::<RejectHeaderRequest>()?;
    m.add_class::<RequestRemovals>()?;
    m.add_class::<RespondRemovals>()?;
    m.add_class::<RejectRemovalsRequest>()?;
    m.add_class::<RequestAdditions>()?;
    m.add_class::<RespondAdditions>()?;
    m.add_class::<RejectAdditionsRequest>()?;
    m.add_class::<RespondBlockHeaders>()?;
    m.add_class::<RejectBlockHeaders>()?;
    m.add_class::<RequestBlockHeaders>()?;
    m.add_class::<RequestHeaderBlocks>()?;
    m.add_class::<RejectHeaderBlocks>()?;
    m.add_class::<RespondHeaderBlocks>()?;
    m.add_class::<HeaderBlock>()?;
    m.add_class::<UnfinishedHeaderBlock>()?;
    m.add_class::<CoinState>()?;
    m.add_class::<RegisterForPhUpdates>()?;
    m.add_class::<RespondToPhUpdates>()?;
    m.add_class::<RegisterForCoinUpdates>()?;
    m.add_class::<RespondToCoinUpdates>()?;
    m.add_class::<CoinStateUpdate>()?;
    m.add_class::<RequestChildren>()?;
    m.add_class::<RespondChildren>()?;
    m.add_class::<RequestSesInfo>()?;
    m.add_class::<RespondSesInfo>()?;
    m.add_class::<RequestFeeEstimates>()?;
    m.add_class::<RespondFeeEstimates>()?;
    m.add_class::<RequestRemovePuzzleSubscriptions>()?;
    m.add_class::<RespondRemovePuzzleSubscriptions>()?;
    m.add_class::<RequestRemoveCoinSubscriptions>()?;
    m.add_class::<RespondRemoveCoinSubscriptions>()?;
    m.add_class::<CoinStateFilters>()?;
    m.add_class::<RequestPuzzleState>()?;
    m.add_class::<RespondPuzzleState>()?;
    m.add_class::<RejectPuzzleState>()?;
    m.add_class::<RequestCoinState>()?;
    m.add_class::<RespondCoinState>()?;
    m.add_class::<RejectCoinState>()?;

    // full node protocol
    m.add_class::<NewPeak>()?;
    m.add_class::<NewTransaction>()?;
    m.add_class::<RequestTransaction>()?;
    m.add_class::<RespondTransaction>()?;
    m.add_class::<RequestProofOfWeight>()?;
    m.add_class::<RespondProofOfWeight>()?;
    m.add_class::<RequestBlock>()?;
    m.add_class::<RejectBlock>()?;
    m.add_class::<RequestBlocks>()?;
    m.add_class::<RespondBlocks>()?;
    m.add_class::<RejectBlocks>()?;
    m.add_class::<RespondBlock>()?;
    m.add_class::<NewUnfinishedBlock>()?;
    m.add_class::<RequestUnfinishedBlock>()?;
    m.add_class::<RespondUnfinishedBlock>()?;
    m.add_class::<NewSignagePointOrEndOfSubSlot>()?;
    m.add_class::<RequestSignagePointOrEndOfSubSlot>()?;
    m.add_class::<RespondSignagePoint>()?;
    m.add_class::<RespondEndOfSubSlot>()?;
    m.add_class::<RequestMempoolTransactions>()?;
    m.add_class::<NewCompactVDF>()?;
    m.add_class::<RequestCompactVDF>()?;
    m.add_class::<RespondCompactVDF>()?;
    m.add_class::<RequestPeers>()?;
    m.add_class::<RespondPeers>()?;
    m.add_class::<NewUnfinishedBlock2>()?;
    m.add_class::<RequestUnfinishedBlock2>()?;

    // facilities from clvm_rs

    m.add_function(wrap_pyfunction!(run_chia_program, m)?)?;
    m.add("NO_UNKNOWN_OPS", NO_UNKNOWN_OPS)?;
    m.add("LIMIT_HEAP", LIMIT_HEAP)?;
    m.add("ENABLE_BLS_OPS_OUTSIDE_GUARD", ENABLE_BLS_OPS_OUTSIDE_GUARD)?;

    m.add_function(wrap_pyfunction!(serialized_length, m)?)?;
    m.add_function(wrap_pyfunction!(compute_merkle_set_root, m)?)?;
    m.add_function(wrap_pyfunction!(tree_hash, m)?)?;
    m.add_function(wrap_pyfunction!(get_puzzle_and_solution_for_coin, m)?)?;

    // facilities from chia-bls

    m.add_class::<PublicKey>()?;
    m.add_class::<Signature>()?;
    m.add_class::<GTElement>()?;
    m.add_class::<SecretKey>()?;
    m.add_class::<AugSchemeMPL>()?;
    m.add_class::<BlsCache>()?;

    Ok(())
}
