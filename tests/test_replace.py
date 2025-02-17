from gold_rs import Coin
from gold_rs.sized_ints import uint64
from gold_rs.sized_bytes import bytes32
import pytest

coin = b"bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
parent = b"edededededededededededededededed"
ph = b"abababababababababababababababab"
ph2 = b"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
sig = b"abababababababababababababababababababababababab"


def test_coin_replace_parent() -> None:
    c1 = Coin(coin, ph, uint64(1000000))
    c2 = c1.replace(parent_coin_info=bytes32(parent))
    assert c1.parent_coin_info == coin
    assert c2.parent_coin_info == parent


def test_coin_replace_amount() -> None:
    c1 = Coin(coin, ph, uint64(1000000))
    c2 = c1.replace(amount=uint64(100))
    assert c1.amount == 1000000
    assert c2.amount == 100


def test_coin_replace_ph_amount() -> None:
    c1 = Coin(coin, ph, uint64(1000000))
    c2 = c1.replace(amount=uint64(100), puzzle_hash=bytes32(ph2))
    assert c1.amount == 1000000
    assert c1.puzzle_hash == ph
    assert c2.amount == 100
    assert c2.puzzle_hash == ph2


def test_coin_replace_fail() -> None:
    c1 = Coin(coin, ph, uint64(1000000))
    with pytest.raises(KeyError, match="unknown field foobar"):
        c1.replace(amount=uint64(100), foobar=ph2)  # type: ignore[call-arg]
