# Copyright 2025 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import annotations

import binascii

import pytest
from hypothesis import given, settings
from hypothesis.strategies import binary, integers

import nacl.bindings as b
import nacl.exceptions as exc
from nacl.kdf import KDF

from .utils import read_crypto_test_vectors

CONTEXT = b"KDF test"
MASTER_KEY = bytes(range(b.crypto_kdf_KEYBYTES))


def _vectors() -> list[tuple[bytes, bytes, bytes]]:
    # Type safety: every record in kdf-blake2b.txt has exactly three fields.
    return read_crypto_test_vectors(  # type: ignore[return-value]
        "kdf-blake2b.txt", delimiter=b"|"
    )


def test_crypto_kdf_constants():
    assert b.crypto_kdf_BYTES_MIN == 16
    assert b.crypto_kdf_BYTES_MAX == 64
    assert b.crypto_kdf_CONTEXTBYTES == 8
    assert b.crypto_kdf_KEYBYTES == 32
    assert b.crypto_kdf_PRIMITIVE == "blake2b"


def test_crypto_kdf_keygen():
    key = b.crypto_kdf_keygen()
    assert isinstance(key, bytes)
    assert len(key) == b.crypto_kdf_KEYBYTES
    assert key != b.crypto_kdf_keygen()


@pytest.mark.parametrize(
    ("subkey_id", "subkey_len", "expected"),
    [
        (int(sid), int(length), binascii.unhexlify(hexed))
        for sid, length, hexed in _vectors()
    ],
)
def test_crypto_kdf_derive_from_key_vectors(
    subkey_id: int, subkey_len: int, expected: bytes
):
    subkey = b.crypto_kdf_derive_from_key(
        subkey_len, subkey_id, CONTEXT, MASTER_KEY
    )
    assert subkey == expected
    assert len(subkey) == subkey_len


def test_crypto_kdf_derive_is_deterministic():
    first = b.crypto_kdf_derive_from_key(32, 1, CONTEXT, MASTER_KEY)
    second = b.crypto_kdf_derive_from_key(32, 1, CONTEXT, MASTER_KEY)
    assert first == second


def test_crypto_kdf_distinct_ids_distinct_subkeys():
    first = b.crypto_kdf_derive_from_key(32, 1, CONTEXT, MASTER_KEY)
    second = b.crypto_kdf_derive_from_key(32, 2, CONTEXT, MASTER_KEY)
    assert first != second


def test_crypto_kdf_distinct_contexts_distinct_subkeys():
    first = b.crypto_kdf_derive_from_key(32, 1, CONTEXT, MASTER_KEY)
    second = b.crypto_kdf_derive_from_key(32, 1, b"otherctx", MASTER_KEY)
    assert first != second


@given(
    key=binary(min_size=32, max_size=32),
    context=binary(min_size=8, max_size=8),
    subkey_len=integers(min_value=16, max_value=64),
    subkey_id=integers(min_value=0, max_value=2**16 - 1),
)
@settings(max_examples=20)
def test_crypto_kdf_roundtrip(
    key: bytes, context: bytes, subkey_len: int, subkey_id: int
):
    subkey = b.crypto_kdf_derive_from_key(subkey_len, subkey_id, context, key)
    assert len(subkey) == subkey_len
    assert subkey == b.crypto_kdf_derive_from_key(
        subkey_len, subkey_id, context, key
    )


@given(binary(min_size=0, max_size=31))
@settings(max_examples=20)
def test_crypto_kdf_key_too_small(key: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, CONTEXT, key)


@given(binary(min_size=33, max_size=64))
@settings(max_examples=20)
def test_crypto_kdf_key_too_large(key: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, CONTEXT, key)


@given(binary(min_size=0, max_size=7))
@settings(max_examples=20)
def test_crypto_kdf_context_too_small(context: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, context, MASTER_KEY)


@given(binary(min_size=9, max_size=16))
@settings(max_examples=20)
def test_crypto_kdf_context_too_large(context: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, context, MASTER_KEY)


@pytest.mark.parametrize("bad_len", [0, 1, 15, 65, 256])
def test_crypto_kdf_bad_subkey_len(bad_len: int):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(bad_len, 0, CONTEXT, MASTER_KEY)


@pytest.mark.parametrize("bad_id", [-1, 2**64, 2**64 + 1])
def test_crypto_kdf_bad_subkey_id(bad_id: int):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, bad_id, CONTEXT, MASTER_KEY)


@pytest.mark.parametrize("bad_value", [b"", "not-bytes", None, 32.0])
def test_crypto_kdf_bad_key_type(bad_value):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, CONTEXT, bad_value)


@pytest.mark.parametrize("bad_value", [b"", "not-bytes", None, 8])
def test_crypto_kdf_bad_context_type(bad_value):
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, 0, bad_value, MASTER_KEY)


def test_crypto_kdf_bool_rejected():
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(True, 0, CONTEXT, MASTER_KEY)
    with pytest.raises(exc.TypeError):
        b.crypto_kdf_derive_from_key(32, True, CONTEXT, MASTER_KEY)


def test_kdf_high_level_vectors():
    kdf = KDF(MASTER_KEY, CONTEXT)
    for subkey_id, subkey_len, expected in _vectors():
        assert kdf.derive(
            int(subkey_len), int(subkey_id)
        ) == binascii.unhexlify(expected)


def test_kdf_high_level_matches_binding():
    kdf = KDF(MASTER_KEY, CONTEXT)
    assert kdf.derive(32, 7) == b.crypto_kdf_derive_from_key(
        32, 7, CONTEXT, MASTER_KEY
    )


def test_kdf_high_level_keygen():
    key = KDF.keygen()
    assert len(key) == KDF.KEY_SIZE
    kdf = KDF(key, CONTEXT)
    assert bytes(kdf) == key


def test_kdf_high_level_encoder():
    import nacl.encoding

    kdf = KDF(
        MASTER_KEY.hex(),  # type: ignore[arg-type]
        CONTEXT,
        encoder=nacl.encoding.HexEncoder,
    )
    assert kdf.derive(32, 0) == b.crypto_kdf_derive_from_key(
        32, 0, CONTEXT, MASTER_KEY
    )


def test_kdf_high_level_bad_key():
    with pytest.raises(exc.TypeError):
        KDF(b"short", CONTEXT)


def test_kdf_high_level_bad_context():
    with pytest.raises(exc.TypeError):
        KDF(MASTER_KEY, b"short")


def test_kdf_high_level_bad_subkey_len():
    kdf = KDF(MASTER_KEY, CONTEXT)
    with pytest.raises(exc.TypeError):
        kdf.derive("32", 0)  # type: ignore[arg-type]
    with pytest.raises(exc.ValueError):
        kdf.derive(15, 0)
    with pytest.raises(exc.ValueError):
        kdf.derive(65, 0)


def test_kdf_high_level_bad_subkey_id():
    kdf = KDF(MASTER_KEY, CONTEXT)
    with pytest.raises(exc.TypeError):
        kdf.derive(32, 1.5)  # type: ignore[arg-type]
    with pytest.raises(exc.ValueError):
        kdf.derive(32, -1)
    with pytest.raises(exc.ValueError):
        kdf.derive(32, 2**64)
