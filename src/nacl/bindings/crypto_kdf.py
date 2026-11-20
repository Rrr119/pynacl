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

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

__all__ = [
    "crypto_kdf_BYTES_MAX",
    "crypto_kdf_BYTES_MIN",
    "crypto_kdf_CONTEXTBYTES",
    "crypto_kdf_KEYBYTES",
    "crypto_kdf_PRIMITIVE",
    "crypto_kdf_derive_from_key",
    "crypto_kdf_keygen",
]

"""
Key derivation functions (crypto_kdf, BLAKE2b based).
"""
crypto_kdf_BYTES_MIN: int = lib.crypto_kdf_bytes_min()
crypto_kdf_BYTES_MAX: int = lib.crypto_kdf_bytes_max()
crypto_kdf_CONTEXTBYTES: int = lib.crypto_kdf_contextbytes()
crypto_kdf_KEYBYTES: int = lib.crypto_kdf_keybytes()
crypto_kdf_PRIMITIVE: str = ffi.string(lib.crypto_kdf_primitive()).decode(
    "ascii"
)


def crypto_kdf_keygen() -> bytes:
    """
    Generate a new master key suitable for
    :func:`crypto_kdf_derive_from_key`.

    :return: a master key of :data:`crypto_kdf_KEYBYTES` bytes
    :rtype: bytes
    """
    key = ffi.new("unsigned char[]", crypto_kdf_KEYBYTES)
    lib.crypto_kdf_keygen(key)
    return ffi.buffer(key, crypto_kdf_KEYBYTES)[:]


def crypto_kdf_derive_from_key(
    subkey_len: int,
    subkey_id: int,
    context: bytes,
    key: bytes,
) -> bytes:
    """
    Derive a subkey from a master ``key``.

    :param subkey_len: length of the derived subkey, in bytes; it must be
                       between :data:`crypto_kdf_BYTES_MIN` and
                       :data:`crypto_kdf_BYTES_MAX` (inclusive).
    :type subkey_len: int
    :param subkey_id: the numeric identifier of the subkey to derive
                      (a non-negative 64 bit integer).
    :type subkey_id: int
    :param context: a ``bytes`` sequence of exactly
                    :data:`crypto_kdf_CONTEXTBYTES` bytes, used to separate
                    subkeys derived for different uses.
    :type context: bytes
    :param key: the master key, a ``bytes`` sequence of exactly
                :data:`crypto_kdf_KEYBYTES` bytes.
    :type key: bytes
    :return: the derived subkey
    :rtype: bytes
    """
    ensure(
        isinstance(subkey_len, int)
        and not isinstance(subkey_len, bool)
        and crypto_kdf_BYTES_MIN <= subkey_len <= crypto_kdf_BYTES_MAX,
        "subkey_len must be an integer between "
        f"{crypto_kdf_BYTES_MIN} and {crypto_kdf_BYTES_MAX}",
        raising=exc.TypeError,
    )
    ensure(
        isinstance(subkey_id, int)
        and not isinstance(subkey_id, bool)
        and 0 <= subkey_id <= (2**64 - 1),
        "subkey_id must be an unsigned 64 bit integer",
        raising=exc.TypeError,
    )
    ensure(
        isinstance(context, bytes) and len(context) == crypto_kdf_CONTEXTBYTES,
        f"context must be a {crypto_kdf_CONTEXTBYTES} byte long bytes "
        "sequence",
        raising=exc.TypeError,
    )
    ensure(
        isinstance(key, bytes) and len(key) == crypto_kdf_KEYBYTES,
        f"key must be a {crypto_kdf_KEYBYTES} byte long bytes sequence",
        raising=exc.TypeError,
    )

    subkey = ffi.new("unsigned char[]", subkey_len)
    res = lib.crypto_kdf_derive_from_key(
        subkey, subkey_len, subkey_id, context, key
    )
    ensure(
        res == 0,
        "Subkey derivation failed.",
        raising=exc.CryptoError,
    )

    return ffi.buffer(subkey, subkey_len)[:]
