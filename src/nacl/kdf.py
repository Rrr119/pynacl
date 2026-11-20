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

from typing import ClassVar

import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.utils import StringFixer


class KDF(encoding.Encodable, StringFixer):
    """
    The :class:`KDF` class derives subkeys from a single master key using
    the BLAKE2b based ``crypto_kdf`` primitive of libsodium.

    A different :class:`KDF` instance should be used for every distinct
    purpose: the ``context`` string is mixed into every derived subkey, so
    subkeys derived with different contexts are independent even when they
    share the same master key and subkey identifier.

    :param key: the master key, exactly :data:`KDF.KEY_SIZE` bytes once
                decoded.
    :param context: a ``bytes`` sequence of exactly
                    :data:`KDF.CONTEXT_SIZE` bytes identifying the intended
                    use of the derived subkeys.
    :param encoder: the encoder used to decode the given ``key``.

    :cvar KEY_SIZE: the required master key size, in bytes.
    :cvar CONTEXT_SIZE: the required context size, in bytes.
    :cvar BYTES_MIN: the minimum allowed subkey length, in bytes.
    :cvar BYTES_MAX: the maximum allowed subkey length, in bytes.
    """

    KEY_SIZE: ClassVar[int] = nacl.bindings.crypto_kdf_KEYBYTES
    CONTEXT_SIZE: ClassVar[int] = nacl.bindings.crypto_kdf_CONTEXTBYTES
    BYTES_MIN: ClassVar[int] = nacl.bindings.crypto_kdf_BYTES_MIN
    BYTES_MAX: ClassVar[int] = nacl.bindings.crypto_kdf_BYTES_MAX

    def __init__(
        self,
        key: bytes,
        context: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        key = encoder.decode(key)
        if not isinstance(key, bytes) or len(key) != self.KEY_SIZE:
            raise exc.TypeError(
                f"KDF must be created from a {self.KEY_SIZE} byte long bytes "
                "sequence",
            )

        if not isinstance(context, bytes) or len(context) != self.CONTEXT_SIZE:
            raise exc.TypeError(
                "The context must be a "
                f"{self.CONTEXT_SIZE} byte long bytes sequence",
            )

        self._key = key
        self._context = context

    def __bytes__(self) -> bytes:
        return self._key

    @classmethod
    def keygen(cls) -> bytes:
        """
        Generate a new random master key of :data:`KEY_SIZE` bytes.

        :return: a fresh master key
        :rtype: bytes
        """
        return nacl.bindings.crypto_kdf_keygen()

    def derive(
        self,
        subkey_len: int,
        subkey_id: int,
    ) -> bytes:
        """
        Derive a subkey from the master key.

        :param subkey_len: the length of the subkey to derive, in bytes. It
                           must be between :data:`BYTES_MIN` and
                           :data:`BYTES_MAX` (inclusive).
        :param subkey_id: the numeric identifier of the subkey. The same
                          master key, context and identifier always produce
                          the same subkey.
        :return: the derived subkey
        :rtype: bytes
        """
        if not isinstance(subkey_len, int) or isinstance(subkey_len, bool):
            raise exc.TypeError(
                "subkey_len must be an integer between "
                f"{self.BYTES_MIN} and {self.BYTES_MAX}",
            )
        if not self.BYTES_MIN <= subkey_len <= self.BYTES_MAX:
            raise exc.ValueError(
                "subkey_len must be between "
                f"{self.BYTES_MIN} and {self.BYTES_MAX} bytes",
            )
        if not isinstance(subkey_id, int) or isinstance(subkey_id, bool):
            raise exc.TypeError("subkey_id must be an unsigned 64 bit integer")
        if not 0 <= subkey_id <= (2**64 - 1):
            raise exc.ValueError(
                "subkey_id must be an unsigned 64 bit integer",
            )

        return nacl.bindings.crypto_kdf_derive_from_key(
            subkey_len, subkey_id, self._context, self._key
        )
