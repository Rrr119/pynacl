nacl.kdf
========

.. currentmodule:: nacl.kdf

.. autoclass:: KDF
    :members:

nacl.bindings
=============

.. currentmodule:: nacl.bindings

The low level bindings expose the wrapped libsodium functions and constants
directly.

.. data:: crypto_kdf_BYTES_MIN

    Minimum allowed subkey length, in bytes (16).

.. data:: crypto_kdf_BYTES_MAX

    Maximum allowed subkey length, in bytes (64).

.. data:: crypto_kdf_CONTEXTBYTES

    Required length of the context, in bytes (8).

.. data:: crypto_kdf_KEYBYTES

    Required length of the master key, in bytes (32).

.. data:: crypto_kdf_PRIMITIVE

    Name of the underlying primitive (``"blake2b"``).

.. function:: crypto_kdf_keygen()

    Generate a new random master key.

    :rtype: bytes

.. function:: crypto_kdf_derive_from_key(subkey_len, subkey_id, context, key)

    Derive a ``subkey_len`` bytes long subkey identified by ``subkey_id``
    from the master ``key`` and the ``context``.

    :param int subkey_len: length of the derived subkey, between
                           :data:`crypto_kdf_BYTES_MIN` and
                           :data:`crypto_kdf_BYTES_MAX` (inclusive).
    :param int subkey_id: the unsigned 64 bit subkey identifier.
    :param bytes context: exactly :data:`crypto_kdf_CONTEXTBYTES` bytes.
    :param bytes key: exactly :data:`crypto_kdf_KEYBYTES` bytes.
    :rtype: bytes
    :raises nacl.exceptions.TypeError: if any argument has the wrong type or
                                       length.
