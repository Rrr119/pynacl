Key Derivation
==============

.. currentmodule:: nacl.kdf

A key derivation function derives one or more subkeys from a single
high-entropy master key. The same master key and subkey identifier always
produce the same subkey, while distinct identifiers (or distinct contexts)
produce independent subkeys.

The :py:class:`KDF` class wraps libsodium's BLAKE2b based ``crypto_kdf``
primitive. It is intended for deriving keys from an existing *random* master
key; it must not be used to hash passwords, which are low entropy and require
a password hashing function such as the ones in :py:mod:`nacl.pwhash`.

Usage
-----

Generate a master key and derive a couple of subkeys:

.. testcode::

    import nacl.kdf

    master_key = nacl.kdf.KDF.keygen()

    # The context identifies what the derived keys are used for and must be
    # exactly nacl.kdf.KDF.CONTEXT_SIZE (8) bytes long.
    kdf = nacl.kdf.KDF(master_key, b"enc keys")

    encryption_key = kdf.derive(32, 1)
    authentication_key = kdf.derive(32, 2)

    print(len(encryption_key), len(authentication_key))

.. testoutput::

    32 32

A subkey length must be between :py:data:`KDF.BYTES_MIN` and
:py:data:`KDF.BYTES_MAX` (16 to 64 bytes), and the subkey identifier is an
unsigned 64 bit integer:

.. testcode::

    short_key = kdf.derive(nacl.kdf.KDF.BYTES_MIN, 0)
    print(len(short_key))

.. testoutput::

    16

The same parameters always derive the same subkey, and a different context
isolates subkeys even when the master key and identifier are shared:

.. testcode::

    other_kdf = nacl.kdf.KDF(master_key, b"mac keys")

    print(kdf.derive(32, 1) == kdf.derive(32, 1))
    print(kdf.derive(32, 1) == other_kdf.derive(32, 1))

.. testoutput::

    True
    False

The master key may also be passed through an encoder, like the rest of the
high level API:

.. testcode::

    import nacl.encoding

    encoded = nacl.encoding.HexEncoder.encode(master_key)
    decoded_kdf = nacl.kdf.KDF(
        encoded, b"enc keys", encoder=nacl.encoding.HexEncoder
    )

    print(decoded_kdf.derive(32, 1) == kdf.derive(32, 1))

.. testoutput::

    True
