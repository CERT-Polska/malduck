Cryptography
=======================

.. automodule:: malduck.crypto

Common cryptography algorithms used in malware.

AES
--------------

AES (Advanced Encryption Standard) block cipher.

Supported modes: CBC, ECB, CTR.

.. code-block:: python

    from malduck import aes

    key = b'A'*16
    iv = b'B'*16
    plaintext = b'data'*16
    ciphertext = aes.cbc.encrypt(key, iv, plaintext)


AES-CBC mode
~~~~~~~~~~~~
.. autofunction:: malduck.aes.cbc.encrypt
.. autofunction:: malduck.aes.cbc.decrypt

AES-ECB mode
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: malduck.aes.ecb.encrypt
.. autofunction:: malduck.aes.ecb.decrypt

AES-CTR mode
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: malduck.aes.ctr.encrypt
.. autofunction:: malduck.aes.ctr.decrypt

Blowfish (ECB only)
-------------------

Blowfish block cipher.

Supported modes: ECB.

.. code-block:: python

    from malduck import blowfish

    key = b'blowfish'
    plaintext = b'data'*16
    ciphertext = blowfish.ecb.encrypt(key, plaintext)


.. autofunction:: malduck.blowfish.ecb.encrypt
.. autofunction:: malduck.blowfish.ecb.decrypt

ChaCha20
--------

ChaCha20 stream cipher.

Assumes empty nonce if none given.

.. code-block:: python

    from malduck import chacha20

    key = b'chachaKeyHereNow' * 2
    nonce = b'\x01\x02\x03\x04\x05\0x6\0x7'
    plaintext = b'data'*16
    ciphertext = chacha20.decrypt(key, plaintext, nonce)

.. autofunction:: malduck.chacha20.encrypt
.. autofunction:: malduck.chacha20.decrypt

DES/DES3 (CBC only)
-------------------

Triple DES block cipher.

Fallbacks to single DES for 8 byte keys.

Supported modes: CBC.

.. code-block:: python

    from malduck import des3

    key = b'des3des3'
    iv = b'3des3des'
    plaintext = b'data' * 16
    ciphertext = des3.cbc.encrypt(key, plaintext)

.. autofunction:: malduck.des3.cbc.encrypt
.. autofunction:: malduck.des3.cbc.decrypt

Salsa20
--------

Salsa20 stream cipher.

Assumes empty nonce if none given.

.. code-block:: python

    from malduck import salsa20

    key = b'salsaFTW' * 4
    nonce = b'\x01\x02\x03\x04\x05\0x6\0x7'
    plaintext = b'data' * 16
    ciphertext = salsa20.decrypt(key, plaintext, nonce)

.. autofunction:: malduck.salsa20.encrypt
.. autofunction:: malduck.salsa20.decrypt


Serpent (CBC only)
------------------

Serpent block cipher.

Supported modes: CBC

.. code-block:: python

    from malduck import serpent

    key = b'a'*16
    iv = b'b'*16
    plaintext = b'data'*16
    ciphertext = serpent.cbc.encrypt(key, plaintext, iv=iv)

.. autofunction:: malduck.serpent.cbc.encrypt
.. autofunction:: malduck.serpent.cbc.decrypt

Rabbit
--------------

Rabbit stream cipher.

.. code-block:: python

    from malduck import rabbit

    key = b'a'*16
    iv = b'b'*16
    plaintext = b'data'*16
    ciphertext = rabbit(key, iv, plaintext)

.. autofunction:: malduck.rabbit

RC4
--------------

RC4 stream cipher.

.. code-block:: python

    from malduck import rc4

    key = b'a'*16
    plaintext = b'data'*16
    ciphertext = rc4(key, plaintext)

.. autofunction:: malduck.rc4

XOR
--------------

XOR "stream cipher".

.. code-block:: python

    from malduck import xor

    key = b'a'*16
    xored = b'data'*16
    unxored = xor(key, xored)

.. autofunction:: malduck.xor

RSA (BLOB parser)
-----------------

.. autoclass:: malduck.rsa
    :members:

.. autoclass:: malduck.crypto.rsa.RSA
    :members:

BLOB struct
-----------

.. autoclass:: malduck.crypto.winhdr.BLOBHEADER
    :members:

.. autoclass:: malduck.crypto.aes.PlaintextKeyBlob
    :members:

.. autoclass:: malduck.crypto.rsa.PublicKeyBlob
    :members:

.. autoclass:: malduck.crypto.rsa.PrivateKeyBlob
    :members:
