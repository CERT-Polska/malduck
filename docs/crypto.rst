Cryptography
=======================

.. automodule:: malduck.crypto

AES
--------------

.. autofunction:: malduck.aes.cbc
.. autofunction:: malduck.aes.ecb
.. autofunction:: malduck.aes.ctr

.. autoclass:: malduck.crypto.aes.AES
    :members:

Blowfish
---------

.. autofunction:: malduck.blowfish

DES3
--------------

.. autofunction:: malduck.des3.cbc

Serpent
--------------

.. autofunction:: malduck.serpent

Rabbit
--------------

.. autofunction:: malduck.rabbit

RC4
--------------

.. autofunction:: malduck.rc4

RSA
--------------

.. autoclass:: malduck.rsa
    :members:

.. autoclass:: malduck.crypto.rsa.RSA
    :members:

XOR
--------------

.. autofunction:: malduck.xor

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
