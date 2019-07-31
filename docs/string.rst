Common string operations (padding, chunks, base64)
==================================================

.. automodule:: malduck.string


Supports most common string operations e.g.:

* packing/unpacking:
    :py:func:`p64`, :py:func:`p32`, :py:func:`p16`, :py:func:`p8`

    :py:func:`u64`, :py:func:`u32`, :py:func:`u16`, :py:func:`u8`

* chunks: :py:func:`chunks_iter`, :py:func:`chunks`

chunks/chunks_iter
-------------------

.. autofunction:: malduck.chunks_iter
.. autofunction:: malduck.chunks

asciiz/utf16z
--------------

.. autofunction:: malduck.asciiz
.. autofunction:: malduck.utf16z

enhex/unhex
----------
.. autofunction:: malduck.enhex
.. autofunction:: malduck.unhex

.. autofunction:: malduck.uleb128
.. autofunction:: malduck.base64

Padding (null/pkcs7)
---------------------

.. autofunction:: malduck.pad
.. autofunction:: malduck.unpad

Packing/unpacking (p64/p32/p16/p8, u64/u32/u16/u8, bigint)
-----------------------------------------------------------

.. autofunction:: malduck.uint64
.. autofunction:: malduck.uint32
.. autofunction:: malduck.uint16
.. autofunction:: malduck.uint8

.. autofunction:: malduck.u64
.. autofunction:: malduck.u32
.. autofunction:: malduck.u16
.. autofunction:: malduck.u8
.. autofunction:: malduck.p64
.. autofunction:: malduck.p32
.. autofunction:: malduck.p16
.. autofunction:: malduck.p8

.. autofunction:: malduck.bigint

IPv4 inet_ntoa
---------------
.. autofunction:: malduck.ipv4
