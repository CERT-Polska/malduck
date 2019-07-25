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

.. autofunction:: malduck.string.ops.chunks_iter
.. autofunction:: malduck.string.ops.chunks

asciiz/utf16z
--------------

.. autofunction:: malduck.string.ops.asciiz
.. autofunction:: malduck.string.ops.utf16z

enhex/unhex
----------
.. autofunction:: malduck.string.ops.enhex
.. autofunction:: malduck.string.ops.unhex

.. autofunction:: malduck.string.ops.uleb128
.. autoclass:: malduck.string.ops.Base64
    :members:

Padding (null/pkcs7)
---------------------

.. autoclass:: malduck.string.ops.Padding
    :members:
.. autoclass:: malduck.string.ops.Unpadding
    :members:

Packing/unpacking (p64/p32/p16/p8, u64/u32/u16/u8, bigint)
-----------------------------------------------------------

.. autofunction:: malduck.string.bin.uint64
.. autofunction:: malduck.string.bin.uint32
.. autofunction:: malduck.string.bin.uint16
.. autofunction:: malduck.string.bin.uint8

.. autofunction:: malduck.string.bin.u64
.. autofunction:: malduck.string.bin.u32
.. autofunction:: malduck.string.bin.u16
.. autofunction:: malduck.string.bin.u8
.. autofunction:: malduck.string.bin.p64
.. autofunction:: malduck.string.bin.p32
.. autofunction:: malduck.string.bin.p16
.. autofunction:: malduck.string.bin.p8

.. autofunction:: malduck.string.bin.bigint

IPv4 inet_ntoa
---------------
.. autofunction:: malduck.string.inet.ipv4
