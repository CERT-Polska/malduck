Cockroach
=========

Cockroach is your primitive & immortal swiss army knife for research purposes.
The idea and most of the implementation is based on
`mlib <https://github.com/mak/mlib>`_ by `Maciej Kotowicz <mak@lokalhost.pl>`_.
Cockroach is designed to be used by `Cuckoo Sandbox`_ and as such is modular,
easy to modify & update, and should remain backwards compatible.

.. _`Cuckoo Sandbox`: https://cuckoosandbox.org/

Installing
==========

Installing may be performed by running::

    pip install -U roach

Currently, Cockroach works under 32-bit & 64-bit Linux, Windows, and macOS.
However, under macOS the ``aplib`` decompression isn't implemented as-is.

Overview
========

Cockroach has been designed in such a way that all of its functionality is
exposed by the main module, i.e., ``roach``, and that each exported method may
be used in an easy manner. It exposes a simple API for a number of operations.

Currently Cockroach exports the following methods:

* Compression

  - aplib
  - gzip

* Cryptography

  - AES (CBC, ECB, and CTR)
  - Blowfish
  - Rabbit
  - RC4
  - RSA
  - Triple DES
  - Xor

* Hashing

  - crc32
  - md5
  - sha1, sha224, sha256, sha384, sha512

* String

  - int/uint 8/16/32/64 serialization
  - bigint serialization
  - ipv4 parsing
  - null/pkcs7 (un)padding
  - uleb128

* Bitwise

  - rol & ror

* Disassembly

  - wrapper for x86

* Executable files

  - wrapper for PE files

* Cuckoo Process Memory Dumps

  - parsing & various operations
  - parse PE files straight from a memory dump

* Structure

  - wrapper for ``ctypes.Structure``

* Verification

  - verify ascii strings

Usage
=====

After installation, using ``roach`` in your project may look as follows.

.. code-block:: python

    from roach import rc4, aes, disasm, procmem, sha1, aplib, gzip, ...

Examples
========

Following are various examples to understand what makes ``roach`` powerful.

Cryptography
------------

.. code-block::

    >>> from roach import aes, rc4, xor
    >>> aes.cbc("cockroachislife!", "3\xbf\r\xa7\xe1\x0b\r\xd6\x85\xd0\xb4r\xfc\x0e\xa1\x22")
    'lifeiscockroach!'
    >>> rc4("thisiskey", "\xe6\xd1\xc1\xdf\xc93\xd9#\x890\xa6\xe7\xe5\xd3jL$\x98")
    'magic_happens_here'
    >>> xor("hi!", "\x00\x0cM\x04\x06\x01\x1f\x06S\x04\r")
    'hello world'

String
------

.. code-block::

    >>> from roach import int8, uint32, ipv4, pad
    >>> int8("\xff")
    -1
    >>> uint32("\xe8\x03\x00\x009\x05\x00\x00)#\x00\x00")
    (1000, 1337, 9001)
    >>> ipv4("\x7f\x00\x00\x01")
    '127.0.0.1'
    >>> ipv4(0x7f000001)
    '127.0.0.1'
    >>> ipv4("1.2.3.4")
    '1.2.3.4'
    >>> pad("roach", 8)
    'roach\x03\x03\x03'
    >>> pad.null("roach", 8)
    'roach\x00\x00\x00'

Disassembly
-----------

.. code-block::

    >>> from roach import disasm, insn
    >>> a, b = disasm("hAAAA\xc3", 0x1000)
    >>> a.mnem, a.op1.value
    (u'push', 1094795585)
    >>> str(a)
    'push 0x41414141'
    >>> str(b)
    'ret'
    >>> a == insn("push", 0x41414141, addr=0x1000)
    True
    >>> b == insn("ret", addr=0x1005)
    True

Executable files
----------------

.. code-block::

    >>> from roach import pe, asciiz
    >>> img = pe(open("tests/files/calc.exe", "rb").read(), fast_load=False)
    >>> len(list(img.resources("RT_ICON")))
    16
    >>> img.sections[0].Name
    '.text\x00\x00\x00'
    >>> asciiz(img.sections[0].Name)
    '.text'
    >>> "0x%x" % img.section(".data").VirtualAddress
    '0x54000'

Cuckoo Process Memory dumps
---------------------------

.. code-block::

    >>> from roach import procmem
    >>> p = procmem("tests/files/calc.dmp")
    >>> "0x%x" % p.findmz(0xe9999)
    '0xd0000'
    >>> p.readv(0xd0000, 8)
    'MZ\x90\x00\x03\x00\x00\x00'
    >>> p.regions[0].to_json()
    {'protect': 'r', 'end': '0x000d1000', 'addr': '0x000d0000',
     'state': 4096, 'offset': 24, 'type': 16777216, 'size': 4096}

.. code-block::

    >>> from roach import procmempe, asciiz
    >>> p = procmempe("tests/files/calc.dmp", 0xd0000)
    >>> asciiz(p.pe.sections[2].Name)
    '.rsrc'
    >>> len(list(p.pe.resources("RT_ICON")))
    16
    >>> p.imgbase == 0xd0000
    True

Structure
---------

.. code-block::

    >>> from roach import Structure, uint8, uint32
    >>> class A(Structure):
    ...   _fields_ = [
    ...     ("a", uint8),
    ...     ("b", uint8 * 3),
    ...     ("c", uint32 * 2),
    ...     ("d", 8),
    ...   ]
    ...
    >>> a = A.parse("ABBBCCCCDDDDhello!\x00\x00")
    >>> a.a == 0x41
    True
    >>> a.b == [0x42, 0x42, 0x42]
    True
    >>> a.c == [0x43434343, 0x44444444]
    True
    >>> a.d == "hello!"
    True
    >>> a.as_dict()
    {'a': 65, 'c': [1128481603L, 1145324612L], 'b': [66, 66, 66], 'd': 'hello!'}

Verification
------------

.. code-block::

    >>> from roach import verify
    >>> verify.ascii("hello")
    True
    >>> verify.ascii("binary\x00\x01data")
    False
