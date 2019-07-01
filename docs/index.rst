.. malduck documentation master file, created by
   sphinx-quickstart on Mon Apr 15 15:48:25 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to malduck's documentation!
===================================

Malduck is your ducky companion in malware analysis journeys. It is mostly based on `Roach`_ project, which derives
many concepts from `mlib`_ library created by `Maciej Kotowicz`_. The purpose of fork was to make Roach independent
from `Cuckoo Sandbox`_ project, but still supporting its internal `procmem` format.

Main goal is to make library for malware researchers, which will be something like `pwntools`_ for CTF players.

Malduck provides many improvements resulting from CERT.pl codebase, making malware analysis scripts much shorter
and more powerful.

.. _Roach: https://github.com/hatching/roach
.. _mlib: https://github.com/mak/mlib
.. _Maciej Kotowicz: mak@lokalhost.pl
.. _Cuckoo Sandbox: https://cuckoosandbox.org/
.. _pwntools: https://github.com/Gallopsled/pwntools

.. toctree::
   :maxdepth: 2
   :caption: Overview:

   crypto
   compression
   hash
   ints
   procmem
   string
   disasm
   pe


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
