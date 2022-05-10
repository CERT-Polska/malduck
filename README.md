# :duck: Malduck

## [Installation ⚙️](#how-to-start) | [Docs 📚](https://malduck.readthedocs.io/en/latest/)

---

Malduck is your ducky companion in malware analysis journeys. It is mostly based on [Roach](https://github.com/hatching/roach) project, which derives many concepts from [mlib](https://github.com/mak/mlib) 
library created by [Maciej Kotowicz](https://lokalhost.pl). The purpose of fork was to make Roach independent from [Cuckoo Sandbox](https://cuckoosandbox.org/) project, but still supporting its internal `procmem` format.

Malduck provides many improvements resulting from CERT.pl codebase, making scripts written for malware analysis purposes much shorter and more powerful. 

## Features

- **Cryptography** (AES, Blowfish, Camelie, ChaCha20, Serpent and many others)
- **Compression algorithms** (aPLib, gzip, LZNT1 (RtlDecompressBuffer))
- **Memory model objects** (work on memory dumps, PE/ELF, raw files and IDA dumps using the same code)
- **Extraction engine** (modular extraction framework for config extraction from files/dumps)
- Fixed integer types (like Uint64) and bitwise utilities
- String operations (chunks, padding, packing/unpacking etc)
- Hashing algorithms (CRC32, MD5, SHA1, SHA256)

## Usage examples

#### AES

```python
from malduck import aes

key = b'A'*16
iv = b'B'*16
plaintext = b'data'*16
ciphertext = aes.cbc.encrypt(key, iv, plaintext)
```

### Serpent

```python
from malduck import serpent

key = b'a'*16
iv = b'b'*16
plaintext = b'data'*16
ciphertext = serpent.cbc.encrypt(key, plaintext, iv)
```

### APLib decompression

```python
from malduck import aplib

# Headerless compressed buffer
aplib(b'T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00')
```

### Fixed integer types

```python
from malduck import DWORD

def sdbm_hash(name: bytes) -> int:
    hh = 0
    for c in name:
        # operations on the DWORD type produce a dword, so a result
        # is also a DWORD.
        hh = DWORD(c) + (hh << 6) + (hh << 16) - hh
    return int(hh)
```

### Extractor engine - module example

```python
from malduck import Extractor

class Citadel(Extractor):
    family = "citadel"
    yara_rules = ("citadel",)
    overrides = ("zeus",)

    @Extractor.string("briankerbs")
    def citadel_found(self, p, addr, match):
        log.info('[+] `Coded by Brian Krebs` str @ %X' % addr)
        return True

    @Extractor.string
    def cit_login(self, p, addr, match):
        log.info('[+] Found login_key xor @ %X' % addr)
        hit = p.uint32v(addr + 4)
        print(hex(hit))
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}

        hit = p.uint32v(addr + 5)
        print(hex(hit))
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}
```

### Memory model objects

```python
from malduck import procmempe

with procmempe.from_file("notepad.exe", image=True) as p:
    resource_data = p.pe.resource("NPENCODINGDIALOG")
```

## How to start

Install it by running

```shell
pip install malduck
```

More documentation can be found on [readthedocs](https://malduck.readthedocs.io/en/latest/).

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
