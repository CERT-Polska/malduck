# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import codecs
import click

from .procmem import CuckooProcessMemory
from .py2compat import ensure_string


@click.group()
def main():
    pass


@main.command("cuckoomem.list")
@click.argument("mempath", type=click.Path(exists=True))
def cuckoomem_list(mempath):
    with CuckooProcessMemory.from_file(mempath) as p:
        for region in p.regions:
            print("0x%08x .. 0x%08x %s" % (region.addr, region.addr + region.size,
                                           ensure_string(codecs.escape_encode(p.readv(region.addr, 16))[0])))
