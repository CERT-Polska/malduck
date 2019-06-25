# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import click

from .procmem import CuckooProcessMemory


@click.group()
def main():
    pass


@main.command("cuckoomem.list")
@click.argument("mempath", type=click.Path(exists=True))
def cuckoomem_list(mempath):
    with CuckooProcessMemory.from_file(mempath) as p:
        for region in p.regions:
            print "0x%08x .. 0x%08x" % (region.addr, region.addr + region.size),
            print repr(p.readv(region.addr, 16))
