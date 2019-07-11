# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import codecs
import click
import os

from .procmem import CuckooProcessMemory, ProcessMemoryPE
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


@main.command("fixpe")
@click.argument("mempath", type=click.Path(exists=True))
@click.argument("outpath", type=click.Path(), required=False)
@click.option("--force/--no-force", "-f", default=False, help="Try to fix dump even if it's correctly parsed as PE")
def fixpe(mempath, outpath, force):
    with ProcessMemoryPE.from_file(mempath) as p:
        if not force and p.is_image_loaded_as_memdump():
            click.echo("Input file looks like correct PE file. Use -f if you want to fix it anyway.")
            return 1
        outpath = outpath or mempath + ".exe"
        if not force and os.path.isfile(outpath):
            click.confirm("{} exists. Overwrite?".format(outpath), abort=True)
        with open(outpath, "wb") as f:
            f.write(p.store())
        click.echo("Fixed {} => {}".format(mempath, outpath))
