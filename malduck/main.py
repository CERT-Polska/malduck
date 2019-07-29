import click
import os

from .procmem import ProcessMemoryPE


@click.group()
def main():
    pass


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
