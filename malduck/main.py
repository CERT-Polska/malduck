import codecs
import click
import json
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
    """Fix dumped PE file into the correct form"""
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


@main.command("extract")
@click.pass_context
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
@click.option("--base", "-b", default=None, help="Base address of dump (use '0x' prefix for hexadecimal value)")
@click.option("--pe/--non-pe", default=None, help="Specified files are PE executables/dumps (default: detect)")
@click.option("--single/--multi", default=False, help="Treat files as single analysis "
                                                      "(merge all configs from the same family into one)")
@click.option("--modules", default=None, type=click.Path(exists=True), required=False,
              help="Specify directory where Yara files and modules are located (default path is ~/.malduck)")
def extract(ctx, paths, base, pe, single, modules):
    """Extract static configuration from dumps"""
    from .extractor import ExtractManager, ExtractorModules

    def echo_config(extract_manager, file_path=None):
        if extract_manager.config:
            for config in extract_manager.config:
                message = (
                    "[+] Ripped '{family}' from {file_path}:" if file_path is not None
                    else "[+] Ripped '{family}' configuration:"
                ) .format(family=config["family"], file_path=file_path)
                click.echo(message, err=True)
                click.echo(json.dumps(config, indent=4))

    if base is None:
        base = 0
    else:
        base = int(base, 0)

    extractor_modules = ExtractorModules(modules)
    extract_manager = ExtractManager(extractor_modules)

    if not extract_manager.extractors:
        click.echo("[!] No extractor modules found under '{}'!".format(modules), err=True)
        ctx.abort()

    for path in paths:
        if os.path.isdir(path):
            files = filter(os.path.isfile, map(lambda f: os.path.join(path, f), os.listdir(path)))
        elif os.path.isfile(path):
            files = [path]
        else:
            files = []
            click.echo("[!] Symbolic links are not supported, {} ignored.".format(path), err=True)

        for file_path in files:
            extract_manager.push_file(file_path, base=base, pe=pe)
            if not single:
                echo_config(extract_manager, file_path)
                extract_manager = ExtractManager(extractor_modules)
        if single:
            echo_config(extract_manager)
