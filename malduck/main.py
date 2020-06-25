import click
import logging
import json
import os

from .procmem import ProcessMemoryPE


@click.group()
@click.option(
    "--log-level",
    "-l",
    type=str,
    default=None,
    help="Set logging level for commands: critical, error, warning (default), info, debug",
)
@click.option(
    "--verbose/--quiet",
    "-v/-q",
    default=None,
    help="Verbose mode (shortcut for '--log-level debug') / quiet mode ('--log-level error')",
)
@click.version_option()
def main(log_level, verbose):
    if log_level is None:
        if verbose is None:
            log_level = "warning"
        else:
            log_level = "debug" if verbose else "error"
    log_level = logging.getLevelName(log_level.upper())
    logging.basicConfig(level=log_level)
    logging.captureWarnings(True)


@main.command("fixpe")
@click.argument("mempath", type=click.Path(exists=True))
@click.argument("outpath", type=click.Path(), required=False)
@click.option(
    "--force/--no-force",
    "-f",
    default=False,
    help="Try to fix dump even if it's correctly parsed as PE",
)
def fixpe(mempath, outpath, force):
    """Fix dumped PE file into the correct form"""
    with ProcessMemoryPE.from_file(mempath) as p:
        if not force and p.is_image_loaded_as_memdump():
            click.echo(
                "Input file looks like correct PE file. Use -f if you want to fix it anyway."
            )
            return 1
        outpath = outpath or mempath + ".exe"
        if not force and os.path.isfile(outpath):
            click.confirm(f"{outpath} exists. Overwrite?", abort=True)
        with open(outpath, "wb") as f:
            f.write(p.store())
        click.echo(f"Fixed {mempath} => {outpath}")


@main.command("extract")
@click.pass_context
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--base",
    "-b",
    default=None,
    help="Base address of dump (use '0x' prefix for hexadecimal value)",
)
@click.option(
    "--analysis/--files",
    default=False,
    help="Treat files as dumps from single analysis "
    "(merge configs from the same family)",
)
@click.option(
    "--modules",
    default=None,
    type=click.Path(exists=True),
    required=False,
    help="Specify directory where Yara files and modules are located (default path is ~/.malduck)",
)
def extract(ctx, paths, base, analysis, modules):
    """Extract static configuration from dumps"""
    from .extractor import ExtractManager, ExtractorModules

    def echo_config(extract_manager, file_path=None):
        if extract_manager.config:
            for config in extract_manager.config:
                family = config["family"]
                message = (
                    f"[+] Ripped '{family}' from {file_path}:"
                    if file_path is not None
                    else f"[+] Ripped '{family}' configuration:"
                )
                click.echo(message, err=True)
                click.echo(json.dumps(config, indent=4, sort_keys=True))

    if base is None:
        base = 0
    else:
        base = int(base, 0)

    extractor_modules = ExtractorModules(modules)
    extract_manager = ExtractManager(extractor_modules)

    if not extract_manager.extractors:
        click.echo(f"[!] No extractor modules found under '{modules}'!", err=True)
        ctx.abort()

    for path in paths:
        if os.path.isdir(path):
            files = filter(
                os.path.isfile, map(lambda f: os.path.join(path, f), os.listdir(path))
            )
        elif os.path.isfile(path):
            files = [path]
        else:
            files = []
            click.echo(
                f"[!] Symbolic links are not supported, {path} ignored.", err=True,
            )

        for file_path in sorted(files):
            extract_manager.push_file(file_path, base=base)
            if not analysis:
                echo_config(extract_manager, file_path)
                extract_manager = ExtractManager(extractor_modules)
        if analysis:
            echo_config(extract_manager)
