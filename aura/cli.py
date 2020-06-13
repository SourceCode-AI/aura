"""
Main CLI entry point for the Aura framework
"""

import json
import sys
import os
import shutil
import textwrap
from pathlib import Path

import click
from prettyprinter import install_extras

from . import commands
from . import exceptions
from .uri_handlers.base import URIHandler, ScanLocation
from .diff import DiffAnalyzer

from . import __version__
from . import config


install_extras(include=("dataclasses",))
LOGGER = config.get_logger(__name__)
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def scan_help_text():
    help_text = """
    Perform a security audit for a given package/data
    """

    help_text = textwrap.dedent(help_text)

    for uri_handler in URIHandler.__subclasses__():
        if hasattr(uri_handler, "help"):
            uhelp = textwrap.dedent(uri_handler.help).strip()
            help_text += f"\n{uhelp}\n"

    return help_text


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx, **kwargs):
    """Package security aura project"""
    pass


@cli.command(name="scan", help=scan_help_text())
@click.argument("uri", metavar="<SCAN_URI>")
@click.option("-v", "--verbose", default=None, count=True)
@click.option("-a", "--analyzer", multiple=True, help="Specify analyzer(s) to run")
@click.option("-f", "--format", "out_type", default="text", help="Output format")
@click.option(
    "--min-score",
    default=None,
    type=click.INT,
    help="Output only scans with at least minimum score",
)
@click.option("--benchmark", is_flag=True)
@click.option("--benchmark-sort", default="cumtime")
@click.option(
    "-t", "--filter-tags",
    multiple=True,
    default=config.get_default_tag_filters(),
    help="Include or exclude results with specified tags only"
)
@click.option("--async", "fork_mode", flag_value=True)
@click.option("--no-async", "fork_mode", flag_value=False)
def scan(
    uri,
    verbose=None,
    analyzer=None,
    out_type="text",
    min_score=None,
    benchmark=False,
    benchmark_sort="cumtime",
    filter_tags=None,
    fork_mode=False
):

    output_opts = {}
    if min_score is not None:
        output_opts["min_score"] = min_score

    if verbose is not None:
        output_opts["verbosity"] = verbose + 1

    meta = {
        "format": out_type,
        "analyzers": analyzer,
        "source": "cli",
        "filter_tags": filter_tags,
        "fork": fork_mode,
        "output_opts": output_opts
    }
    if benchmark:
        import cProfile, pstats, io

        pr = cProfile.Profile()
        pr.enable()
        meta["fork"] = False
    else:
        cProfile, pstats, pr, io = None, None, None, None

    try:
        commands.scan_uri(uri, metadata=meta)
    except exceptions.AuraException as e:
        click.secho(e.args[0], err=True, fg='red')
        return sys.exit(1)

    if pr:
        pr.disable()
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats(benchmark_sort)
        ps.print_stats(.1)
        print(s.getvalue())

    sys.exit(0)


@cli.command(name="scan_mirror")
@click.option("--output_dir", metavar="<OUTPUT DIRECTORY>", default="aura_mirror_scan")
def scan_mirror(output_dir):
    output_dir = Path(output_dir)

    if not output_dir.is_dir():
        click.confirm(f"Output directory doesn't exists, do you want to create it?", abort=True)
        os.makedirs(output_dir)

    commands.scan_mirror(
        output_dir=output_dir
    )


@cli.command(name="diff")
@click.argument("pth1", metavar="<FIRST PATH>")
@click.argument("pth2", metavar="<SECOND PATH>")
@click.option("-f", "--format", default="text", help="Output URI format")
def diff(pth1, pth2, format="text"):
    commands.data_diff(
        a_path=pth1,
        b_path=pth2,
        format_uri=format
    )


@cli.command(name="parse_ast")
@click.argument("path")
@click.option(
    "--stages", "-s",
    multiple=True,
    type=click.Choice(["raw"] + list(config.get_installed_stages()), case_sensitive=False)
)
def parse_ast(path, stages=None):
    commands.parse_ast(path, stages=stages)


@cli.command(name="info")
def info():
    commands.info()


@cli.command()
@click.option(
    "-o",
    "--out",
    default=os.fspath(config.get_relative_path("pypi_stats")),
    type=click.Path(
        file_okay=True,
        dir_okay=True,
        writable=True,
        allow_dash=True
    ),
)
def fetch_pypi_stats(out):
    """
    Download the latest PyPI download stats from the public BigQuery dataset
    """
    if out !="-" and os.path.exists(out):
        LOGGER.info(f"File '{out}' exists, creating backup")
        shutil.copyfile(out, f"{out}.bak")

    with open(out, "wb") as fd:
        commands.fetch_pypi_stats(fd)


@cli.command()
@click.option("-o", "--out", default="-", type=click.File("w"))
@click.option("-m", "--max-distance", default=2, type=click.IntRange(min=0, max=10))
@click.option("-l", "--limit", default=None, type=click.INT)
def find_typosquatting(out, max_distance, limit=None):
    if limit <= 0:
        click.secho("Invalid value for limit", file=sys.stderr)
        sys.exit(1)

    commands.generate_typosquatting(out=out, distance=max_distance, limit=limit)


@cli.group("r2c")
def r2c():
    pass


@r2c.command(name="generate_input")
@click.argument("out_file", metavar="<OUTPUT FILE>", type=click.File("w"))
def generate_input(out_file):
    commands.generate_r2c_input(out_file)


@r2c.command(name="scan")
@click.option("--out", default="/analysis/output/output.json", type=click.File("w"))
@click.option("--mode", default="generic")
@click.argument("source", nargs=-1, type=click.Path())
def run_r2c_analyzer(source, out, mode):
    commands.r2c_scan(source=source, out_file=out, mode=mode)


@cli.command(name="check_requirement")
def check_requirement():
    """Perform security check of the given requirement
    This command is used for integration with package managers (e.g. pip)
    """
    payload = json.loads(sys.stdin.read())
    commands.check_requirement(payload)


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
