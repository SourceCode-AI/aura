"""
Main CLI entry point for the Aura framework
"""

import json
import sys
import os
import pwd
import textwrap
from pathlib import Path
from tempfile import NamedTemporaryFile

import click
from prettyprinter import install_extras

from . import commands
from . import exceptions
from .cache import purge
from .uri_handlers.base import URIHandler
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
@click.option("-f", "--format", "out_type", multiple=True, help="Output format")
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
@click.option("--download-only", "download_only", flag_value=True)
def scan(
    uri,
    verbose=None,
    analyzer=None,
    out_type=("text",),
    min_score=None,
    benchmark=False,
    benchmark_sort="cumtime",
    filter_tags=None,
    fork_mode=False,
    download_only=False,
):
    output_opts = {
        "tags": filter_tags
    }
    if min_score is not None:
        output_opts["min_score"] = min_score

    if verbose is not None:
        output_opts["verbosity"] = verbose + 1

    if not out_type:
        out_type = ("text",)

    meta = {
        "format": out_type,
        "analyzers": analyzer,
        "source": "cli",
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
        commands.scan_uri(uri, metadata=meta, download_only=download_only)
    except exceptions.FeatureDisabled as e:
        LOGGER.exception(e.args[0], exc_info=e)
        click.secho(e.args[0], err=True, fg="red")
        return sys.exit(2)
    except exceptions.AuraException as e:
        click.secho(e.args[0], err=True, fg='red')
        return sys.exit(1)

    if pr:
        pr.disable()
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats(benchmark_sort)
        ps.print_stats(.1)
        print(s.getvalue())


    purge(standard=False)
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
@click.option("-f", "--format", multiple=True, help="Output URI format")
@click.option("--detections/--no-detections", "detections", is_flag=True, default=True)
@click.option("--patch/--no-patch", "patch", is_flag=True, default=True)
@click.option("--output-same-renames", "same_renames", flag_value=True)
@click.option("--no-same-renames", "same_renames", flag_value=False)
@click.option("-a", "--analyzer", multiple=True, help="Specify analyzers to run")
def diff(pth1, pth2, *, format=None, detections=True, patch=None, same_renames=None, analyzer=None):
    if not format:
        format = ("text",)

    output_opts = {
        "detections": detections,
    }

    if analyzer and detections:
        output_opts["detections"] = analyzer

    if patch is not None:
        output_opts["patch"] = patch
    if same_renames is not None:
        output_opts["output_same_renames"] = same_renames

    commands.data_diff(
        a_path=pth1,
        b_path=pth2,
        format_uri=format,
        output_opts=output_opts
    )
    purge(standard=False)


@cli.command(name="parse_ast")
@click.argument("path")
@click.option(
    "--stages", "-s",
    multiple=True,
    type=click.Choice(["raw"] + list(config.get_installed_stages()), case_sensitive=False)
)
@click.option(
    "--format", "-f",
    type=click.Choice(["text", "json"]),
    default = "text"
)
def parse_ast(path, stages=None, format="text"):
    if path == "-":
        ctx = NamedTemporaryFile(mode="w", prefix="aura_parse_ast_")
        ctx.write(sys.stdin.read())
        ctx.flush()
        path = ctx.name
    else:
        ctx = None

    try:
        commands.parse_ast(path, stages=stages, format=format)
    except exceptions.PythonExecutorError as exc:
        print(exc.stderr.decode(), file=sys.stderr)
    finally:
        if ctx:
            ctx.close()



@cli.command(name="info")
def info():
    commands.show_info()
    purge(standard=True)


@cli.command(name="update")
def update_aura():
    from . import update
    purge(standard=True)
    update.update_all()


@cli.command()
@click.option("-m", "--max-distance", default=2, type=click.IntRange(min=1, max=10))
@click.option("-l", "--limit", default=100, type=click.INT)
@click.option("-f", "--format", default="text")
@click.option("-e", "--extended", is_flag=True, default=False, help="Enable extended checks and integrations")
@click.argument("pkg", nargs=-1)
def find_typosquatting(max_distance, limit=100, pkg=None, format="text", extended=False):
    if limit <= 0:
        click.secho("Invalid value for limit", file=sys.stderr)
        sys.exit(1)

    commands.generate_typosquatting(distance=max_distance, limit=limit, pkgs=pkg, format_uri=format, extended=extended)


@cli.command()
@click.argument("uris", type=click.File("r"))
@click.option("--workers", "-w", type=int, default=10)
def prefetch(uris, workers=10):
    from . import prefetch as pf

    pf.prefetch_mirror(pf.read_uris(uris), workers=workers)


@cli.command(name="check_requirement")
def check_requirement():
    """Perform security check of the given requirement
    This command is used for integration with package managers (e.g. pip)
    """
    payload = json.loads(sys.stdin.read())
    commands.check_requirement(payload)


@cli.command()
@click.option("--tag", "-t", multiple=True)
def cleanup(tag=None):
    commands.cleanup(cache_tags=tag)


def main():
    if "AURA_USER" in os.environ:
        username = os.environ["AURA_USER"]
        u = pwd.getpwnam(username)
        LOGGER.info(f"Changing user to {username} (UID: {u.pw_uid})")
        os.seteuid(u.pw_uid)

    cli(obj={})


if __name__ == "__main__":
    main()
