"""
Main CLI for the Project Aura
"""

import json
import sys
import textwrap
from pathlib import Path

import click

from . import commands
from .uri_handlers.base import URIHandler
from .diff import DiffAnalyzer

from .analyzers.base import get_analyzers

from . import utils
from . import exceptions
from . import config


LOGGER = config.get_logger(__name__)
CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help']
)


def scan_help_text():
    help_text = """
    Perform a security audit for a given package/data
    """

    help_text = textwrap.dedent(help_text)

    for uri_handler in URIHandler.__subclasses__():
        if hasattr(uri_handler, 'help'):
            uhelp = textwrap.dedent(uri_handler.help).strip()
            help_text += f"\n{uhelp}\n"

    return help_text


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('--format', 'out_type', default='text', type=click.Choice(['text', 'json']), help="Output format")
@click.option('--min-score', default=0, type=click.INT, help="Output only scans with at least minimum score")
@click.pass_context
def cli(ctx, **kwargs):
    """Package security aura project"""
    if ctx.obj:  # TODO: remove and transition to scan options
        ctx.obj.update(kwargs)


@cli.command(name='scan', help=scan_help_text())
@click.argument('uri', metavar='<SCAN_URI>')
@click.option('-v', '--verbose', count=True)
@click.option('-a', '--analyzer', help="Specify analyzer to run")
@click.option('-f', '--format', 'out_type', default='text', type=click.Choice(['text', 'json']), help="Output format")
@click.pass_context
def scan(ctx, uri, verbose=0, analyzer=None, out_type='plain'):
    meta = {
        'verbosity': verbose,
        'format': out_type,
        'min_score': ctx.obj.get('min_score'),
    }

    commands.scan_uri(uri, metadata=meta, analyzer=analyzer)

    sys.exit(0)


@cli.command(name='diff')
@click.argument('pth1', metavar='<FIRST PATH>')
@click.argument('pth2', metavar='<SECOND PATH>')
@click.pass_context
def diff(ctx, pth1, pth2):
    pth1 = Path(pth1)
    pth2 = Path(pth2)

    da = DiffAnalyzer()
    da.compare(pth1, pth2)
    da.pprint()


@cli.command(name='parse_ast')
@click.argument('path')
#@click.option('--raw', is_flag=True, default=False, help="Print raw AST tree as received from parser")
def parse_ast(path):
    commands.parse_ast(path)

@cli.command(name='info')
def info():
    analyzers = get_analyzers()
    if analyzers:
        click.secho("Installed analyzers:", color='green')
        for x in analyzers.values():
            click.secho(f" - {x.analyzer_id}")
    else:
        click.secho("No installed analyzers found!", color='red', blink=True, bold=True)

    click.secho(f"Installed URI handlers:")
    for k, v in URIHandler.load_handlers().items():
        click.secho(f"- '{k}://'")


@cli.group('r2c')
def r2c():
    pass

@r2c.command(name='generate_input')
@click.argument('out_file', metavar='<OUTPUT FILE>', type=click.File('w'))
def generate_input(out_file):
    commands.generate_r2c_input(out_file)


@r2c.command(name='scan')
@click.option('--out', default='/analysis/output/output.json', type=click.File('w'))
@click.option('--mode', default='generic')
@click.argument('source', nargs=-1, type=click.Path())
def run_r2c_analyzer(source, out, mode):
    commands.r2c_scan(source=source, out_file=out, mode=mode)


@cli.command(name='check_requirement')
def check_requirement():
    """
    Perform security check of the given requirement
    This command is used for integration with package managers (e.g. PIP)

    :return:
    """
    payload = json.loads(sys.stdin.read())
    commands.check_requirement(payload)


def main():
    cli(obj={
        'out_type': config.CFG.get('aura', 'output-format') or 'text',
        'min_score': 0,
        'release': 'latest'
    })


if __name__ == '__main__':
    main()
