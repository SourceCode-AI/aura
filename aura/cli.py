import textwrap
from pathlib import Path

import click
import simplejson as json

from .uri_handlers.base import URIHandler
from .uri_handlers.handlers import *  # Dummy import to register URI handlers
from .package_analyzer import Analyzer
from .scan_results import ScanResults
from .diff import DiffAnalyzer
from . import utils


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
            help_text += f"\n{uhelp}"

    return help_text


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('--format', 'out_type', default='text', type=click.Choice(['text', 'json']), help="Output format")
@click.option('--min-score', default=0, type=click.INT, help="Output only scans with at least minimum score")
@click.pass_context
def cli(ctx, **kwargs):
    """Package security aura project"""
    ctx.obj.update(kwargs)


@cli.command(name='scan', help=scan_help_text())
@click.argument('uri', metavar='<SCAN_URI>')
@click.option('-v', '--verbose', count=True)
@click.pass_context
def scan(ctx, uri, verbose=0):
    handler = URIHandler.from_uri(uri)

    if handler is None:
        raise ValueError("Could not find a handler for provided URI")
    try:
        for location in handler.get_paths():
            scan = ScanResults(location.name)
            sandbox = Analyzer(location=location, callback=scan.signal)
            sandbox.run(strip_path=location.parent)

            if scan.score < ctx.obj['min_score']:
                continue

            if ctx.obj['out_type'] == 'json':
                click.echo(json.dumps(scan.json, default=utils.json_encoder))
            else:
                scan.pprint(verbose=verbose)
    finally:
        handler.cleanup()


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


def main():
    cli(obj={
        'out_type': 'text',
        'min_score': 0,
        'release': 'latest'
    })


if __name__ == '__main__':
    main()
