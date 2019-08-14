import sys
import os
import json
import time
import pprint
from pathlib import Path
from functools import partial

import click

from .package_analyzer import Analyzer
from .scan_results import ScanResults
from .uri_handlers.base import URIHandler, ScanLocation

from . import __version__ as version
from . import config
from . import exceptions
from . import utils
from . import mirror
from . import plugins
from . import typos
from .package import PypiPackage

logger = config.get_logger(__name__)


def check_requirement(pkg):
    click.secho("Received payload from package manager, running security audit...")

    handler = URIHandler.from_uri(f"{pkg['path']}")
    try:
        metadata = {
            'uri_input': 'pkg_path',
            'source': 'package_manager',
            'pm_data': pkg,
            'format': 'plain',
            'min_score': 0
        }

        for location in handler.get_paths():
            # print(f"Enumerating: {location}")
            scan = scan_worker(location, metadata)

            scan.pprint()

        typosquatting = typos.check_name(pkg['name'])
        if typosquatting:
            click.secho("Possible typosquatting detected", fg='red', bold=True, blink=True)
            click.secho(f"Following {len(typosquatting)} packages with similar names has been found:")
            for x in typosquatting:
                click.echo(f" - '{x}'")

    finally:
        handler.cleanup()
    sys.exit(1)


def scan_worker(item, metadata):
    item_metadata = metadata.copy()
    if 'path' not in item_metadata:
        item_metadata['path'] = item.location

    if not item.location.exists():
        logger.warn(f"Location '{item.location}' does not exists. Skipping")
        return

    scan = ScanResults(
        item.location.name,
        metadata=item_metadata,
    )

    sandbox = Analyzer(location=item.location)

    hits = sandbox.run(strip_path=item.location.parent, metadata=item_metadata)

    for x in hits:
        scan.add_hit(x)

    return scan


def scan_uri(uri, metadata=None):
    start = time.time()
    handler = None
    metadata = metadata or {}
    output_format = metadata.get('format', 'plain')
    all_hits = []

    try:
        handler = URIHandler.from_uri(uri)

        if handler is None:
            raise ValueError(f"Could not find a handler for provided URI: '{uri}'")

        metadata.update({
            'uri_scheme': handler.scheme,
            'uri_input': handler.metadata,
            'source': 'cli',  # TODO: migrate to passed metadata
        })

        for x in handler.get_paths(): #type: ScanLocation
            scan = scan_worker(x, metadata)

            if scan is not None:
                if scan.score < metadata.get('min_score', 0):
                    continue

                if output_format == 'json':
                    click.echo(json.dumps(scan.json, default=utils.json_encoder))
                elif output_format == 'none':
                    pass
                else:
                    scan.pprint(verbose=metadata.get('verbosity', 0))

                all_hits.append(scan.json)

    except exceptions.NoSuchPackage:
        logger.warn(f"No such package: {uri}")
    except Exception:
        logger.exception(f"An error was thrown while processing URI: '{uri}'")
        raise
    finally:
        if handler:
            handler.cleanup()

    logger.info(f"Scan finished in {time.time() - start} s")
    return all_hits


def parse_ast(path):
    from .analyzers.python.taint.visitor import TaintAnalysis

    meta = {
        'path': path,
        'source': 'cli'
    }

    analyzer = TaintAnalysis.from_cache(source=path, metadata=meta)
    if not analyzer.traversed:
        analyzer.traverse()

    tree = json.dumps(analyzer.tree['ast_tree'], default=utils.json_encoder, indent=2)
    print(tree)
    print("\n\n---\n\n")
    pprint.pprint(analyzer.tree['ast_tree'])

    #traversal = execution_flow.ExecutionFlow.from_cache(source=path, metadata=meta)
    #if not traversal.traversed:
    #    traversal.traverse()

    #pprint.pprint(traversal.tree)
    #if traversal.hits:
    #    print("\n---[ Hits ]---\n")
    #    for x in traversal.hits:
    #        print(" * " + repr(x._asdict()))


def info():
    """
    Collect and print information about the framework environment and plugins
    """
    click.secho(f"---[ Aura framework version {version} ]---", fg='blue', bold=True)
    analyzers = plugins.load_entrypoint('aura.analyzers')
    if not analyzers['entrypoints']:
        click.secho("No analyzers available", color='red', blink=True, bold=True)
    else:
        click.echo("Available analyzers:")

    for k, v in analyzers['entrypoints'].items():
        click.echo(f" * {k} - {getattr(v, 'analyzer_description', 'Description N/A')}")

    if analyzers['disabled']:
        click.secho("Disabled analyzers:", color='red', bold=True)
        for (k, v) in analyzers['disabled']:
            click.echo(f" * {k.name} - {v}")

    click.secho(f"\nAvailable URI handlers:")
    for k, v in URIHandler.load_handlers().items():
        click.secho(f"- '{k}://'")

    click.echo("\nExternal integrations:")
    tokens = {'librariesio': "Libraries.io API"}
    for k, v in tokens.items():
        t = config.get_token(k)
        fg = 'green' if t is not None else 'red'
        status = 'enabled' if t is not None else 'Disabled - Token not found'
        click.secho(f" * {v}: {status}", fg=fg)

        try:
            from google.cloud import bigquery
            client = bigquery.Client()
            client.get_service_account_email()
            click.secho(" * BigQuery: enabled", fg='green')
        except Exception:
            click.secho(" * BigQuery: disabled", fg='red')

    if config.get_relative_path('pypi_stats').is_file():
        click.secho("\nPyPI download stats present. Typosquatting protection enabled", fg='green')
    else:
        click.secho("\nPyPI download stats not found, run `aura fetch-pypi-stats`. Typosquatting protection disabled", fg='red')


def fetch_pypi_stats(out):
    typos.generate_stats(out)


def generate_typosquatting(out, distance=2, limit=None):
    f = partial(typos.damerau_levenshtein, max_distance=distance)
    pth = config.get_relative_path('pypi_stats')
    for num, (x, y) in enumerate(typos.enumerator(typos.generate_popular(pth), f)):
        out.write(json.dumps({'original': x, 'typosquatting': y}) + '\n')
        if limit and num >= limit:
            break


def generate_r2c_input(out_file):
    inputs = []

    for pkg_name in PypiPackage.list_packages():
        try:
            pkg = PypiPackage.from_pypi(pkg_name)
        except exceptions.NoSuchPackage:
            continue
        targets = []

        input_definition = {
            'metadata': {'package': pkg_name},
            'input_type': 'AuraInput'
        }

        for url in pkg.info['urls']:
            targets.append({
                'url': url['url'],
                'metadata': url
            })


        input_definition['targets'] = json.dumps(targets)
        inputs.append(input_definition)

    out_file.write(json.dumps({
        'name': 'aura',
        'version': '0.0.1',
        'description': 'This is a set of all PyPI packages',
        'inputs': inputs
    }))


    # lm = mirror.LocalMirror()
    # for x in lm.list_packages():
    #     pkg = lm.get_json(x.name)
    #
    #     urls = []
    #     for u in pkg.get('urls', []):
    #         urls.append(u['url'])
    #
    #     if urls:
    #         record = {f'https://pypi.org/project/{x.name}': urls}
    #         out_file.write(json.dumps(record) + '\n')


def r2c_scan(source, out_file, mode='generic'):
    out = {
        'results': [],
        'errors': []
    }

    pkg_metadata = {}

    metadata = {
        'format': 'none'
    }



    if mode == 'pypi':
        logger.info("R2C mode set to PyPI")
        assert len(source) == 1
        location = Path(source[0])

        meta_loc = location / 'metadata.json'
        if meta_loc.is_file():
            with open(location / 'metadata.json', "r") as fd:
                pkg_metadata = json.loads(fd.read())
                metadata.update({
                    'package_type': pkg_metadata.get('packagetype'),
                    'package_name': pkg_metadata.get('name'),
                    'python_version': pkg_metadata.get('python_version')
                })
        source = [os.fspath(x.absolute()) for x in location.iterdir() if x.name != 'metadata.json']
    else:
        logger.info("R2C mode set to generic")

    for src in source:
        logger.info(f"Enumerating {src} with metadata: {metadata}")

        try:
            data = scan_uri(
                src,
                metadata=metadata
            )

            for loc in data:
                for hit in loc['hits']:
                    rhit = {
                        'check_id': hit.pop('type'),
                        'extra': hit
                    }
                    if 'line_no' in hit:
                        rhit['start'] = {'line': hit['line_no']}
                        rhit['path'] = os.path.relpath(hit['location'], source[0])

                    out['results'].append(rhit)

        except Exception as exc:
            out['errors'].append({
                "message": f"An exception occurred: {str(exc)}",
                'data': {"path": str(src)}
            })

    pprint.pprint(out)

    out_file.write(json.dumps(out, default=utils.json_encoder))
