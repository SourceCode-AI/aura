from __future__ import annotations

import sys
import os
import json
import time
import inspect
from pathlib import Path
from functools import partial
from typing import Union

import click
from prettyprinter import pprint

from .package_analyzer import Analyzer
from .uri_handlers.base import URIHandler, ScanLocation

from . import __version__ as version
from . import config
from . import exceptions
from . import utils
from . import mirror
from . import plugins
from . import typos
from . import worker_executor
from .package import PypiPackage
from .output.base import AuraOutput


logger = config.get_logger(__name__)

OK = '\u2713'
NOK = '\u2717'


def check_requirement(pkg):
    click.secho("Received payload from package manager, running security audit...")

    handler = URIHandler.from_uri(f"{pkg['path']}")
    try:
        metadata = {
            "uri_input": "pkg_path",
            "source": "package_manager",
            "pm_data": pkg,
            "format": "plain",
            "min_score": 0,
        }

        for location in handler.get_paths():
            # print(f"Enumerating: {location}")
            scan = scan_worker(location, metadata)

            scan.pprint()

        typosquatting = typos.check_name(pkg["name"])
        if typosquatting:
            click.secho(
                "Possible typosquatting detected", fg="red", bold=True, blink=True
            )
            click.secho(
                f"Following {len(typosquatting)} packages with similar names has been found:"
            )
            for x in typosquatting:
                click.echo(f" - '{x}'")

    finally:
        handler.cleanup()
    sys.exit(1)


def scan_worker(item: ScanLocation, metadata: dict) -> list:
    item_metadata = metadata.copy()
    if "path" not in item_metadata:
        item_metadata["path"] = item.location

    if not item.location.exists():
        logger.error(f"Location '{item.location}' does not exists. Skipping")
        return []

    sandbox = Analyzer(location=item.location)

    hits = sandbox.run(strip_path=item.location.parent, metadata=item_metadata)
    return hits


def scan_uri(uri, metadata: Union[list, dict]=None) -> list:
    with utils.enrich_exception(uri, metadata):
        start = time.time()
        handler = None
        metadata = metadata or {}
        output_format = metadata.get("format", "text")
        all_hits = []

        try:
            handler = URIHandler.from_uri(uri)

            if handler is None:
                raise ValueError(f"Could not find a handler for provided URI: '{uri}'")
            elif not handler.exists:
                raise exceptions.InvalidLocation(f"Invalid location provided from URI: '{uri}'")

            metadata.update(
                {"name": uri, "uri_scheme": handler.scheme, "uri_input": handler.metadata}
            )

            for x in handler.get_paths():  # type: ScanLocation
                all_hits.extend(scan_worker(x, metadata))

            if output_format:
                formats = AuraOutput.get_output_formats()
                if output_format not in formats:
                    raise ValueError(f"Unknown output format: '{output_format}'")

                output = formats[output_format](metadata=metadata)
                output.output(hits=all_hits)

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


def scan_mirror(output_dir: Path):
    mirror_pth = mirror.LocalMirror.get_mirror_path()
    click.echo("Collecting package names from a mirror")
    pkgs = list(x.name for x in Path(mirror_pth / "json").iterdir())
    click.echo(f"Collected {len(pkgs)} packages")
    click.echo("Spawning scanning workers")

    with click.progressbar(pkgs) as bar:
        for idx, pkg in enumerate(bar):
            uri = f"mirror://{pkg}"

            out_pth = output_dir / f"{pkg}.scan_results.json"

            metadata = {
                "format": "json",
                "output_path": os.fspath(out_pth),
                "fork": True
            }
            scan_uri(uri=uri, metadata=metadata)
            # executor.apply_async(
            #     func=scan_uri,
            #     kwds={"uri": uri, "metadata": metadata}
            # )


def parse_ast(path: Union[str, Path], stages=None):
    from .analyzers.python.visitor import Visitor

    meta = {"path": path, "source": "cli"}

    v = Visitor.run_stages(metadata=meta, stages=stages)

    tree = json.dumps(v.tree["ast_tree"], default=utils.json_encoder, indent=2)
    print(tree)
    print("\n\n---\n\n")
    pprint(v.tree["ast_tree"], indent=2)


def info():
    """
    Collect and print information about the framework environment and plugins
    """
    click.secho(f"---[ Aura framework version {version} ]---", fg="blue", bold=True)
    analyzers = plugins.load_entrypoint("aura.analyzers")
    if not analyzers["entrypoints"]:
        click.secho("No analyzers available", color="red", blink=True, bold=True)
    else:
        click.echo("Available analyzers:")

    for k, v in analyzers["entrypoints"].items():
        doc = getattr(v, 'analyzer_description', None)
        if not doc:
            doc = inspect.getdoc(v) or "Description N/A"
        click.echo(f" {OK} {k} - {doc}")

    if analyzers["disabled"]:
        click.secho("Disabled analyzers:", color="red", bold=True)
        for (k, v) in analyzers["disabled"]:
            click.echo(f" {NOK} {k.name} - {v}")

    click.secho(f"\nAvailable URI handlers:")
    for k, v in URIHandler.load_handlers().items():
        click.secho(f" {OK} '{k}://'")

    click.echo("\nExternal integrations:")
    tokens = {"librariesio": "Libraries.io API"}
    for k, v in tokens.items():
        t = (config.get_token(k) is not None)
        fg = "green" if t else "red"
        status = "enabled" if t else "Disabled - Token not found"
        click.secho(f" {OK if t else NOK} {v}: {status}", fg=fg)

        try:
            from google.cloud import bigquery

            client = bigquery.Client()
            client.get_service_account_email(retry=0)
            click.secho(f" {OK} BigQuery: enabled", fg="green")
        except Exception:
            click.secho(f" {NOK} BigQuery: disabled", fg="red")

    if config.get_relative_path("pypi_stats").is_file():
        click.secho(
            f"\n {OK} PyPI download stats present. Typosquatting protection enabled",
            fg="green",
        )
    else:
        click.secho(
            f"\n {NOK} PyPI download stats not found, run `aura fetch-pypi-stats`. Typosquatting protection disabled",
            fg="red",
        )


def fetch_pypi_stats(out):
    typos.generate_stats(out)


def generate_typosquatting(out, distance=2, limit=None):
    f = partial(typos.damerau_levenshtein, max_distance=distance)
    pth = config.get_relative_path("pypi_stats")
    for num, (x, y) in enumerate(typos.enumerator(typos.generate_popular(pth), f)):
        out.write(json.dumps({"original": x, "typosquatting": y}) + "\n")
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
            "metadata": {"package": pkg_name},
            "input_type": "AuraInput",
        }

        for url in pkg.info["urls"]:
            targets.append({"url": url["url"], "metadata": url})

        input_definition["targets"] = json.dumps(targets)
        inputs.append(input_definition)

    out_file.write(
        json.dumps(
            {
                "name": "aura",
                "version": "0.0.1",
                "description": "This is a set of all PyPI packages",
                "inputs": inputs,
            }
        )
    )

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


def r2c_scan(source, out_file, mode="generic"):
    out = {"results": [], "errors": []}

    pkg_metadata = {}

    metadata = {"format": "none"}

    if mode == "pypi":
        logger.info("R2C mode set to PyPI")
        assert len(source) == 1
        location = Path(source[0])

        meta_loc = location / "metadata.json"
        if meta_loc.is_file():
            with open(location / "metadata.json", "r") as fd:
                pkg_metadata = json.loads(fd.read())
                metadata.update(
                    {
                        "package_type": pkg_metadata.get("packagetype"),
                        "package_name": pkg_metadata.get("name"),
                        "python_version": pkg_metadata.get("python_version"),
                    }
                )
        source = [
            os.fspath(x.absolute())
            for x in location.iterdir()
            if x.name != "metadata.json"
        ]
    else:
        logger.info("R2C mode set to generic")

    for src in source:
        logger.info(f"Enumerating {src} with metadata: {metadata}")

        try:
            data = scan_uri(src, metadata=metadata)

            for loc in data:
                for hit in loc["hits"]:
                    rhit = {"check_id": hit.pop("type"), "extra": hit}
                    if "line_no" in hit:
                        rhit["start"] = {"line": hit["line_no"]}
                        rhit["path"] = os.path.relpath(hit["location"], source[0])

                    out["results"].append(rhit)

        except Exception as exc:
            exc_tb = sys.exc_info()[-1]

            out["errors"].append(
                {
                    "message": f"[{exc_tb.tb_lineno}] An exception occurred: {str(exc)}",
                    "data": {"path": str(src)},
                }
            )

    pprint(out)
    out_file.write(json.dumps(out, default=utils.json_encoder))
