import os
import shutil
from pathlib import Path

from click import secho

from . import utils


STATS_CDN_URL = "https://cdn.sourcecode.ai/aura/pypi_stats.json"
REVERSE_CDN_URL = "https://cdn.sourcecode.ai/aura/reverse_dependencies.json"


def backup_file(file_path):
    if file_path == "-":
        return

    if os.path.exists(file_path):
        secho(f"File '{file_path}' exists, creating backup")
        shutil.copyfile(file_path, f"{file_path}.bak")


def update_pypi_stats(outfile=None):
    if outfile is None:
        outfile = Path("pypi_stats.json")

    backup_file(outfile)
    secho("Downloading latest pypi download stats dataset")

    fd = outfile.open("wb")
    utils.download_file(STATS_CDN_URL, fd)


def update_reverse_dependencies(outfile=None):
    if outfile is None:
        outfile = Path("reverse_dependencies.json")

    backup_file(outfile)
    secho("Downloading latest reverse PyPI dependencies dataset")

    fd = outfile.open("wb")
    utils.download_file(REVERSE_CDN_URL, fd)


def update_all():
    update_pypi_stats()
    update_reverse_dependencies()
