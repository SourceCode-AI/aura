import os
import shutil

from click import secho, File

from . import config
from . import utils


STATS_CDN_URL = "https://cdn.sourcecode.ai/datasets/typosquatting/pypi_stats.json"


def backup_file(file_path):
    if file_path == "-":
        return

    if os.path.exists(file_path):
        secho(f"File '{file_path}' exists, creating backup")
        shutil.copyfile(file_path, f"{file_path}.bak")


def update_pypi_stats(outfile=None):
    if outfile is None:
        outfile = config.get_pypi_stats_path()

    backup_file(outfile)
    secho("Downloading latest pypi download stats dataset")

    fd = outfile.open("wb")
    utils.download_file(STATS_CDN_URL, fd)


def update_all():
    update_pypi_stats()
