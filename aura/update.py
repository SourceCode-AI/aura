import os
import shutil
import tarfile
import tempfile
from pathlib import Path

from click import secho

from . import utils


DATASET_CDN_URL = "https://cdn.sourcecode.ai/aura/aura_dataset.tgz"


def backup_file(file_path):
    if file_path == "-":
        return

    if os.path.exists(file_path):
        secho(f"File '{file_path}' exists, creating backup")
        shutil.copyfile(file_path, f"{file_path}.bak")


def update_dataset():
    cwd = Path.cwd()

    secho("Downloading latest aura dataset files")
    with tempfile.NamedTemporaryFile(prefix="aura_dataset_update_", suffix=".tgz", mode="wb") as fd:
        utils.download_file(DATASET_CDN_URL, fd)

        archive = tarfile.open(fd.name, "r:*")

        for f in ("reverse_dependencies.json", "pypi_stats.json"):
            backup_file(cwd/f)
            archive.extract(f, path=cwd)


def update_all():
    update_dataset()
