import os
import enum
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Tuple, Any

from click import secho
from git import Repo

from . import utils


DATASET_CDN_URL = "https://cdn.sourcecode.ai/aura/aura_dataset.tgz"


@enum.unique
class UpdateStatus(enum.Enum):
    UP_TO_DATE = 1
    UPDATE_NEEDED = 2
    UNSUPPORTED = 3


def backup_file(file_path):
    if file_path == "-":
        return

    if os.path.exists(file_path):
        secho(f"File '{file_path}' exists, creating backup")
        shutil.copyfile(file_path, f"{file_path}.bak")


def check_git() -> Tuple[UpdateStatus, Any]:  # TODO
    repo = Repo(str(Path(__file__).parent.parent))
    remote = repo.remote()
    remote.update()  # Fetch latest remote refs
    branch = repo.active_branch.name
    commits = tuple(repo.iter_commits("b86df7701e692e559a380cad520f39eaa2711fda..@{u}"))

    if len(commits) == 0:
        return (UpdateStatus.UP_TO_DATE, None)

    print(commits)


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
