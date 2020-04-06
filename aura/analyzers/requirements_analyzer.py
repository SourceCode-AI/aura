import os
import re
from dataclasses import dataclass
from pathlib import Path

import requirements

from .rules import Rule
from ..utils import Analyzer
from .. import package


FILENAME = re.compile(r"^.*requirements.*\.txt$")


@dataclass
class OutdatedRequirement(Rule):
    __hash__ = Rule.__hash__


@dataclass
class UnpinnedRequirement(Rule):
    __hash__ = Rule.__hash__


@Analyzer.ID("requirements_file_analyzer")
def analyze_requirements_file(pth: Path, **kwargs):
    """
    Analyzer the requirements.txt file and lookup for outdated packages
    """
    if not FILENAME.match(os.fspath(pth)):
        return

    with pth.open("r") as fd:
        for req in requirements.parse(fd):
            if not req.specs:
                hit = UnpinnedRequirement(
                    message = f"Package {req.name} is unpinned",
                    signature = f"req_unpinned#{os.fspath(pth)}#{req.name}",
                    score = 10,
                    extra = {
                        "package": req.name
                    },
                    tags = {"unpinned_requirement"}
               )
                yield hit
                continue

            pypi = package.PypiPackage.from_pypi(req.name)
            latest = pypi.get_latest_release()
            for comparator, spec in req.specs:
                if not package.CONSTRAINS[comparator](latest, spec):
                    hit = OutdatedRequirement(
                        message = f"Package {req.name}{req.specs} is outdated, newest version is {latest}",
                        signature = f"req_outdated#{os.fspath(pth)}#{req.name}#{req.specs}#{latest}",
                        score = 5,
                        extra = {
                            "package": req.name,
                            "spec": list(req.specs),
                            "latest": latest
                        },
                        tags = {"outdated_requirement"}
                    )
                    yield hit
                    break
