import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Generator

import requirements
from pkg_resources import RequirementParseError

from .rules import Rule
from ..utils import Analyzer
from ..config import get_score_or_default
from .. import package


FILENAME = re.compile(r"^.*requirements.*\.txt$")
URL = re.compile("^(https?|ftp)://.*$", flags=re.I)


@dataclass
class OutdatedRequirement(Rule):
    __hash__ = Rule.__hash__


@dataclass
class UnpinnedRequirement(Rule):
    __hash__ = Rule.__hash__


@dataclass
class InvalidRequirement(Rule):
    __hash__ = Rule.__hash__


def check_unpinned(requirement, path) -> Optional[UnpinnedRequirement]:
    if not requirement.specs:
        hit = UnpinnedRequirement(
            message=f"Package {requirement.name} is unpinned",
            signature=f"req_unpinned#{path}#{requirement.name}",
            score=get_score_or_default("requirement-unpinned", 10),
            extra={
                "package": requirement.name
            },
            tags={"unpinned_requirement"}
        )
        return hit


def check_outdated(requirement, path) -> Optional[OutdatedRequirement]:
    pypi = package.PypiPackage.from_pypi(requirement.name)
    latest = pypi.get_latest_release()
    for comparator, spec in requirement.specs:
        if not package.CONSTRAINS[comparator](latest, spec):
            hit = OutdatedRequirement(
                message=f"Package {requirement.name}{requirement.specs} is outdated, newest version is {latest}",
                signature=f"req_outdated#{path}#{requirement.name}#{requirement.specs}#{latest}",
                score=get_score_or_default("requirement-outdated", 5),
                extra={
                    "package": requirement.name,
                    "spec": list(requirement.specs),
                    "latest": latest
                },
                tags={"outdated_requirement"}
            )
            return hit


@Analyzer.ID("requirements_file_analyzer")
def analyze_requirements_file(pth: Path, metadata: dict, **kwargs) -> Generator[Rule, None, None]:
    """
    Analyzer the requirements.txt file and lookup for outdated packages
    """
    if not FILENAME.match(os.fspath(pth)):
        return

    norm_pth = os.fspath(metadata.get("normalized_path") or pth)

    with pth.open("r") as fd:
        for idx, req_line in enumerate(fd):
            req_line = req_line.strip()

            if URL.match(req_line):
                yield InvalidRequirement(
                    message = f"Can't process requirement with a remote URL",
                    signature = f"req_invalid#{norm_pth}/{idx}",
                    extra = {
                        "reason": "remote_url",
                        "line": req_line,
                        "line_no": idx
                    },
                    score = get_score_or_default("requirement-remote-url", 20),
                    tags = {"invalid_requirement", "remote_url"}
                )
                continue

            try:
                for req in requirements.parse(req_line):
                    hit = check_unpinned(req, norm_pth)
                    if hit:
                        yield hit
                        continue

                    hit = check_outdated(req, norm_pth)
                    if hit:
                        yield hit
                        continue
            except (RequirementParseError, ValueError) as exc:
                yield InvalidRequirement(
                    message = f"Could not parse the requirement for analysis",
                    signature = f"req_invalid#{norm_pth}/{idx}",
                    extra = {
                        "reason": "cant_parse",
                        "line": req_line.strip(),
                        "line_no": idx,
                        "exc_message": exc.args[0]
                    },
                    score = get_score_or_default("requirement-invalid", 0),
                    tags = {"invalid_requirement", "cant_parse"}
                )
