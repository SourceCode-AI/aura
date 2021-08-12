from typing import Iterable

from packaging.requirements import Requirement

from .detections import Detection
from .requirements_analyzer import check_outdated
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..exceptions import NoSuchPackage, PluginDisabled


try:
    from tomlkit import parse as parse_toml
except ImportError:
    raise PluginDisabled("`tomlkit` python package is not installed")



@Analyzer.ID("pyproject_toml")
def analyze_pyproject(*, location: ScanLocation) -> Iterable[Detection]:
    if location.location.name == "poetry.lock":
        yield from analyzer_poetry_lock(location=location)
        return

    if location.location.name != "pyproject.toml":
        return

    # pyproject = parse_toml(location.location.read_text())  # TODO


def analyzer_poetry_lock(*, location: ScanLocation):
    lock = parse_toml(location.location.read_text())

    for pkg in lock["package"]:  # type: ignore[union-attr]
        req_specifier = f"{pkg['name']}=={pkg['version']}"

        req = Requirement(req_specifier)
        try:
            yield from check_outdated(req, location)
        except NoSuchPackage:
            pass
