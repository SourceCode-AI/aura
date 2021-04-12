from packaging.version import Version

from .detections import Detection
from .. import package
from ..utils import Analyzer
from ..uri_handlers.base import ScanLocation
from ..exceptions import NoSuchPackage, PluginDisabled
from ..config import get_score_or_default


try:
    from tomlkit import parse as parse_toml
except ImportError:
    raise PluginDisabled("`tomlkit` python package is not installed")



@Analyzer.ID("pyproject_toml")
def analyze_pyproject(*, location: ScanLocation):
    if location.location.name == "poetry.lock":
        yield from analyzer_poetry_lock(location=location)
        return

    if location.location.name != "pyproject.toml":
        return

    pyproject = parse_toml(location.location.read_text())  # TODO


def analyzer_poetry_lock(*, location: ScanLocation):
    lock = parse_toml(location.location.read_text())

    for pkg in lock["package"]:
        pkg_version = Version(pkg["version"])
        pkg_name = str(pkg["name"])

        try:
            pypi = package.PypiPackage.from_cached(pkg_name)
            latest = Version(pypi.get_latest_release())

            if latest > pkg_version:
                yield Detection(
                    detection_type="OutdatedPackage",
                    message=f"Package {pkg_name}=={pkg_version} in poetry.lock is outdated, newest version is {latest}",
                    signature=f"outpdate_pkg#{str(location)}#{pkg_name}#{pkg_version}",
                    score=get_score_or_default("requirement-outdated", 5),
                    location=location.location,
                    extra={
                        "package": pkg_name,
                        "specs": f"=={pkg_version}",
                        "latest": str(latest)
                    },
                    tags={"outdated_package"}
                )
        except NoSuchPackage:
            pass
