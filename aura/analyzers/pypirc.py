import configparser

from .. import config
from .detections import Detection
from ..uri_handlers.base import ScanLocation
from ..utils import Analyzer, fast_checksum
from ..type_definitions import AnalyzerReturnType


@Analyzer.ID("pypirc")
def analyze(*, location: ScanLocation) -> AnalyzerReturnType:
    """
    Scans for exposure of credentials inside the `.pypirc` file
    """
    if location.location.name != ".pypirc":
        return
    try:
        pypirc = configparser.ConfigParser()
        pypirc.read(str(location.location))
    except configparser.ParsingError:
        # TODO: generate a detection
        return

    # Filter on these values, some pregenerated configurations use them and we don't want to generate false positives on these
    user_blacklist = config.CFG.get("pypirc", {}).get("username_blacklist", [])
    pwd_blacklist = config.CFG.get("pypirc", {}).get("password_blacklist", [])

    for section_name in pypirc.sections():
        section = pypirc[section_name]

        if "username" in section and "password" in section:
            username = section.get("username")
            password = section.get("password")

            if username in user_blacklist or password in pwd_blacklist:
                continue
            elif not (password and username):  # Filter blank values
                continue

            sig = fast_checksum(f"{section_name}#{username}#{password}")

            yield Detection(
                detection_type="LeakingPyPIrc",
                message = "Leaking credentials in the `.pypirc` file",
                signature = f"pypirc#{sig}",
                location = location.location,
                score = 100,  # TODO: make the score configurable
                extra = {
                    "section": section_name,
                    "username": username,
                    "password": password
                },
                tags = {"sensitive_file", "secrets_leak", "pypirc"}
            )

