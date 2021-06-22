"""
Implementation of the `aura info` command
"""

import inspect
import shutil
from importlib import resources
from typing import Optional

try:
    import jsonschema
except ImportError:
    jsonschema = None

from . import __version__ as version
from .exceptions import MissingFile
from .uri_handlers.base import URIHandler
from . import github
from . import plugins
from . import config
from .json_proxy import loads


def get_analyzer_description(analyzer) -> str:
    doc = getattr(analyzer, "analyzer_description", None)
    if not doc:
        doc = inspect.getdoc(analyzer) or "Description N/A"
    return doc


def check_pypi_stats() -> dict:
    try:
        if config.get_pypi_stats_path():  # Put into try except
            return {
                "enabled": True,
                "description": "PyPI typosquatting protection enabled"
            }
    except MissingFile:
        pass

    return {
        "enabled": False,
        "description": "PyPI download stats not found, typosquatting protection is disabled. Run `aura update` to download"
    }


def check_reverse_dependencies() -> dict:
    try:
        if config.get_reverse_dependencies_path():
            return {
                "enabled": True,
                "description": "Reverse dependencies dataset present. Package scoring feature is fully enabled"
            }
    except MissingFile:
        pass

    return {
        "enabled": False,
        "description": "Reverse dependencies dataset not found, package scoring may be affected. Run `aura update` to download"
    }


def check_git() -> dict:
    git_pth = shutil.which("git")
    if git_pth:
        return {
            "enabled": True,
            "description": "git client is present"
        }
    else:
        return {
            "enabled": False,
            "description": "`git` client is not present, this is required for the `aura diff` functionality"
        }


def check_github_api() -> dict:
    if github.API_TOKEN:
        return {
            "enabled": True,
            "description": "GitHub API token is present, rate limiting is increased"
        }
    else:
        return {
            "enabled": False,
            "description": "Github API token not present, rate limiting is significantly lowered"
        }


def check_schema() -> Optional[dict]:
    """
    Returns None if jsonschema is not installed indicating it's not possible to verify the schema
    """
    if jsonschema is None:
        return None

    res = {}
    semantic_schema = loads(resources.read_text("aura.data", "semantic_rules_schema.json"))
    try:
        jsonschema.validate(config.SEMANTIC_RULES, semantic_schema)
        res["semantic_rules"] = True
    except jsonschema.ValidationError as exc:
        res["semantic_rules"] = exc.args[0]

    return res


def gather_aura_information() -> dict:
    info = {
        "aura_version": version,
        "analyzers": {},
        "integrations": {},
        "uri_handlers": {},
        "schema_validation": check_schema()
    }

    analyzers = plugins.load_entrypoint("aura.analyzers")

    for k, v in analyzers["entrypoints"].items():
        doc = get_analyzer_description(v)
        info["analyzers"][k] = {
            "enabled": True,
            "description": doc
        }

    for k, v in analyzers["disabled"]:
        info["analyzers"][k] = {
            "enabled": False,
            "description": v
        }

    uris = URIHandler.load_handlers(ignore_disabled=False)

    for k, v in uris.pop("disabled", {}).items():
        info["uri_handlers"][k] = {"enabled": False, "description": v}

    for k, v in uris.items():
        info["uri_handlers"][k] = {"enabled": True}

    info["integrations"]["pypi_stats"] = check_pypi_stats()
    info["integrations"]["reverse_dependencies"] = check_reverse_dependencies()
    info["integrations"]["git"] = check_git()
    info["integrations"]["github"] = check_github_api()

    return info


if __name__ == "__main__":
    from .output.text import TextInfoOutput
    data = gather_aura_information()
    TextInfoOutput().output_info_data(data)
