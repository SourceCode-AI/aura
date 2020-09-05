import json
import inspect
import shutil
from importlib import resources

import jsonschema

from . import __version__ as version
from .uri_handlers.base import URIHandler
from . import plugins
from . import config


def get_analyzer_description(analyzer) -> str:
    doc = getattr(analyzer, "analyzer_description", None)
    if not doc:
        doc = inspect.getdoc(analyzer) or "Description N/A"
    return doc


def check_pypi_stats() -> dict:
    if config.get_pypi_stats_path():  # Put into try except
        return {
            "enabled": True,
            "description": "PyPI typosquatting protection enabled"
        }
    else:
        return {
            "enabled": False,
            "description": "PyPI download stats not found, typosquatting protection is disabled. Run `aura fetch-pypi-stats` to download"
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


def check_schema() -> dict:
    res = {}
    semantic_schema = json.loads(resources.read_text("aura.data", "semantic_rules_schema.json"))
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
        doc = get_analyzer_description(v)
        info["analyzers"][k] = {
            "enabled": False,
            "description": doc
        }

    for k, v in URIHandler.load_handlers().items():
        info["uri_handlers"][k] = {"enabled": True}

    info["integrations"]["pypi_stats"] = check_pypi_stats()
    info["integrations"]["git"] = check_git()

    return info


if __name__ == "__main__":
    from .output.text import TextInfoOutput
    data = gather_aura_information()
    TextInfoOutput().output_info_data(data)