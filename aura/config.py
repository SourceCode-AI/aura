# coding=utf-8
import os
import sys
import typing
import resource
import logging
import warnings
from importlib import resources
from pathlib import Path
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from typing import Optional, Generator, Any, Union

import tqdm
import pkg_resources
import ruamel.yaml
from ruamel.yaml import composer
try:
    import rapidjson as json
except ImportError:
    import json  # type: ignore[no-redef]

from .exceptions import InvalidConfiguration, MissingFile


CFG : dict
CFG_PATH: Path
SEMANTIC_RULES : dict
LOG_FMT = logging.Formatter("%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s")
LOG_ERR = None
# This is used to trigger breakpoint during AST traversing of specific lines
DEBUG_LINES = set()
DEFAULT_AST_STAGES = ("convert", "rewrite", "ast_pattern_matching", "taint_analysis", "readonly")
PROGRESSBAR_DISABLED: bool = ("AURA_NO_PROGRESS" in os.environ)

DEFAULT_CFG_PATH = "aura.data.aura_config.yaml"
DEFAULT_SIGNATURE_PATH = "aura.data.signatures.yaml"


if "AURA_DEBUG_LINES" in os.environ:
    DEBUG_LINES = set(int(x.strip()) for x in os.environ["AURA_DEBUG_LINES"].split(","))


# Check if the log file can be created otherwise it will crash here
if os.access("aura_errors.log", os.W_OK):
    LOG_ERR = RotatingFileHandler("aura_errors.log", maxBytes=1024 ** 2, backupCount=5)
    LOG_ERR.setLevel(logging.ERROR)


logger = logging.getLogger("aura")


if os.environ.get("AURA_DEBUG_LEAKS"):
    import gc

    gc.set_debug(gc.DEBUG_LEAK)


class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.tqdm.write(msg, file=sys.stderr)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


def configure_logger(level):
    logging.captureWarnings(capture=True)
    logger.setLevel(level)
    log_stream = TqdmLoggingHandler(level=level)
    log_stream.setFormatter(LOG_FMT)
    logger.addHandler(log_stream)
    if LOG_ERR is not None:
        logger.addHandler(LOG_ERR)


def compose_document(self: ruamel.yaml.composer.Composer):
    """
    patch for yaml loader to preserve anchors in multi documents
    See https://stackoverflow.com/questions/40701983/is-it-possible-to-have-aliases-in-a-multi-document-yaml-stream-that-span-all-doc
    """
    self.get_event()
    node = self.compose_node(None, None)
    self.get_event()
    return node


# Monkey patch the YAML composer
ruamel.yaml.composer.Composer.compose_document = compose_document


# Helper for loading API tokens for external integrations
def get_token(name: str) -> str:  # TODO: add tests
    value = CFG.get("api_tokens", {}).get(name)
    # If the token is not specified in the config, fall back to the env variable
    if value is None:
        value = os.environ.get(f"AURA_{name.upper()}_TOKEN", None)

    return value


def get_logger(name: str) -> logging.Logger:
    _log = logging.getLogger(name)
    if LOG_ERR is not None:
        _log.addHandler(LOG_ERR)
    return _log


def get_settings(pth: str, fallback=None) -> Any:
    data = CFG

    for part in pth.split("."):
        if type(data) == dict and part in data:
            data = data[part]
        else:
            return fallback

    return data


@lru_cache()
def get_score_or_default(score_type: str, fallback: int) -> int:
    """
    Retrieve score as defined in the config or fallback to the default provided value
    The scoring values are cached using lru_cache to avoid unnecessary lookups

    :param score_type: name of the scoring parameter as defined in the [score] aura config section
    :param fallback: fallback default value
    :return: Score integer
    """
    return CFG["score"].get(score_type, fallback)


def find_configuration() -> Path:  # TODO: add tests
    pth = Path(os.environ.get("AURA_CFG", "aura_config.yaml"))
    if pth.is_absolute():
        return pth

    cwd = Path.cwd()
    root = (cwd.root, cwd.drive, "/")
    while str(cwd) not in root:
        if (cwd / pth).exists():
            return cwd/pth
        else:
            cwd = cwd.parent

    return Path(DEFAULT_CFG_PATH)


def get_file_location(
        location: str,
        base_path: Optional[Union[str, Path]]=None,
        exc: bool=True
) -> str:
    """
    Lookup a location of a file

    :param location: relative or absolute file location or a filename
    :param base_path: base path used for resolving relative paths or filenames
    :param exc: Flag, raise an exception if the file could not be found/does not exists
    :return: resolved path to the given file location
    """
    if location.startswith("aura.data."):  # Load file as a resource from aura package
        return location

    if os.path.exists(location):
        return location

    if base_path is not None:
        pth = Path(base_path) / location
        if pth.is_file():
            return str(pth)
    else:
        pth = Path(location)

    if exc:
        raise MissingFile(
            f"Can't find configuration file `{location}` using base path `{base_path}`",
            file_location=location, base_path=str(base_path)
        )
    else:
        return str(pth)


def get_file_content(location: str, base_path: Optional[str]=None) -> str:
    pth = get_file_location(location, base_path)

    if pth.startswith("aura.data."):  # Load file as a resource from aura package
        filename = pth[len("aura.data."):]
        return resources.read_text("aura.data", filename)

    else:
        with open(location, "r") as fd:
            return fd.read()


def parse_config(pth, default_pth) -> dict:
    logger.debug(f"Aura configuration located at {pth}")

    content = get_file_content(pth)
    if content.startswith("---"):
        default_cfg = get_file_content(default_pth)
        content = default_cfg + "\n" + content
        docs = list(ruamel.yaml.safe_load_all(content))
        return docs[-1]
    else:
        return ruamel.yaml.safe_load(content)


def load_config():
    global SEMANTIC_RULES, CFG, CFG_PATH

    CFG_PATH = str(find_configuration())
    CFG = parse_config(CFG_PATH, DEFAULT_CFG_PATH)

    if "AURA_SIGNATURES" in os.environ:
        semantic_sig_pth = os.environ["AURA_SIGNATURES"]
    else:
        semantic_sig_pth = CFG["aura"]["semantic-rules"]

    SEMANTIC_RULES = parse_config(semantic_sig_pth, DEFAULT_SIGNATURE_PATH)

    if "AURA_LOG_LEVEL" in os.environ:
        log_level = logging.getLevelName(os.getenv("AURA_LOG_LEVEL").upper())
    else:
        log_level = logging.getLevelName(
            CFG["aura"].get("log-level", "warning").upper()
        )

    configure_logger(log_level)

    if not sys.warnoptions:
        w_filter = CFG["aura"].get("warnings", "default")
        warnings.simplefilter(w_filter)
        os.environ["PYTHONWARNINGS"] = w_filter

    try:
        if rss:=CFG["aura"].get("rlimit-memory"):
            if rss > resource.RLIMIT_RSS:
                logger.warning(f"Configured RSS rlimit ({rss}) is greater than the maximum allowed RSS: {resource.RLIMIT_RSS}")
            else:
                resource.setrlimit(resource.RLIMIT_RSS, (rss, rss))
    except ValueError as exc:
        logger.warning(f"Can't set configured RSS limit: `{exc.args[0]}`")

    try:
        if fsize:=CFG["aura"].get("rlimit-fsize"):
            if fsize > resource.RLIMIT_FSIZE:
                logger.warning(f"Configured FSIZE rlimit ({fsize}) is greater than the maximum allowed FSIZE: {resource.RLIMIT_FSIZE}")
            else:
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    except ValueError as exc:
        logger.warning(f"Can't set configured fsize limit: `{exc.args[0]}`")

    rec_limit = os.environ.get("AURA_RECURSION_LIMIT") or CFG["aura"].get("python-recursion-limit")

    if rec_limit:
        sys.setrecursionlimit(int(rec_limit))


def get_pypi_stats_path(exc=True) -> Path:
    pth = os.environ.get("AURA_PYPI_STATS", None) or CFG["aura"]["pypi_stats"]
    return Path(get_file_location(pth, CFG_PATH, exc=exc))


def get_reverse_dependencies_path(exc=True) -> Path:
    pth = os.environ.get("AURA_REVERSE_DEPENDENCIES", None) or CFG["aura"]["reverse_dependencies"]  # type: ignore[index]
    return Path(get_file_location(pth, CFG_PATH, exc=exc))


def iter_pypi_stats() -> Generator[dict, None, None]:
    pth = get_pypi_stats_path()
    with pth.open() as fd:
        for line in fd:
            yield json.loads(line)


def get_cache_mode() -> str:
    fallback = CFG.get("cache", {}).get("mode", "auto")  # type: ignore[union-attr]
    return os.environ.get("AURA_CACHE_MODE", fallback)


def get_maximum_archive_size() ->typing.Optional[int] :
    """
    Get settings for a maximum archive file size that can be extracted
    If the limit is not specified, fallback to the rlimit-fsize (if configured)

    :return: File int size in bytes for configured limit; otherwise None
    """
    size = CFG["aura"].get("max-archive-size") or CFG["aura"].get("rlimit-fsize")
    return size


def get_default_tag_filters() -> typing.List[str]:
    return CFG.get("tags", [])


def get_installed_stages() -> typing.Generator[str,None,None]:
    for x in pkg_resources.iter_entry_points("aura.ast_visitors"):
        yield x.name


def get_ast_stages() -> typing.Tuple[str,...]:
    cfg_value = CFG["aura"].get("ast-stages") or DEFAULT_AST_STAGES
    return [x for x in cfg_value if x]


def can_fork() -> bool:
    if "AURA_NO_FORK" in os.environ:
        return False

    # FIXME: rename the `async` config to `fork`
    fork = CFG["aura"].get("async", True)
    return fork


CFG_PATH = find_configuration()
load_config()
