# coding=utf-8
import os
import sys
import typing
import time
import resource
import logging
import warnings
import configparser
import concurrent.futures
from pathlib import Path
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from typing import Optional

import tqdm
import pkg_resources
import jsonschema
from ruamel.yaml import YAML


try:
    import simplejson as json
except ImportError:
    import json


CFG = configparser.ConfigParser(default_section="default", allow_no_value=True)
CFG_PATH = None
SEMANTIC_RULES: Optional[dict] = None
LOG_FMT = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
LOG_ERR = None
# This is used to trigger breakpoint during AST traversing of specific lines
DEBUG_LINES = set()
DEFAULT_AST_STAGES = ("convert", "rewrite", "ast_pattern_matching", "taint_analysis", "readonly")
AST_PATTERNS_CACHE = None


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


# Helper for loading API tokens for external integrations
def get_token(name: str) -> str:
    value = CFG.get("api_tokens", name, fallback=None)
    # If the token is not specified in the config, fall back to the env variable
    if value is None:
        value = os.environ.get(f"AURA_{name.upper()}_TOKEN", None)

    return value


def get_relative_path(name: str) -> Path:
    """
    Fetch a path to the file based on configuration and relative path of Aura
    """
    if os.path.isabs(name):
        return Path(name)

    pth = CFG.get("aura", name)
    return Path(CFG_PATH).parent.joinpath(pth)


def get_logger(name: str) -> logging.Logger:
    _log = logging.getLogger(name)
    if LOG_ERR is not None:
        _log.addHandler(LOG_ERR)
    return _log


def get_settings(pth: str, fallback=None) -> Optional[str]:
    data = CFG

    for part in pth.split("."):
        if part in data:
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
    return int(CFG.get("score", score_type, fallback=fallback))


def find_configuration() -> Path:
    pth = Path(os.environ.get("AURA_CFG", "config.ini"))
    if pth.is_absolute():
        return pth

    cwd = Path.cwd()
    while cwd not in (cwd.root, cwd.drive):
        if (cwd / pth).exists():
            return cwd/pth
        else:
            cwd = cwd.parent

    return pth


def load_config():
    global SEMANTIC_RULES, CFG, CFG_PATH
    pth = find_configuration()
    if pth.is_dir():
        pth /= "config.ini"

    if not pth.is_file():
        logger.fatal(f"Invalid configuration path: {pth}")
        sys.exit(1)

    logger.debug(f"Aura configuration located at {pth}")

    CFG_PATH = os.fspath(pth)
    CFG.read(pth)

    semantic_sig_pth = (
        pth.parent / CFG.get("aura", "semantic-rules", fallback="signatures.yaml")
    ).absolute()

    if not semantic_sig_pth.is_file():
        logger.fatal(f"Invalid path to the signatures file: {semantic_sig_pth}")
        sys.exit(1)

    # this environment variable is needed by python AST parser to pick up location of signatures
    if not os.environ.get("AURA_SIGNATURES"):
        os.putenv("AURA_SIGNATURES", os.fspath(semantic_sig_pth))

    yaml = YAML(typ="safe")
    SEMANTIC_RULES = yaml.load(semantic_sig_pth.read_text())

    with (Path(__file__).parent / "config_schema.json").open("r") as fd:
        schema = json.loads(fd.read())
        # FIXME: jsonschema.validate(instance=SEMANTIC_RULES, schema=schema)

    if "AURA_LOG_LEVEL" in os.environ:
        log_level = logging.getLevelName(os.getenv("AURA_LOG_LEVEL").upper())
    else:
        log_level = logging.getLevelName(
            CFG.get("aura", "log-level", fallback="warning").upper()
        )

    configure_logger(log_level)

    if not sys.warnoptions:
        w_filter = CFG.get("aura", "warnings", fallback="default")
        warnings.simplefilter(w_filter)
        os.environ["PYTHONWARNINGS"] = w_filter

    if CFG["aura"].get("rlimit-memory"):
        rss = int(CFG["aura"]["rlimit-memory"])
        resource.setrlimit(resource.RLIMIT_RSS, (rss, rss))

    if CFG["aura"].get("rlimit-fsize"):
        fsize = int(CFG["aura"]["rlimit-fsize"])
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

    if "AURA_RECURSION_LIMIT" in os.environ:
        sys.setrecursionlimit(int(os.environ["AURA_RECURSION_LIMIT"]))
    elif CFG["aura"].get("python-recursion-limit"):
        rec_limit = int(CFG["aura"]["python-recursion-limit"])
        sys.setrecursionlimit(rec_limit)


def get_maximum_archive_size() ->typing.Optional[int] :
    """
    Get settings for a maximum archive file size that can be extracted
    If the limit is not specified, fallback to the rlimit-fsize (if configured)

    :return: File int size in bytes for configured limit; otherwise None
    """
    size = CFG["aura"].get("max-archive-size", fallback=None)
    if size:
        return int(size)
    size = CFG["aura"].get("rlimit-fsize", fallback=None)
    if size:
        return int(size)


def get_default_tag_filters() -> typing.List[str]:
    if "tags" not in CFG:
        return []

    return list(CFG["tags"].keys())


def get_installed_stages() -> typing.Generator[str,None,None]:
    for x in pkg_resources.iter_entry_points("aura.ast_visitors"):
        yield x.name


def get_ast_stages() -> typing.Tuple[str,...]:
    cfg_value = CFG["aura"].get("ast-stages", fallback=None)
    if cfg_value is None:
        return DEFAULT_AST_STAGES

    stages = []
    for x in cfg_value.split():
        if not x:
            continue
        stages.append(x)

    return tuple(stages)


def get_ast_patterns():
    global AST_PATTERNS_CACHE
    from .pattern_matching import ASTPattern

    if AST_PATTERNS_CACHE is None:
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor() as e:
            AST_PATTERNS_CACHE = tuple(e.map(ASTPattern, SEMANTIC_RULES.get("patterns", [])))
        elapsed = round(time.monotonic() - start, 5)
        logger.debug(f"AST Pattern compilation took {elapsed}s")
    return AST_PATTERNS_CACHE

load_config()
