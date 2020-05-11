# -*- coding: utf-8 -*-

import os
import time


from .base import AnalyzerDeactivated
from .rules import Rule
from ..uri_handlers.base import ScanLocation
from ..utils import Analyzer
from .. import config


rules = None
yara = None

try:
    import yara
except ImportError:
    raise AnalyzerDeactivated(
        "Yara for python is not installed or can't be imported, see docs."
    )

try:
    rules = yara.compile(
        filepath=config.CFG.get("aura", "yara-rules", fallback="rules.yara")
    )
except yara.Error:
    raise AnalyzerDeactivated("Can't compile/find yara rules")


logger = config.get_logger(__name__)


@Analyzer.ID("yara")
def analyze(*, location: ScanLocation):
    """Run Yara rules on all input files recursively"""
    loc = str(location)
    start = time.time()

    for m in rules.match(os.fspath(location.location), timeout=10):
        strings = tuple(set(x[-1] for x in m.strings))
        hit = Rule(
            detection_type = "YaraMatch",
            message = f"Yara match '{m.rule}' signature",
            signature = f"yara#{location}#{m.rule}#{hash(strings)}",
            location = loc,
            extra = {
                "rule": m.rule,
                "strings": strings,
                "meta": m.meta,
            },
            tags = set(m.tags)
        )
        yield hit

    end = time.time() - start
    if end >= 1:
        logger.info(f"Yara scan of {loc} took {end} s")
