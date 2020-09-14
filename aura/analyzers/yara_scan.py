# -*- coding: utf-8 -*-

import os
import time

from .detections import Detection
from ..uri_handlers.base import ScanLocation
from ..utils import Analyzer
from ..exceptions import PluginDisabled
from .. import config


try:
    import yara
except ImportError:
    raise PluginDisabled(
        "Yara for python is not installed or can't be imported, see docs."
    )

try:
    rules_pth = config.CFG["aura"].get("yara-rules", "aura.data.rules.yara")
    rules = yara.compile(source=config.get_file_content(rules_pth, config.CFG_PATH))
except yara.Error as exc:
    raise PluginDisabled("Can't compile/find yara rules")


logger = config.get_logger(__name__)


@Analyzer.ID("yara")
def analyze(*, location: ScanLocation):
    """Run Yara rules on all input files recursively"""
    start = time.time()

    try:
        for m in rules.match(os.fspath(location.location), timeout=10):
            strings = tuple(set(x[-1] for x in m.strings))
            score_each = m.meta.get("score_each", False)
            rule_score = m.meta.get("score", 0)
            if score_each:
                total_score = len(strings)*rule_score
            else:
                total_score = rule_score

            yield Detection(
                detection_type = "YaraMatch",
                message = f"Yara match '{m.rule}' signature",
                signature = f"yara#{str(location)}#{m.rule}#{hash(strings)}",
                location = location.location,
                score = total_score,
                extra = {
                    "rule": m.rule,
                    "strings": strings,
                    "meta": m.meta,
                },
                tags = set(m.tags)
            )
    except yara.Error as exc:
        yield Detection(
            detection_type="YaraError",
            message=exc.args[0],
            signature=f"yara_error#{str(location)}",
            location=location.location,
            tags = {"yara_error"}
        )

    end = time.time() - start
    if end >= 1:
        logger.info(f"Yara scan of {str(location)} took {end} s")
