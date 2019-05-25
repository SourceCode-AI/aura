#-*- coding: utf-8 -*-

import os
import time
from dataclasses import dataclass, field
from pathlib import Path


from .base import AnalyzerDeactivated
from .rules import Rule
from ..utils import Analyzer
from .. import config

rules = None
yara = None

try:
    import yara
except ImportError:
    raise AnalyzerDeactivated("Yara for python is not installed or can't be imported, see docs.")

try:
    rules = yara.compile(filepath=config.CFG.get('aura', 'yara-rules', fallback='rules.yara'))
except yara.Error:
    raise AnalyzerDeactivated("Can't compile/find yara rules")



logger = config.get_logger(__name__)


@dataclass
class YaraMatch(Rule):
    rule: str = ''
    strings: tuple = ()
    meta: dict = field(default_factory=dict)

    def _asdict(self):
        d = {
            'rule': self.rule,
            'strings': self.strings
        }

        if self.meta:
            d['metadata'] = self.meta

        d.update(Rule._asdict(self))
        return d

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((
                self.rule,
                self.strings
            ))

        return self._hash


@Analyzer.ID('yara')
@Analyzer.description("Run Yara rules on all input files recursively")
def analyze(pth: Path, **kwargs):
    pth = os.fspath(pth)
    start = time.time()

    for m in rules.match(pth, timeout=10):
        strings = set(x[-1] for x in m.strings)
        hit = YaraMatch(
            rule = m.rule,
            strings = tuple(strings),
            meta = m.meta,
            tags = set(m.tags)
        )
        yield hit

    end = time.time() - start
    if end >= 1:
        logger.info(f"Yara scan of {pth} took {end} s")
