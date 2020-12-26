from dataclasses import dataclass
from typing import Any

from .base import ScanOutputBase, DiffOutputBase, TyposquattingOutputBase
from ..type_definitions import DiffType, DiffAnalyzerType
from ..json_proxy import dumps


class JSONOutputBase:
    @classmethod
    def protocol(cls) -> str:
        return "json"


@dataclass()
class JSONScanOutput(JSONOutputBase, ScanOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            return

        self._fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    def output(self, hits, scan_metadata: dict):
        score = 0
        tags = set()

        for x in hits:
            tags |= x.tags
            score += x.score

        data = {
            "detections": [x._asdict() for x in hits],
            "imported_modules": list(
                {x.extra["name"] for x in hits if x.name == "ModuleImport"}
            ),
            "tags": list(tags),
            "metadata": scan_metadata,
            "score": score,
            "name": scan_metadata["name"],
        }

        print(dumps(data), file=self._fd)


@dataclass()
class JSONDiffOutput(JSONOutputBase, DiffOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            return

        self._fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    def output_diff(self, diff_analyzer: DiffAnalyzerType):
        payload = {
            "tables": [],
            "diffs": []
        }

        for table in diff_analyzer.tables:
            payload["tables"].append(table.asdict())

        for d in self.filtered(diff_analyzer.diffs):  # type: DiffType
            diff = d.as_dict()
            if not self.patch:
                diff.pop("diff", None)

            payload["diffs"].append(diff)

        print(dumps(payload), file=self._fd)


class JSONTyposquattingOutput(TyposquattingOutputBase):
    @classmethod
    def protocol(cls) -> str:
        return "json"

    def output_typosquatting(self, entries):
        for x in entries:
            data = {
                "original": x["original"],
                "typosquatting": x["typo"],
                "original_score": x["orig_score"].get_score_matrix(),
                "typosquatting_score": x["typo_score"].get_score_matrix(),
            }
            print(dumps(data))
