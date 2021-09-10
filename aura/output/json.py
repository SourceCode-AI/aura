from dataclasses import dataclass

from .base import ScanOutputBase, DiffOutputBase, TyposquattingOutputBase
from .. import __version__
from ..type_definitions import DiffType, DiffAnalyzerType
from ..json_proxy import dumps


class JSONOutputBase:
    @classmethod
    def protocol(cls) -> str:
        return "json"


@dataclass()
class JSONScanOutput(JSONOutputBase, ScanOutputBase):
    def __enter__(self):
        if self.output_location == "-":
            return

        self.out_fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.out_fd:
            self.out_fd.close()

    def output(self, hits, scan_metadata: dict, fd=None):
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
            "version": __version__
        }

        fd = fd or self.out_fd
        print(dumps(data), file=fd)


@dataclass()
class JSONDiffOutput(JSONOutputBase, DiffOutputBase):
    def __enter__(self):
        if self.output_location == "-":
            return

        self.out_fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.out_fd:
            self.out_fd.close()

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

        print(dumps(payload), file=self.out_fd)


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
