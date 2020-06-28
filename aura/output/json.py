from dataclasses import dataclass
from typing import Any

import rapidjson as json

from .base import ScanOutputBase, DiffOutputBase
from ..diff import Diff
from ..exceptions import MinimumScoreNotReached
from ..utils import json_encoder


@dataclass()
class JSONScanOutput(ScanOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            return

        self._fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    @classmethod
    def is_supported(cls, parsed_uri) -> bool:
        return parsed_uri.scheme == "json"

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

        print(json.dumps(data, default=json_encoder), file=self._fd)


@dataclass()
class JSONDiffOutput(DiffOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            return

        self._fd = open(self.output_location, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    @classmethod
    def is_supported(cls, parsed_uri) -> bool:
        return parsed_uri.scheme == "json"

    def output_diff(self, diff_analyzer):
        payload = {
            "tables": [],
            "diffs": []
        }

        for table in diff_analyzer.tables:
            payload["tables"].append(table.asdict())

        for d in self.filtered(diff_analyzer.diffs):  # type: Diff
            diff = {
                "operation": d.operation,
                "a_ref": d.a_ref,
                "b_ref": d.b_ref,
                "a_size": d.a_size,
                "b_size": d.b_size,
                "a_mime": d.a_mime,
                "b_mime": d.b_mime,
                "a_md5": d.a_md5,
                "b_md5": d.b_md5,
                "similarity": d.similarity
            }

            if d.new_detections:
                diff["new_detections"] = [x._asdict() for x in d.new_detections]

            if d.removed_detections:
                diff["removed_detections"] = [x._asdict() for x in d.removed_detections]

            if d.diff and self.patch:
                diff["diff"] = d.diff

            payload["diffs"].append(diff)

        print(json.dumps(payload, default=json_encoder), file=self._fd)
