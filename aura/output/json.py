import json

from .base import AuraOutput, DiffOutputBase
from ..diff import Diff
from ..exceptions import MinimumScoreNotReached
from ..utils import json_encoder


class JSONOutput(AuraOutput):
    def output(self, hits):
        try:
            filtered = self.filtered(hits)
        except MinimumScoreNotReached:
            return

        score = 0
        tags = set()

        for x in filtered:
            tags |= x.tags
            score += x.score

        data = {
            "detections": [x._asdict() for x in filtered],
            "imported_modules": list(
                {x.extra["name"] for x in hits if x.name == "ModuleImport"}
            ),
            "tags": list(tags),
            "metadata": self.metadata,
            "score": score,
            "name": self.metadata["name"],
        }

        out = json.dumps(data, default=json_encoder)
        if self.metadata.get("output_path") is None:
            print(out)
        else:
            with open(self.metadata["output_path"], "w") as fd:
                fd.write(out)


class JSONDiffOutput(DiffOutputBase):
    def output_diff(self, diffs):
        payload = {
            "diffs": []
        }
        total_sim = 0.0

        for d in diffs:  # type: Diff
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
                "similarity": d.similarity,
                "new_detections": [x._asdict() for x in d.new_detections],
                "removed_detections": [x._asdict() for x in d.removed_detections],
            }
            if d.diff:
                diff["diff"] = d.diff

            total_sim += d.similarity
            payload["diffs"].append(diff)

        payload["total_similarity"] = total_sim / len(diffs)

        print(json.dumps(payload, default=json_encoder))
