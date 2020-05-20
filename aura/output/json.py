import json

from .base import AuraOutput
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
            "hits": [x._asdict() for x in filtered],
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

    def output_diff(self, diffs):
        data = []
        # TODO
        raise NotImplementedError("todo")
