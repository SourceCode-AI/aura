from dataclasses import dataclass, field
from typing import Iterable, List, Callable

from ..exceptions import MinimumScoreNotReached


@dataclass()
class FilterConfiguration:
    min_score: int = 0
    tag_filters: list = field(default_factory=list)  # TODO: compile tags
    verbosity: int = 1

    def filter_detections(self, detections) -> list:
        processed = []
        total_score: int = 0

        compiled_tags = compile_filter_tags(self.tag_filters)

        for detection in sorted(detections):
            # Normalize tags
            tags = [tag.lower().replace("-", "_") for tag in detection.tags]

            # if verbosity is below 2, informational results are filtered
            # norm is that informational results should have a score of 0
            if self.verbosity < 2 and detection.informational and detection.score == 0:
                continue
            elif not all(tag_filter(tags) for tag_filter in compiled_tags):
                continue
            elif self.verbosity < 3 and detection.name == "ASTParseError" and detection._metadata.get("source") == "blob":
                continue
            else:
                total_score += detection.score
                processed.append(detection)

        if self.min_score and self.min_score > total_score:
            raise MinimumScoreNotReached(f"Score of {total_score} did not meet the minimum {self.min_score}")

        return processed


def compile_filter_tags(tags: Iterable[str]) -> List[Callable[[Iterable[str]], bool]]:
    """
    compile input filter tags into an easy to use list of lambda's so the output hits can be filtered using map
    """
    compiled = []

    for t in tags:
        # normalize tags to lowercase with `-` replaced to `_`
        t = t.strip().lower().replace('-', '_')

        if not t:
            continue

        if t.startswith("!"):  # It a tag is prefixed with `!` then it means to exclude findings with such tag
            compiled.append(lambda x: t[1:] not in x)
        else:
            compiled.append(lambda x: t in x)

    return compiled
