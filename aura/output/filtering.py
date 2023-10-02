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

        compiled_include, compiled_exclude = compile_filter_tags(self.tag_filters)

        for detection in sorted(detections):
            # Normalize tags
            tags = [tag.lower().replace("-", "_") for tag in detection.tags]

            # if verbosity is below 2, informational results are filtered
            # norm is that informational results should have a score of 0
            if self.verbosity < 2 and detection.informational and detection.score == 0:
                continue
            elif compiled_exclude and not all(tag_filter(tags) for tag_filter in compiled_exclude):
                continue
            elif compiled_include and not any(tag_filter(tags) for tag_filter in compiled_include):
                continue
            elif (
                self.verbosity < 3 and detection.name == "ASTParseError" and detection._metadata.get("source") == "blob"
            ):
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
    include_tags = []
    exclude_tags = []

    def include(tag):
        def wrapper(x):
            if tag[-1] == "*":
                return any(y.startswith(tag[:-1]) for y in x)
            else:
                return tag in x

        return wrapper

    def exclude(tag):
        def wrapper(x):
            if tag[-1] == "*":
                return not any(y.startswith(tag[:-1]) for y in x)
            else:
                return tag not in x

        return wrapper

    for t in tags:
        # normalize tags to lowercase with `-` replaced to `_`
        t = t.strip().lower().replace("-", "_")

        if not t:
            continue

        if t.startswith("!"):  # It a tag is prefixed with `!` then it means to exclude findings with such tag
            exclude_tags.append(exclude(t[1:]))
        else:
            include_tags.append(include(t))

    return include_tags, exclude_tags
