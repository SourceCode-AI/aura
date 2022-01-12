import re
from typing import Optional, List, Dict, Union, Iterable

from .base import PostAnalysisHook
from ..uri_handlers.base import ScanLocation


from .detections import Detection
from ..utils import Analyzer


PATH_SPLIT_CHARS = re.compile("[$/]")
AGGREGATION_EXCLUDE_TAGS = {"misc:file_stats"}  # TODO: make this configurable



@Analyzer.ID("file_stats")
def analyze(*, location: ScanLocation):
    """This analyzer collect stats about analyzer files"""
    l : Optional[ScanLocation] = location
    while l:
        if l.metadata.get("source") == "diff":
            return
        l = l.parent

    loc = str(location)  # TODO: refactor this line

    info = {
        "mime": location.metadata["mime"],
        "size": location.size,
    }

    for x in ("tlsh", "md5", "sha1", "sha256", "sha512"):
        if x in location.metadata:
            info[x] = location.metadata[x]

    yield Detection(
        detection_type="FileStats",
        message = "Statistics about files scanned by aura",
        informational=True,
        extra=info,
        location=loc,
        signature=f"file_stats#{loc}",
        tags={"misc:file_stats"}
    )


class DirectoryTreeStats(PostAnalysisHook):
    def __init__(self):
        self.tree: Dict[str, Union[str, dict]] = {"children": {}}

    def post_analysis(self, detections: Iterable[Detection], metadata: dict) -> List[Detection]:
        size = 0
        files = 0

        for d in detections:
            if not d.location:
                continue

            l = self.location_to_tree_item(d.location)

            if d.detection_type == "FileStats":
                l["mime"] = d.extra["mime"]
                l["size"] = d.extra["size"]
                files += 1
                size += l["size"]

            l["tags"] = l.get("tags", set()) | (d.tags - AGGREGATION_EXCLUDE_TAGS)
            l["score"] = l.get("score", 0) + d.score

        for name in tuple(self.tree["children"].keys()):
            self.collapse(name, self.tree)

        metadata["directory_tree_stats"] = self.tree
        metadata["files_processed"] = files
        metadata["data_processed"] = size
        return detections

    def collapse(self, name, parent):
        tree_item = parent["children"][name]

        if len(tree_item["children"]) == 1 and not( tree_item.get("mime") or tree_item.get("score")):
            sub_name, sub_children = tuple(tree_item["children"].items())[0]
            new_name = f"{name}/{sub_name}"
            del parent["children"][name]
            parent["children"][new_name] = sub_children
            return self.collapse(new_name, parent)
        else:
            for sub_name in tuple(tree_item["children"].keys()):
                self.collapse(sub_name, tree_item)

    def location_to_tree_item(self, location: str):
        item = self.tree

        for subpath in self.split_location(location):
            next_item = item["children"].setdefault(subpath, {"children": {}})
            item = next_item

        return item

    def split_location(self, location: str) -> List[str]:
        return PATH_SPLIT_CHARS.split(location)
