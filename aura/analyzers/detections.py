from __future__ import annotations

from typing  import List, Union, Set, Optional, Dict, cast
from pathlib import Path
from dataclasses import dataclass, field
from functools import total_ordering

from .. import config
from ..utils import normalize_path
from .python.nodes import NodeType, ASTNode


@dataclass
@total_ordering
class Detection:
    """
    Base for analyzers to produce detections from audit scans that are reported back to the Aura framework
    Subclass this to have different hits on semantic level

    :param message: Detection message, intended to be displayed to a user
    :type message: str
    :param signature: Used by default for hashing/deduplication of various detections. At minimum, it is highly recommended to include at least a detection name and a normalized path to the scanned file. In case of AST based detections, line number is also recommended as it is possible that the source code can contain multiple detections of the same anomaly that are on different lines and should be reported separately.
    :type signature: str

    :param score: A score associated with this detection that is then used to compute the overall score of the input scanned by Aura.
    :type score: int, optional
    :param node: A reference to the AST node object. It is recommended to set this attribute for AST based detections as the framework will automatically fill some of the emtadata for the output such as line number or the actual content of the line.
    :type node: ASTNode, optional
    :param extra: A schema less dictionary. Use this to report back any data fields when exporting the scan data into various formats such as JSON
    :type extra: dict, optional
    :param tags: A set of strings that acts as tags for this detection. Used for filtering the outputs and tagging whole files via detections.
    :type tags: Set[str], optional
    :param detection_type: An identifier of the detection type. Used for filtering out the different detections. If not provided, class name is used.
    :type detection_type: str, optional
    """

    signature: str
    message: str
    score: int = 0  # Score that affects security audit
    line_no: Optional[int] = None  # Set to None to hide it from output
    line: Union[
        str, None
    ] = None  # Set to None or empty string to hide it from output
    # If the rule is tied to the AST tree detections, then set the node pointer appropriately
    # Set to None to hide or for rules that are not tied to the AST tree
    detection_type: Optional[str] = None
    node: Optional[NodeType] = None
    tags: Set[str] = field(default_factory=set)
    extra: dict = field(default_factory=dict)
    informational: bool = False
    location: Optional[Path, str] = None
    scan_location = None
    _metadata: Optional[dict] = None

    def __post_init__(self):
        self._hash = None
        self._diff_hash = None
        self._severity = None

        if isinstance(self.node, ASTNode) and self.line_no is None:
            self.line_no = self.node.line_no

    def _asdict(self) -> Dict:
        """
        Exporting mechanism for JSON output/machine processing
        Define fields to be exported here, subclass need to fetch the fields from their parent in this method
        Output dict must contain only elements that are JSON serializable

        :return: Serialized data for the detection
        :rtype: dict
        """
        data = {
            "score": self.score,
            "type": self.name,
            "slug": self.slug,
            "severity": get_severity(self)
        }

        if self.tags:
            data["tags"] = list(self.tags)
        if self.extra:
            data["extra"] = self.extra

        if self.line:
            data["line"] = self.line

        if self.line_no is not None:
            data["line_no"] = self.line_no

        if self.signature:
            data["signature"] = self.signature

        if self.message:
            data["message"] = self.message

        if self.location is not None:
            if isinstance(self.location, Path):
                data["location"] = normalize_path(cast(Path, self.location))
            else:
                data["location"] = self.location

        return data

    def __le__(self, other):
        if not isinstance(other, Detection):
            return True
        elif not (type(self.line_no) == int and type(other.line_no) == int):
            return True
        return self.line_no <= other.line_no

    def __hash__(self):
        """
        Default hash implementation for deduplication of detections.
        By default a combination of a class name and a `signature` attribute is used to produce the hash.

        Override this method for a custom deduplication logic
        """
        if not self.signature:
            return NotImplemented

        if self._hash is None:
            self._hash = hash((self.__class__.__name__, self.signature))
        return self._hash

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        try:
            return hash(self) == hash(other)
        except:
            return False

    @property
    def name(self) -> str:
        if self.detection_type:
            return self.detection_type
        else:
            return self.__class__.__name__

    @property
    def diff_hash(self) -> int:
        if self._diff_hash is None:
            self._diff_hash = hash((self.line, self.name, self.message))
        return self._diff_hash

    @property
    def slug(self) ->str:
        return self.name.lower()


class DataProcessing(Detection):
    pass


def get_severity(detection: Detection) -> str:
    if detection._severity is not None:
        return detection._severity

    for category, catdef in config.CFG["severities"].items():
        if "score" in catdef and detection.score >= catdef["score"]:
            return category
        if detection.name in catdef.get("detections", []):
            return category
        if set(catdef.get("tags", [])).intersection(detection.tags):
            return category

    return "unknown"
