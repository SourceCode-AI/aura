from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Iterable


from .. import base
from ..detections import Detection
from ...bases import JSONSerializable
from ...bases import ASTAnalyzer
from ... import config


@dataclass(frozen=True)
class UnicodeCharacter(JSONSerializable):
    character: str

    @classmethod
    def from_character(cls, char: str) -> UnicodeCharacter:
        assert len(char) == 1
        return cls(character=char)

    @property
    def name(self) -> str:
        return unicodedata.name(self.character)

    @property
    def category(self) -> str:
        return unicodedata.category(self.character)

    def to_dict(self) -> dict:
        return {
            "character": repr(self.character),
            "name": self.name,
            "category": self.category
        }


def analyze_string(data: str) -> Iterable[UnicodeCharacter]:
    """
    Check if given string contains non-ascii characters

    :param data: input string to check
    :type data: str
    :return: list of detected non-ascii character definitions
    :rtype: Iterable[UnicodeCharacter]
    """
    chars = []

    for char in data:
        if ord(char) >= 128:
            chars.append(UnicodeCharacter.from_character(char))

    return chars


class NonAsciiCharacters(base.NodeAnalyzerV2, ASTAnalyzer):
    analyzer_id = "non_ascii_characters"

    def node_Var(self, context):
        if context.node.var_type != "assign":
            return
        elif type(context.node.var_name) != str:
            return

        chars = analyze_string(context.node.var_name)
        if chars:
            yield Detection(
                detection_type="NonAsciiCharacters",
                score=config.get_score_or_default("non-ascii-tokens", 50),
                message="Variable name contains non-ascii characters",
                signature=f"misc:nonascii:var#{context.signature}",
                node = context.node,
                line_no=context.node.line_no,
                tags={"nonascii:var", "pep:672"},
                extra={
                    "characters": [
                        x.to_json() for x in chars
                    ]
                }
            )

    def node_Attribute(self, context):
        chars = analyze_string(context.node.attr)
        if chars:
            yield Detection(
                detection_type="NonAsciiCharacters",
                score=config.get_score_or_default("non-ascii-tokens", 50),
                message=f"Attribute name contains non-ascii characters",
                signature=f"misc:nonascii:attr#{context.signature}",
                node = context.node,
                line_no=context.node.line_no,
                tags={"nonascii:attr", "pep:672"},
                extra={
                    "characters": [
                        x.to_json() for x in chars
                    ]
                }
            )

    def node_FunctionDef(self, context):
        chars = analyze_string(context.node.name)
        if chars:
            yield Detection(
                detection_type="NonAsciiCharacters",
                score=config.get_score_or_default("non-ascii-tokens", 50),
                message=f"Function name definition contains non-ascii characters",
                signature=f"misc:nonascii:func#{context.signature}",
                node=context.node,
                line_no=context.node.line_no,
                tags={"nonascii:func", "pep:672"},
                extra={
                    "characters": [
                        x.to_json() for x in chars
                    ]
                }
            )

    def node_ClassDef(self, context):
        chars = analyze_string(context.node.name)
        if chars:
            yield Detection(
                detection_type="NonAsciiCharacters",
                score=config.get_score_or_default("non-ascii-tokens", 50),
                message=f"Class name definition contains non-ascii characters",
                signature=f"misc:nonascii:class#{context.signature}",
                node=context.node,
                line_no=context.node.line_no,
                tags={"nonascii:class", "pep:672"},
                extra={
                    "characters": [
                        x.to_json() for x in chars
                    ]
                }
            )
