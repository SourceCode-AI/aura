"""
Analyzer that looks for interesting data blobs inside the source code
"""
import re
import os
import base64
import binascii
from dataclasses import dataclass

from . import rules
from .base import NodeAnalyzerV2
from ..utils import Analyzer
from ..pattern_matching import PatternMatcher
from .. import config


URL_REGEX = re.compile(r"^(http|ftp)s?://.+")
BASE64_REGEX = re.compile(
    r"^([A-Za-z0-9+\/]{4}){12,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b$"
)


@dataclass
class URL(rules.Rule):
    message = "URL found"
    __hash__ = rules.Rule.__hash__


@dataclass
class Base64Blob(rules.Rule):
    message = "Base64 data blob found"
    __hash__ = rules.Rule.__hash__


@dataclass
class StringMatch(rules.Rule):
    __hash__ = rules.Rule.__hash__


@Analyzer.ID("data_finder")
class DataFinder(NodeAnalyzerV2):
    """Extracts artifacts from the source code such sa URLs or Base64 blobs"""
    def node_String(self, context):
        val = context.node.value
        pth = os.fspath(context.visitor.normalized_path)

        if URL_REGEX.match(val):
            yield URL(
                node=context.node,
                line_no=context.node.line_no,
                tags={"url",},
                extra={"url": val},
                signature=f"data_finder#url#{hash(val)}#{hash(pth)}",
            )
        elif BASE64_REGEX.match(val):
            try:
                result = base64.b64decode(val)
                result = result.decode("utf-8")

                yield Base64Blob(
                    node=context.node,
                    line_no=context.node.line_no,
                    tags={"base64",},
                    extra={"base64_decoded": result},
                    signature=f"data_finder#base64_blob#{hash(result)}#{hash(pth)}",
                )
            except UnicodeError:
                return
            except binascii.Error:
                return


@Analyzer.ID("string_finder")
class StringFinder(NodeAnalyzerV2):
    """Find string patterns as defined in the signatures file"""
    def node_String(self, context):
        signatures = config.SEMANTIC_RULES.get("strings", [])
        compiled = PatternMatcher.compile_patterns(signatures=signatures)
        value = str(context.node)

        for hit in PatternMatcher.find_matches(value, compiled):
            # TODO: define some kind of _id to embed into the signature below
            output = StringMatch(
                message=hit.message,
                extra={
                    "string": value
                },
                signature=f"string_finder#{value}/{context.node.line_no}#{context.visitor.normalized_path}",
                score=hit._signature.get("score", 0)
            )
            yield output

        yield from []
