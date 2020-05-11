"""
Analyzer that looks for interesting data blobs inside the source code
"""
import re
import os
import base64
import binascii

from . import rules
from .base import NodeAnalyzerV2
from ..utils import Analyzer
from ..pattern_matching import PatternMatcher
from .. import config


BASE64_REGEX = re.compile(
    r"^([A-Za-z0-9+\/]{4}){12,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b$"
)


@Analyzer.ID("data_finder")
class DataFinder(NodeAnalyzerV2):
    """Extracts artifacts from the source code such sa URLs or Base64 blobs"""
    def node_String(self, context):
        val = context.node.value
        pth = os.fspath(context.visitor.normalized_path)

        if BASE64_REGEX.match(val):
            try:
                result = base64.b64decode(val)
                result = result.decode("utf-8")

                yield rules.Rule(
                    detection_type="Base64Blob",
                    message="Base64 data blob found",
                    node=context.node,
                    score=config.get_score_or_default("base-64-blob", 0),
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
            output = rules.Rule(
                detection_type="StringMatch",
                message=hit.message,
                extra={
                    "signature_id": hit._signature["id"],
                    "string": value
                },
                signature=f"string_finder#{hit._signature['id']}#{value}#{context.visitor.normalized_path}/{context.node.line_no}",
                score=hit._signature.get("score", 0),
                node=context.node,
                #location=context.visitor.path,
                tags=set(hit._signature.get("tags", []))
            )
            yield output

        yield from []
