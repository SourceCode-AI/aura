"""
Analyzer that looks for interesting data blobs inside the source code
"""
import re
import os
import base64
import binascii
import tempfile
from typing import Union, cast

from .detections import Detection
from .base import NodeAnalyzerV2
from .python.nodes import Context, String, Bytes, ASTNode
from ..utils import Analyzer
from ..pattern_matching import PatternMatcher
from ..uri_handlers.base import ScanLocation
from ..bases import ASTAnalyzer
from .. import utils
from .. import config


BASE64_REGEX = re.compile(
    r"^([A-Za-z0-9+\/]{4}){12,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b$"
)


class DataFinder(NodeAnalyzerV2, ASTAnalyzer):
    """Extracts artifacts from the source code such sa URLs or Base64 blobs"""
    analyzer_id = "data_finder"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]

        self._no_blobs = False

        if "AURA_NO_BLOBS" in os.environ:
            self._no_blobs = True

        self.__min_blob_size = self.get_min_size()

    @classmethod
    def get_min_size(cls) -> int:
        return config.get_settings("aura.min-blob-size", 100)  # type: ignore[return-value]

    def node_String(self, context: Context):
        node = cast(String, context.node)

        val = node.value

        if BASE64_REGEX.match(val):
            try:
                result = base64.b64decode(val).decode("utf-8")

                yield Detection(
                    detection_type="Base64Blob",
                    message="Base64 data blob found",
                    node=node,
                    score=config.get_score_or_default("base-64-blob", 0),
                    tags={"behavior:obfuscation", "behavior:base64_payload"},
                    extra={"base64_decoded": result},
                    signature=f"data_finder#base64_blob#{utils.fast_checksum(result)}#{context.signature}",
                )
            except UnicodeError:
                pass
            except binascii.Error:
                pass

        if len(val) >= self.__min_blob_size and self._no_blobs is False:
            yield self.__export_blob(val, context)

    def node_Bytes(self, context: Context):
        node = cast(Bytes, context.node)

        if len(node.value) >= self.__min_blob_size and self._no_blobs is False:
            yield self.__export_blob(node.value, context)

    def __export_blob(self, blob: Union[bytes, str], context: Context) -> ScanLocation:
        node = cast(ASTNode, context.node)

        tmp_dir = tempfile.mkdtemp(prefix="aura_pkg__sandbox_blob_")
        file_pth = os.path.join(tmp_dir, "blob")

        location = context.visitor.location.create_child(
            parent=context.visitor.location,
            new_location=tmp_dir,
            cleanup=True,
            strip_path=tmp_dir
        )
        location.metadata["source"] = "blob"
        location.metadata["parent_line"] = node.line_no

        if type(blob) == str:
            mode = "w"
        else:
            mode = "wb"

        with open(file_pth, mode) as fd:
            fd.write(blob)
            fd.flush()

        return location


class StringFinder(NodeAnalyzerV2, ASTAnalyzer):
    """Find string patterns as defined in the signatures file"""
    analyzer_id = "string_finder"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]

        signatures = config.SEMANTIC_RULES.get("strings", [])  # type: ignore[union-attr]
        self.__compiled_signatures = PatternMatcher.compile_patterns(signatures=signatures)

    def node_String(self, context: Context):
        value = str(context.node)

        for hit in PatternMatcher.find_matches(value, self.__compiled_signatures):
            yield self.__generate_hit(context, hit, value)

    def node_Bytes(self, context: Context):
        try:
            value = str(context.node)
        except (UnicodeDecodeError, TypeError):
            return

        for hit in PatternMatcher.find_matches(value, self.__compiled_signatures):
            yield self.__generate_hit(context, hit, value)

    def __generate_hit(self, context: Context, hit, value: str):
        score = hit._signature.get("score", 0)
        node = cast(ASTNode, context.node)

        return Detection(
                detection_type="StringMatch",
                message=hit.message,
                extra={
                    "signature_id": hit._signature["id"],
                    "string": value
                },
                signature=f"string_finder#{hit._signature['id']}#{utils.fast_checksum(value)}#{context.signature}",
                score=score,
                node=node,
                location=context.visitor.path,
                tags=set(hit._signature.get("tags", [])),
                informational=hit._signature.get("informational", (score==0))
            )
