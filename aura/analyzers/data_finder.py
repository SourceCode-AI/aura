"""
Analyzer that looks for interesting data blobs inside the source code
"""
import re
import os
import base64
import binascii
import tempfile
from typing import Union

from .detections import Detection
from .base import NodeAnalyzerV2
from .python.nodes import Context
from ..utils import Analyzer
from ..pattern_matching import PatternMatcher
from ..uri_handlers.base import ScanLocation
from .. import utils
from .. import config


BASE64_REGEX = re.compile(
    r"^([A-Za-z0-9+\/]{4}){12,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b$"
)


@Analyzer.ID("data_finder")
class DataFinder(NodeAnalyzerV2):
    """Extracts artifacts from the source code such sa URLs or Base64 blobs"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._no_blobs = False

        if "AURA_NO_BLOBS" in os.environ:
            self._no_blobs = True

        self.__min_blob_size = self.get_min_size()

    @classmethod
    def get_min_size(cls) -> int:
        return config.get_settings("aura.min-blob-size", 100)

    def node_String(self, context: Context):
        val = context.node.value

        if BASE64_REGEX.match(val):
            try:
                result = base64.b64decode(val)
                result = result.decode("utf-8")

                yield Detection(
                    detection_type="Base64Blob",
                    message="Base64 data blob found",
                    node=context.node,
                    score=config.get_score_or_default("base-64-blob", 0),
                    tags={"base64",},
                    extra={"base64_decoded": result},
                    signature=f"data_finder#base64_blob#{utils.fast_checksum(result)}#{context.signature}",
                )
            except UnicodeError:
                pass
            except binascii.Error:
                pass

        if len(val) >= self.__min_blob_size and self._no_blobs is False:
            yield self.__export_blob(val, context)

    def node_Binary(self, context: Context):
        if len(context.node.value) >= self.__min_blob_size and self._no_blobs is False:
            yield self.__export_blob(context.node.value, context)

    def __export_blob(self, blob: Union[bytes, str], context: Context) -> ScanLocation:
        tmp_dir = tempfile.mkdtemp(prefix="aura_pkg__sandbox_blob_")
        file_pth = os.path.join(tmp_dir, "blob")

        location = context.visitor.location.create_child(
            parent=context.visitor.location,
            new_location=tmp_dir,
            cleanup=True,
            strip_path=tmp_dir
        )
        location.metadata["source"] = "blob"
        location.metadata["parent_line"] = context.node.line_no

        if type(blob) == str:
            mode = "w"
        else:
            mode = "wb"

        with open(file_pth, mode) as fd:
            fd.write(blob)
            fd.flush()

        return location


@Analyzer.ID("string_finder")
class StringFinder(NodeAnalyzerV2):
    """Find string patterns as defined in the signatures file"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        signatures = config.SEMANTIC_RULES.get("strings", [])
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
        return Detection(
                detection_type="StringMatch",
                message=hit.message,
                extra={
                    "signature_id": hit._signature["id"],
                    "string": value
                },
                signature=f"string_finder#{hit._signature['id']}#{utils.fast_checksum(value)}#{context.signature}",
                score=score,
                node=context.node,
                location=context.visitor.path,
                tags=set(hit._signature.get("tags", [])),
                informational=hit._signature.get("informational", (score==0))
            )
