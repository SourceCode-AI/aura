from dataclasses import dataclass

from .json import JSONScanOutput
from ..json_proxy import dumps
from .. import __version__

# SARIF has only the following levels: ['none', 'note', 'warning', 'error']
LEVEL_MAP = {
    "critical": "warning",
    "high": "warning",
    "low": "note",
    "unknown": "none"
}


@dataclass()
class SARIFOutput(JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "sarif"

    def output(self, hits, scan_metadata: dict):
        tpl = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
            "runs": []
        }

        locations = {}

        run = {
            "tool": {
                "driver": {
                    "name": "Aura framework",
                    "version": __version__
                }
            },
            "results": [],
            "artifacts": []
        }

        for detection in hits:
            uri = detection.scan_location.location.as_uri()

            if uri not in locations:
                artifact = self._convert_to_artifact(detection)
                locations[uri] = artifact

            d = detection._asdict()
            level = d["severity"]
            level = LEVEL_MAP.get(level, level)

            region = {}

            if "line_no" in d:
                region["startLine"] = d["line_no"]
                region["endLine"] = d.get("end_line_no", d["line_no"])

            if "col" in d:
                region["startColumn"] = d["col"]

            if "end_col" in d:
                region["endColumn"] = d["end_col"]

            if "line" in d:
                region["snippet"] = {"text": d["line"]}
                if "endColumn" not in region:
                    region["endColumn"] = len(d["line"])

            result = {
                "ruleId": d["type"],
                "level": level,
                "message": {
                    "text": d["message"]
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri
                            },
                            "region": region
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": d["signature"]
                }
            }
            run["results"].append(result)

        run["artifacts"].extend(locations.values())
        tpl["runs"].append(run)

        print(dumps(tpl), file=self._fd)

    @staticmethod
    def _convert_to_artifact(detection) -> dict:
        artifact = {
            "location": {
                "uri": detection.scan_location.location.as_uri()
            },
            "length": detection.scan_location.size,
            "hashes": {
                "md5": detection.scan_location.metadata["md5"],
                "sha-1": detection.scan_location.metadata["sha1"],
                "sha-256": detection.scan_location.metadata["sha256"],
                "sha-512": detection.scan_location.metadata["sha512"],
                "tlsh": detection.scan_location.metadata["tlsh"]
            }
        }
        return artifact
