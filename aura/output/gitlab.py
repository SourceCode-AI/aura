from uuid import uuid4
from dataclasses import dataclass
from typing import List, Sequence

from .json import JSONScanOutput
from ..scan_data import ScanData
from ..json_proxy import dumps
from .. import __version__


@dataclass()
class GitlabSASTOutput(JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "gitlab-sast"

    def output(self, scans: Sequence[ScanData]):
        tpl = {
            "scanner": {
                "id": "aura",
                "name": "Aura framework",
                "version": __version__,
                "url": "https://sourcecode.ai",
                "vendor": {
                    "name": "SourceCode.AI"
                }
            },
            "version": "5.0.0",
            "status": "success",
            "type": "sast",
            "vulnerabilities": []
        }

        for scan in scans:
            for detection in scan.hits:
                d = detection.to_json()
                data = {
                    "id": str(uuid4()),
                    "category": d["type"],
                    "severity": d["severity"].capitalize(),
                    "message": d["message"],
                    "location": {
                        "file": d["location"]
                    },
                    "cve": "",  # Required property for some reason
                    "identifiers": [  # Also required per jsonschema
                        # We will just copy a list of tags in here
                        # `[d["type"]]` is fallback because this array must be non-empty
                        {
                            "type": "aura",
                            "name": "tag",
                            "value": x
                        } for x in d.get("tags", [d["type"]])
                    ],
                    "scanner": {
                        "id": "aura",
                        "name": "Aura framework"
                    }
                }
                tpl["vulnerabilities"].append(data)

        print(dumps(tpl), file=self.out_fd)
