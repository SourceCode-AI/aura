from uuid import uuid4
from dataclasses import dataclass

from .json import JSONScanOutput
from ..json_proxy import dumps
from .. import __version__


@dataclass()
class GitlabSASTOutput(JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "gitlab-sast"

    def output(self, hits, scan_metadata: dict):
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

        for detection in hits:
            d = detection._asdict()
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

        print(dumps(tpl), file=self._fd)
