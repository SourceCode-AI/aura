import datetime
from dataclasses import dataclass
from uuid import uuid4

from . import json
from .. import __version__


@dataclass()
class SBOMOutput(json.JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "sbom"

    def __enter__(self):
        super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        super().__exit__(exc_type, exc_val, exc_tb)

    def output(self, hits, scan_metadata: dict):
        components = []

        for x in hits:
            if "sbom_component" in x.tags:
                components.append(x.extra)

        now = datetime.datetime.utcnow()

        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": f"urn:uuid:{str(uuid4())}",
            "version": 1,
            "metadata": {
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "tools": [
                    {
                        "vendor": "SourceCode.AI",
                        "name": "Aura",
                        "version": __version__,
                    }
                ]
            },
            "components": components
        }

        print(json.dumps(data), file=self.out_fd)
