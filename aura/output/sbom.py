from dataclasses import dataclass
from uuid import uuid4

from . import json


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

        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": f"urn:uuid:{str(uuid4())}",
            "version": 1,
            "components": components
        }

        print(json.dumps(data), file=self.out_fd)
