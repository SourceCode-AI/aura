from importlib import resources
from io import StringIO
from base64 import b64encode
from dataclasses import dataclass

from .json import JSONScanOutput


@dataclass()
class HTMLOutput(JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "html"

    def output(self, hits, scan_metadata: dict):
        json_fd = StringIO()
        super().output(hits, scan_metadata, fd=json_fd)

        js_renderer = resources.read_text("aura.data.html_results", "results.js")
        payload = resources.read_text("aura.data.html_results", "template.html")
        payload = payload.replace("{js_renderer}", js_renderer)
        payload = payload.replace("{scan_data}", b64encode(json_fd.getvalue().encode()).decode())

        print(payload, file=self.out_fd)
