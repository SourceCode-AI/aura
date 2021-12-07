from importlib import resources
from io import StringIO
from base64 import b64encode
from pathlib import Path
from dataclasses import dataclass
from typing import Sequence

import jinja2

from .json import JSONScanOutput
from ..scan_data import ScanData

with resources.path("aura.data.html_results", "template.html") as rpath:
    tpl_pth = rpath.parent


jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(tpl_pth))
)



@dataclass()
class HTMLOutput(JSONScanOutput):
    @classmethod
    def protocol(cls) -> str:
        return "html"

    def output(self, scans: Sequence[ScanData]):
        json_fd = StringIO()
        super().output(scans, fd=json_fd)

        scan_data = b64encode(json_fd.getvalue().encode()).decode()
        app_js = resources.read_text("aura.data.html_results", "app.js")
        components_js = resources.read_text("aura.data.html_results", "components.js")
        aura_css = resources.read_text("aura.data.html_results", "aura.css")
        tpl = jenv.from_string(resources.read_text("aura.data.html_results", "template.html"))

        js_renderer = components_js + "\n" + app_js

        payload = tpl.render(
            scan_data=scan_data,
            js_renderer=js_renderer,
            custom_css=aura_css
        )

        print(payload, file=self.out_fd)
