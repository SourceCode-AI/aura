import re
import sys
from shutil import get_terminal_size
from dataclasses import dataclass
from textwrap import wrap
from prettyprinter import pformat
from typing import Optional, Any
from collections import Counter

from click import secho, style

from .. import utils
from .. import config
from ..analyzers.detections import get_severity
from .base import ScanOutputBase, DiffOutputBase, InfoOutputBase
from .table import Table


# Reference for unicode box characters:
# https://jrgraphix.net/r/Unicode/2500-257F

# ASCII Logo generated from png using https://asciiart.club/  & tweaked for better visual appearance
LOGO = """
                ▁▄▄▄▄▄▄▄▄▁                                           
           ▁▄████████████████▄▁                                      
        ▄▆█████▀▀▀▀    ▀▀▀▀█████▆▄                                   
      ▄████▀▀      ▄▄▄▄      ▀▀████▄                                 
    ▄████▀    ▄▆██████████▆▄    ▀████▄                               
   ▆███▀   ▄█████▀▀    ▀▀█████▄   ▀███▆                              
  ▟███▀   ████▀            ▀████   ▀███▙                             
 ▗███▌   ███▀     ▄█▛▜█▄     ▀███   ▐███▖      ___                   
 ▟██▌   ████     ██▋  ▐██     ████   ▐██▙     /   | __  ___________ _
 ███▏  ▐████████▙▀██▌▐██▀▟████████▌  ▕███    / /| |/ / / / ___/ __ `/
 ▜██▌   ████▔▔▔▔▔▔▄█▌▐█▄▔▔▔▔▔▔████   ▐██▛   / ___ / /_/ / /  / /_/ / 
 ▝███   ▝███▄    ▄█▙▄▄▟█▄    ▄███▘   ███▘  /_/  |_\__,_/_/   \__,_/  
  ▜███   ▝███▄   ▀▀▀▀▀▀▀▀   ▄███▘   ███▛                             
   ████▖   ▀██▌            ▐██▀   ▗████    {version}                 
    ▀███▖    ▀              ▀    ▄████                               
     ▝█████▄                  ▄█████▀          by SourceCode.AI      
       ▝▀█████▄▄▁        ▁▄▄██████▘                                  
          ▝▀██████████████████▀▘                                     
               ▔▀▀▀▀▀▀▀▀▀▀▔                                                                         
"""


SEVERITY_COLORS = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "magenta",
    "unknown": "white"
}



class PrettyReport:
    ANSI_RE = re.compile(r"""
    (\x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z]) # a letter
    """, re.VERBOSE)

    def __init__(self, fd=None):
        width = config.get_settings("aura.text-output-width", "auto")
        if width == "auto":
            self.width = get_terminal_size(fallback=(120, 24))[0]
        else:
            self.width = int(width or 120)

        self.fd = fd

    @classmethod
    def ansi_length(cls, line:str):
        return len(cls.ANSI_RE.sub("", line))

    def print_separator(self, sep="\u2504", left="\u251C", right="\u2524"):
        secho(f"{left}{sep*(self.width-2)}{right}", file=self.fd)

    def print_thick_separator(self):
        self.print_separator(left="\u255E", sep="\u2550", right="\u2561")

    def print_top_separator(self):
        self.print_separator(left="\u2552", sep="\u2550", right="\u2555")

    def print_bottom_separator(self):
        self.print_separator(left="\u2558", sep="\u2550", right="\u255B")

    def print_heading(self, text, left="\u251C", right="\u2524", infill="\u2591"):
        text_len = self.ansi_length(text)
        ljust = (self.width-4-text_len)//2
        rjust = self.width-4-text_len-ljust
        secho(f"{left}{infill*ljust} {text} {infill*rjust}{right}", file=self.fd)

    def align(self, line, pos=-1, left="\u2502 ", right=" \u2502"):
        line = self._align_text(line, self.width - len(left) - len(right), pos=pos)
        secho(f"{left}{line}{right}", file=self.fd)

    def wrap(self, text, left="\u2502 ", right=" \u2502"):
        remaining_len=self.width - len(left) - len(right)
        for line in wrap(text, width=remaining_len):
            self.align(line, left=left, right=right)

    def pformat(self, obj, left="\u2502 ", right=" \u2502"):
        remaining_len = self.width - len(left) - len(right)
        for line in pformat(obj, width=remaining_len).splitlines(False):
            self.align(line, left=left, right=right)

    def _align_text(self, text, width, pos=-1):
        content_len = self.ansi_length(text)
        remaining_len = width
        overflow = content_len - remaining_len

        if content_len > remaining_len:
            parts = self.ANSI_RE.split(text)[::-1]
            for idx, x in enumerate(parts):
                if x.startswith(r"\x1b"):
                    continue
                if len(x) > overflow:
                    parts[idx] = x[:-overflow-6] + " [...]"
                    break

            text = "".join(parts[::-1])

        if pos == -1:
            return text + " " * (remaining_len - content_len)
        else:
            return " " * (remaining_len - content_len) + text


@dataclass()
class TextBase:
    _formatter: Optional[PrettyReport] = None

    @classmethod
    def protocol(cls) -> str:
        return "text"

    def _format_detection(
            self,
            hit,
            *,
            header: Optional[str]=None,
            top_separator=True,
            bottom_separator=True
    ):
        out = self._formatter
        if top_separator:
            out.print_top_separator()

        if header is None:
            header = style(hit["type"], "green", bold=True)
            color = SEVERITY_COLORS[hit["severity"]]
            header += style(f" / {hit['severity'].capitalize()} severity", fg=color)
        out.print_heading(header)

        out.print_separator()
        out.wrap(hit["message"])
        out.print_separator()

        if hit.get('line_no') or hit.get('location'):
            line_info = f"Line {style(str(hit.get('line_no', 'N/A')), 'blue', bold=True)}"
            line_info += f" at {style(hit['location'], 'blue', bold=True)}"
            out.align(line_info)

        if hit.get('line'):
            out.align(style(hit["line"], "cyan"))
        out.print_separator()

        score = f"Score: {style(str(hit['score']), 'blue', bold=True)}"
        if hit.get('informational'):
            score += ", informational"
        out.align(score)

        out.align(f"Tags: {', '.join(hit.get('tags', []))}")
        out.align("Extra:")
        out.pformat(hit.get('extra', {}))
        if bottom_separator:
            out.print_bottom_separator()

    def pprint_imports(self, tree, indent=""):
        """
        pretty print the module tree
        """
        last = len(tree) - 1
        for ix, x in enumerate(tree.keys()):
            subitems = tree.get(x, {})

            # https://en.wikipedia.org/wiki/Box-drawing_character
            char = ""
            if ix == last:
                char += "└"
            elif ix == 0:
                char += "┬"
            else:
                char += "├"

            yield f"{indent}{char} {style(x, fg='bright_blue')}"
            if subitems:
                new_indent = " " if ix == last else "│"
                yield from self.pprint_imports(subitems, indent + new_indent)

    def imports_to_tree(self, items: list) -> dict:
        """
        Transform a list of imported modules into a module tree
        """
        root = {}
        for x in items:
            parts = x.split(".")
            current = root
            for x in parts:
                if x not in current:
                    current[x] = {}
                current = current[x]

        return root

    def output_table(self, table):
        out = PrettyReport(fd=self._fd)
        out.print_top_separator()

        if table.metadata.get("title"):
            out.print_heading(table.metadata["title"])

        for row in table:
            cols = []
            for idx, col in enumerate(row):
                text = out._align_text(style(str(col), **col.style), width=table.col_len[idx])
                cols.append(text)

            out.align(" \u2502 ".join(cols))

        out.print_bottom_separator()


@dataclass()
class TextScanOutput(TextBase, ScanOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            self._formatter = PrettyReport(fd=sys.stdout)
            return

        self._fd = open(self.output_location, "w")
        self._formatter = PrettyReport(fd=self._fd)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    def output(self, hits, scan_metadata: dict):
        hits = set(hits)
        imported_modules = {h.extra["name"] for h in hits if h.name == "ModuleImport"}
        score = 0
        tags = set()
        severities = Counter(get_severity(d) for d in hits)

        for h in hits:
            score += h.score
            tags |= h.tags

        score = sum(x.score for x in hits)

        if score < self.min_score:
            return

        secho("\n", file=self._fd)  # Empty line for readability
        self._formatter.print_top_separator()
        self._formatter.print_heading(style(f"Scan results for {scan_metadata.get('name', 'N/A')}", fg="bright_green"))
        score_color = "bright_green" if score == 0 else "bright_red"
        self._formatter.align(style(f"Scan score: {score}", fg=score_color, bold=True))

        self._formatter.align("")

        for severity, color in SEVERITY_COLORS.items():
            count = severities[severity]
            if count == 0:
                color = "bright_black"
            self._formatter.align(style(f"{severity.capitalize()} severity - {count}x", fg=color))

        self._formatter.align("")

        if len(tags) > 0:
            self._formatter.align(f"Tags:")
            for t in tags:
                self._formatter.align(f" - {t}")

        if imported_modules:
            self._formatter.print_heading("Imported modules")
            for line in self.pprint_imports(self.imports_to_tree(imported_modules)):
                self._formatter.align(line)
        else:
            self._formatter.print_heading("No imported modules detected")

        if hits:
            self._formatter.print_heading("Code detections")
            for h in hits:
                self._formatter.print_thick_separator()
                self._format_detection(h._asdict(), top_separator=False, bottom_separator=False)
        else:
            self._formatter.print_heading(style("No code detections has been triggered", fg="bright_green"))

        self._formatter.print_bottom_separator()


class TextInfoOutput(InfoOutputBase):
    @classmethod
    def protocol(cls) -> str:
        return "text"

    def output_info_data(self, data):
        OK = '\u2713'
        NOK = '\u2717'

        out = PrettyReport()

        # Left hand side of the table contains logo and basic project information
        logo = LOGO.format(version=f'Version {data["aura_version"]}'.center(26))

        lhs_lines = logo.split("\n")
        lhs_size = max(len(x) for x in lhs_lines) + 1

        #print(logo)
        out.print_top_separator()

        # Right hand side lists environment information (installed plugins, URI handlers etc.)
        rhs_lines = []

        semantic = data["schema_validation"]["semantic_rules"]
        if semantic is True:
            rhs_lines.append(style(f" {OK} Semantic rules configuration is valid", fg="bright_green"))
        else:
            rhs_lines.append(style(f" {NOK} Semantic rules configuration is not valid:", fg="bright_red"))
            rhs_lines.append(semantic)

        rhs_lines.append("")
        rhs_lines.append("Installed analyzers:")

        rhs_size = max(len(x) for x in rhs_lines)

        #out.align("Installed analyzers: ")
        for name, i in data["analyzers"].items():
            if i["enabled"]:
                mark = OK
                s = {"fg": "bright_green"}
            else:
                mark = NOK
                s = {"fg": "bright_red"}

            rhs_lines.append(style(f" {mark} {name}: {i['description']}", **s))
            #out.align(style(f" {mark} {name}: {i['description']}", **s))

        rhs_lines.append("Installed URI handlers:")
        #out.align("Installed URI handlers: ")
        for name, i in data["uri_handlers"].items():
            mark = OK
            s = {"fg": "bright_green"}

            rhs_lines.append(style(f" {mark} {name}://", **s))
            #out.align(style(f" {mark} {name}://", **s))

        for idx in range(max(len(rhs_lines), len(lhs_lines))):
            if idx < len(lhs_lines):
                lhs = out._align_text(lhs_lines[idx], lhs_size)
            else:
                lhs = " "*lhs_size

            if idx < len(rhs_lines):
                rhs = rhs_lines[idx]
            else:
                rhs = " "

            out.align(f"{lhs} \u2502 {rhs}")

        out.print_bottom_separator()


@dataclass()
class TextDiffOutput(TextBase, DiffOutputBase):
    _fd: Any = None

    def __enter__(self):
        if self.output_location == "-":
            self._formatter = PrettyReport(fd=sys.stdout)
            return

        self._fd = open(self.output_location, "w")
        self._formatter = PrettyReport(fd=self._fd)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    def output_diff(self, diff_analyzer):
        out = PrettyReport(fd=self._fd)

        for table in diff_analyzer.tables:
            self.output_table(table)

        for diff in self.filtered(diff_analyzer.diffs):
            out.print_separator(left="\u2552", sep="\u2550", right="\u2555")

            if diff.operation in ("M", "R"):
                op = "Modified" if diff.operation == "M" else "Renamed"
                out.align(style(f"{op} file. Similarity: {int(diff.similarity * 100)}%", fg="bright_red", bold=True))
                out.align(f"A Path: {style(diff.a_ref, fg='bright_blue')}")
                out.align(f"B Path: {style(diff.b_ref, fg='bright_blue')}")
            elif diff.operation == "A":
                out.align(style(f"File added.", fg="bright_yellow"))
                out.align(f"Path: {style(diff.b_ref, fg='bright_blue')}")
            elif diff.operation == "D":
                out.align(style(f"File removed", fg="green"))
                out.align(f"Path: {style(diff.a_ref, fg='bright_blue')}")

            if diff.diff and self.patch:
                out.print_heading("START OF DIFF")

                for diff_line in diff.diff.splitlines():
                    if diff_line.startswith("@@"):
                        opts = {"fg": "bright_blue"}
                    elif diff_line.startswith("+"):
                        opts = {"fg": "bright_green"}
                    elif diff_line.startswith("-"):
                        opts = {"fg": "bright_red"}
                    else:
                        opts = {"fg": "bright_black"}

                    out.align(style(diff_line, **opts))

                out.print_heading("END OF DIFF")

            if diff.removed_detections or diff.new_detections:
                out.print_separator()

            if diff.removed_detections:
                out.print_heading(style("Removed detections for this file", fg="bright_yellow"))
                for x in diff.removed_detections:
                    out.print_separator()
                    x = x._asdict()
                    header = style(f"Removed: '{x['type']}'", fg="green", bold=True)
                    self._format_detection(x, header=header, bottom_separator=False, top_separator=False)

            if diff.new_detections:
                out.print_heading(style("New detections for this file", fg="bright_red"))
                for x in diff.new_detections:
                    out.print_separator()
                    x = x._asdict()
                    header = style(f"Added: '{x['type']}'", fg="red", bold=True)
                    self._format_detection(x, header=header, bottom_separator=False, top_separator=False)

            out.print_separator(left="\u2558", sep="\u2550", right="\u255B")
