import re
import os
import sys
import itertools
from shutil import get_terminal_size
from dataclasses import dataclass
from textwrap import wrap
from prettyprinter import pformat
from typing import Optional, Any, Generator
from collections import Counter

from click import secho, style

from .. import utils
from .. import config
from ..analyzers.detections import get_severity
from .base import ScanOutputBase, DiffOutputBase, InfoOutputBase, TyposquattingOutputBase
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


OK = '\u2713'
NOK = '\u2717'

TTY_COLORS = bool(os.environ.get("AURA_FORCE_COLORS", False)) or None



class PrettyReport:
    ANSI_RE = re.compile(r"""
    (\x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z]) # a letter
    """, re.VERBOSE)

    def __init__(self, fd=None):
        self.term_width = get_terminal_size(fallback=(120, 24))[0]

        if "AURA_TERM_WIDTH" in os.environ:
            self.width = int(os.environ["AURA_TERM_WIDTH"])
        else:
            width = config.get_settings("aura.text-output-width", "auto")
            if width == "auto":
                self.width = self.term_width
            else:
                self.width = int(width or 120)

        self.fd = fd

    @classmethod
    def ansi_length(cls, line:str):
        return len(cls.ANSI_RE.sub("", line))

    def print_separator(self, sep="\u2504", left="\u251C", right="\u2524", width=None):
        if width is None:
            width = self.width

        secho(f"{left}{sep*(width-2)}{right}", file=self.fd, color=TTY_COLORS)

    def print_thick_separator(self):
        self.print_separator(left="\u255E", sep="\u2550", right="\u2561")

    def print_top_separator(self, **kwargs):
        self.print_separator(left="\u2552", sep="\u2550", right="\u2555", **kwargs)

    def print_bottom_separator(self, **kwargs):
        self.print_separator(left="\u2558", sep="\u2550", right="\u255B", **kwargs)

    def generate_heading(self, text, left="\u251C", right="\u2524", infill="\u2591", width=None):
        if width is None:
            width = self.width - len(left) - len(right) - 2

        text_len = self.ansi_length(text)
        ljust = (width - text_len) // 2
        rjust = width - text_len - ljust
        return f"{left}{infill*ljust} {text} {infill*rjust}{right}"

    def print_heading(self, *args, **kwargs):
        secho(self.generate_heading(*args, **kwargs), file=self.fd, color=TTY_COLORS)

    def align(self, line, pos=-1, left="\u2502 ", right=" \u2502", width=None):
        if width is None:
            width = self.width
        line = self._align_text(line, width - len(left) - len(right), pos=pos)
        secho(f"{left}{line}{right}", file=self.fd, color=TTY_COLORS)

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

    def print_tables(self, *tables):
        table_widths = [t.width+2 for t in tables]

        self.print_top_separator()

        titles = [t.metadata.get("title", "N/A") for t in tables]
        tparts = [tuple(self.generate_heading(title, width=w, left="", right="") for w, title in zip(table_widths, titles))]

        for idx, rows in enumerate(itertools.zip_longest(*tables, fillvalue="")):

            full_row = []

            for ridx, row in enumerate(rows):
                text = " \u2506 ".join(self._align_text(c.pretty, width=tables[ridx].col_len[cidx]) for cidx, c in enumerate(row))
                text = self._align_text(text, width=table_widths[ridx]+2)

                full_row.append(text)

            tparts.append(full_row)

        for idx, tpart in enumerate(tparts):
            self.align(" \u2551 ".join(tpart))
            if idx == 0:
                self.print_thick_separator()

        self.print_bottom_separator()



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

        if hit.get("extra"):
            out.align("Extra data:")
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

    def output_table(self, table: Table):
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

        secho("\n", file=self._fd, color=TTY_COLORS)  # Empty line for readability
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

    def get_feature_status(self, fmt, name, status):
        enabled = status.get("enabled", True)
        mark = OK if enabled else NOK
        description = status.get("description", "Description N/A")
        s = {"fg": ("bright_green" if enabled else "bright_red")}
        return style(fmt.format(mark=mark, status=status, name=name, enabled=enabled, description=description), **s)

    def output_info_data(self, data):
        out = PrettyReport()

        # Left hand side of the table contains logo and basic project information
        logo = LOGO.format(version=f'Version {data["aura_version"]}'.center(26))

        lhs_lines = logo.split("\n")
        lhs_size = max(len(x) for x in lhs_lines) + 1

        #print(logo)
        out.print_top_separator()

        # Right hand side lists environment information (installed plugins, URI handlers etc.)
        rhs_lines = []

        if data["schema_validation"] is not None:
            semantic = data["schema_validation"]["semantic_rules"]
            if semantic is True:
                rhs_lines.append(style(f" {OK} Semantic rules configuration is valid", fg="bright_green"))
            else:
                rhs_lines.append(style(f" {NOK} Semantic rules configuration is not valid:", fg="bright_red"))
                rhs_lines.append(semantic)
        else:
            rhs_lines.append(style(f" ? - `jsonschema` is not installed, unable to verify the configuration", fg="cyan"))

        rhs_lines.append("")
        rhs_lines.append("Installed analyzers:")

        for name, i in data["analyzers"].items():
            rhs_lines.append(self.get_feature_status(fmt=" {mark} {name}: {description}", name=name, status=i))

        rhs_lines.append("Integrations:")
        for name, i in data["integrations"].items():
            rhs_lines.append(self.get_feature_status(fmt=" {mark} {name}: {description}", name=name, status=i))

        rhs_lines.append("Installed URI handlers:")
        for name, i in data["uri_handlers"].items():
            rhs_lines.append(self.get_feature_status(fmt=" {mark} `{name}://` - {description}", name=name, status=i))

        rhs_size = max(len(x) for x in rhs_lines)

        for idx in range(max(len(rhs_lines), len(lhs_lines))):
            if idx < len(lhs_lines):
                lhs = out._align_text(lhs_lines[idx], lhs_size)
            else:
                lhs = " "*lhs_size

            if idx < len(rhs_lines):
                rhs = rhs_lines[idx]
            else:
                rhs = " "


            if out.term_width <= 150:
                out.align(rhs)
            else:
                out.align(f"{lhs} \u2502 {rhs}")

        out.print_bottom_separator()


class TextTyposquattingOutput(TyposquattingOutputBase):
    @classmethod
    def protocol(cls) -> str:
        return "text"

    def output_typosquatting(self, entries):
        out = PrettyReport()
        for x in entries:
            diff_table = x["orig_pkg"]._cmp_info(x["typo_pkg"])
            orig_table = x["orig_score"].get_score_table()
            typo_table = x["typo_score"].get_score_table()
            out.print_tables(orig_table, typo_table, diff_table)


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

        if diff_analyzer.tables:
            out.print_tables(*diff_analyzer.tables)

        for diff in self.filtered(diff_analyzer.diffs):
            out.print_separator(left="\u2552", sep="\u2550", right="\u2555")

            if diff.operation in ("M", "R"):
                op = "Modified" if diff.operation == "M" else "Renamed"
                out.align(style(f"{op} file. Similarity: {int(diff.similarity * 100)}%", fg="bright_red", bold=True))
                out.align(f"A Path: {style(str(diff.a_scan), fg='bright_blue')}")
                out.align(f"B Path: {style(str(diff.b_scan), fg='bright_blue')}")
            elif diff.operation == "A":
                out.align(style(f"File added.", fg="bright_yellow"))
                out.align(f"Path: {style(str(diff.b_scan), fg='bright_blue')}")
            elif diff.operation == "D":
                out.align(style(f"File removed", fg="green"))
                out.align(f"Path: {style(str(diff.a_scan), fg='bright_blue')}")

            if diff.diff and self.patch:
                out.print_heading("START OF DIFF")

                for diff_line in diff.diff.splitlines():
                    diff_line = diff_line.rstrip()

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
