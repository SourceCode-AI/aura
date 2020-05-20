import re
from textwrap import shorten, wrap
from prettyprinter import pformat

from click import echo, secho, style

from .. import utils
from .. import config
from ..exceptions import MinimumScoreNotReached
from .base import AuraOutput


# Reference for unicode box characters:
# https://jrgraphix.net/r/Unicode/2500-257F

class PrettyReport:
    STRIP_ANSI_RE = re.compile(r"""
    \x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z] # a letter
    """, re.VERBOSE).sub

    def __init__(self):
        self.width = config.get_int("aura.text-output-width", 120)

    @classmethod
    def ansi_length(cls, line:str):
        return len(cls.STRIP_ANSI_RE("", line))

    def print_separator(self, sep="\u2504", left="\u251C", right="\u2524"):
        secho(f"{left}{sep*(self.width-2)}{right}")

    def align(self, line, pos=-1, left="\u2502 ", right=" \u2502"):
        content_len = self.ansi_length(line)
        remaining_len = self.width - len(left) - len(right)

        if content_len > remaining_len:
            line = line[:remaining_len-6] + " [...]" #shorten(line, width=remaining_len)

        if pos == -1:
            line = line + " "*(remaining_len-content_len)
        else:
            line = " "*(remaining_len-content_len) + line

        echo(f"{left}{line}{right}")

    def wrap(self, text, left="\u2502 ", right=" \u2502"):
        remaining_len=self.width - len(left) - len(right)
        for line in wrap(text, width=remaining_len):
            self.align(line, left=left, right=right)

    def pformat(self, obj, left="\u2502 ", right=" \u2502"):
        remaining_len = self.width - len(left) - len(right)
        for line in pformat(obj, width=remaining_len).splitlines(False):
            self.align(line, left=left, right=right)


class TextOutput(AuraOutput):
    formatter = PrettyReport()

    def output(self, hits):
        hits = set(hits)
        imported_modules = {h.extra["name"] for h in hits if h.name == "ModuleImport"}

        try:
            hits = self.filtered(hits)
        except MinimumScoreNotReached:
            return

        score = 0
        tags = set()

        for h in hits:
            score += h.score
            tags |= h.tags

        score = sum(x.score for x in hits)

        if score < self.metadata.get("min_score", 0):
            return

        secho(
            f"\n-----[ Scan results for {self.metadata.get('name', 'N/A')} ]-----",
            fg="green",
        )
        secho(f"Scan score: {score}", fg="red", bold=True)
        if len(tags) > 0:
            secho(f"Tags: {', '.join(tags)}")

        if imported_modules:
            secho("Imported Modules:")
            secho(utils.pprint_imports(utils.imports_to_tree(imported_modules)))
        else:
            secho("No imported modules detected")

        if hits:
            secho("Detections:")
            for h in hits:
                self._format_detection(h._asdict())
        else:
            secho("No detections has been triggered", fg="red", bold=True)

    def _format_detection(self, hit):
        out = self.formatter
        out.print_separator(left="\u2552", sep="\u2550", right="\u2555")
        out.align(style(hit["type"], "green", bold=True))
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
        out.print_separator(left="\u2558", sep="\u2550", right="\u255B")

    def output_diff(self, diffs):
        for diff in diffs:
            if diff.operation == "M":
                secho(
                    f"Modified file '{diff.a_ref}' -> '{diff.b_ref}' . Similarity: {diff.similarity}%",
                    fg="red",
                )
            elif diff.operation == "R":
                secho(f"File renamed: '{diff.a_ref}' -> '{diff.b_ref}'", fg="green")
            elif diff.operation == "A":
                secho(f"File added: '{diff.b_ref}'", fg="yellow")
            elif diff.operation == "D":
                secho(f"File removed: '{diff.a_ref}'", fg="green")

            if diff.diff:
                secho("---[ START OF DIFF ]---", fg="blue")
                secho(diff.diff)
                secho("---[ END OF DIFF ]---", fg="blue")
