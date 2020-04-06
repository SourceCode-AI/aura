from click import secho

from ..analyzers.rules import ModuleImport
from .. import utils
from .base import AuraOutput


class TextOutput(AuraOutput):
    def output(self, hits):
        hits = set(hits)
        imported_modules = {h.name for h in hits if isinstance(h, ModuleImport)}

        hits = list(self.filtered(hits))
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
                secho(f" * {h._asdict()}")
        else:
            secho("No detections has been triggered", fg="red", bold=True)
