import copy
import sqlite3
from collections import defaultdict

import click

from . import utils
from .analyzers import rules


class ScanResults():
    def __init__(self, name, metadata=None):
        self.name = name
        self.verbosity = metadata.get('verbosity', 1)
        self.metadata = metadata
        self.hits = set()

        self._yara_hits = defaultdict(lambda : {'score': 0, 'hits': 0})
        self._tags = set()

        self.__imported_modules = set()
        self.__call_hits = defaultdict(lambda : {'score': 0, 'hits': 0})

    def add_hit(self, sender):
        self.hits.add(sender)

        if isinstance(sender, rules.ModuleImport):
            self.__imported_modules.add(sender.name)

    @property
    def filtered(self):
        hits = sorted(self.hits)

        for x in hits:
            if self.verbosity <2 and x.informational and x.score == 0:
                continue
            elif self.metadata.get('exclude_tests', False) and 'test_suite' in x.tags:
                continue

            yield x

    @property
    def score(self):
        score = 0
        for x in self.filtered:
            if hasattr(x, 'tags') and isinstance(x.tags, set):
                self._tags |= x.tags

            if False: # FIXME: isinstance(x, rules.YaraMatch):
                self._process_yara(x)
            elif isinstance(x, rules.FunctionCall):
                self._process_call(x)
            else:
                score += x.score

        score += sum(x['score'] for x in self._yara_hits.values())
        score += sum(x['score'] for x in self.__call_hits.values())

        return score

    def pprint(self, verbose=0):
        click.secho(f"\n---[ Scan results for '{self.name}' ]---", fg='green')
        click.secho(f"Scan score: {self.score}", fg='red', bold=True)

        if self._tags:
            click.echo(f"Tags: {', '.join(self._tags)}")

        if self.__imported_modules:
            click.echo("Imported modules:")
            click.echo(utils.pprint_imports(utils.imports_to_tree(self.__imported_modules)))
        else:
            click.secho("No imported modules detected", fg='red')

        if self.hits and verbose:
            click.echo("- Rules hits:")
            for x in self.filtered:
                click.echo(f" * {x._asdict()}")

    @property
    def json(self):
        data = copy.deepcopy(self.data)
        data['hits'] = []

        for x in self.filtered:
            data['hits'].append(x._asdict())

        data['imported_modules'] = list(self.__imported_modules)
        data['tags'] = list(self._tags)

        if self.metadata:
            data['metadata'] = self.metadata

        return data

    @property
    def data(self):
        data = {
            'name': self.name,
            'score': self.score,
            'hits': list(self.hits),
        }
        return data

    def _process_yara(self, yara_hit):
        stats = self._yara_hits[yara_hit.rule]

        if yara_hit.meta.get('max_hits'):
            max_hits = yara_hit.meta['max_hits']
        else:
            max_hits = 10

        if yara_hit.meta.get('max_score'):
            max_score = yara_hit.meta['max_score']
        else:
            max_score = yara_hit.score*max_hits

        score = stats['score'] + yara_hit.score
        stats['score'] = max_score if score > max_score else score

    def _process_call(self, call_hit:rules.FunctionCall):
        key = call_hit.function
        max_hits = 10
        max_score = call_hit.score * max_hits
        stats = self.__call_hits[key]
        score = stats['score'] + call_hit.score
        stats['score'] = score if score < max_score else max_score
        stats['hits'] += 1


class SQLiteDump:
    def __create_tables(self):
        INPUT_SCHEMA = """
        CREATE TABLE IF NOT EXISTS input (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input TEXT UNIQUE NOT NULL,
            metadata JSON,
            parent INTEGER,
            FOREIGN KEY (parent) REFERENCES input(id)
            ON DELETE CASCADE ON UPDATE NO ACTION
        )
        """

        HIT_SCHEMA = """
        CREATE TABLE IF NOT EXISTS hit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature VARCHAR(255) PRIMARY KEY,
            score INTEGER,
            type VARCHAR(64),
            data JSON,
            input INTEGER,
            FOREIGN KEY (input) REFERENCES input(id)
        )
        """
