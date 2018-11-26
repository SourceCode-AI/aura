import copy
from collections import defaultdict

import click
from blinker import signal

from .analyzers import rules


class ScanResults():
    def __init__(self, name):
        self.name = name
        self.hits = []
        self.signal = signal('scan')
        self.signal.connect(self.on_signal)

        self._yara_hits = defaultdict(lambda : {'score': 0, 'hits': 0})
        self._import_categories = set()
        self._import_hits = defaultdict(lambda : {'score': 0, 'hits': 0})
        self.__call_hits = defaultdict(lambda : {'score': 0, 'hits': 0})

    def on_signal(self, sender):
        self.hits.append(sender)

    @property
    def score(self):
        score = 0
        for x in self.hits:
            if isinstance(x, rules.yara_match):
                self._process_yara(x)
            elif isinstance(x, rules.module_import):
                self._process_import(x)
            elif isinstance(x, rules.function_call):
                self._process_call(x)
            else:
                score += getattr(x, 'score', 0)

        score += sum(x['score'] for x in self._yara_hits.values())
        score += sum(x['score'] for x in self._import_hits.values())
        score += sum(x['score'] for x in self.__call_hits.values())

        return score

    def pprint(self, verbose=0):

        click.secho(f"\n---[ Scan results for '{self.name}' ]---", fg='green')
        click.secho(f"Scan score: {self.score}", fg='red', bold=True)

        if self._import_categories:
            click.echo("Code categories: {}".format(', '.join(self._import_categories)))

        click.echo("Imported modules: {}".format(', '.join(self._import_hits.keys())))

        if self.hits and verbose:
            click.echo("- Rules hits:")
            for x in self.hits:
                click.echo(f" * {x}")

    @property
    def json(self):
        data = copy.deepcopy(self.data)
        data['hits'] = [x._asdict() for x in data['hits']]
        data['imported_modules'] = list(self._import_hits.keys())
        data['categories'] = list(self._import_categories)
        return data

    @property
    def data(self):
        data = {
            'name': self.name,
            'score': self.score,
            'hits': self.hits
        }
        return data

    def _process_yara(self, yara_hit:rules.yara_match):
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

    def _process_import(self, import_hit:rules.module_import):
        if import_hit.category:
            self._import_categories.add(import_hit.category)

        stats = self._import_hits[import_hit.name]
        stats['score'] = import_hit.score
        stats['hits'] += 1

    def _process_call(self, call_hit:rules.function_call):
        key = call_hit.function
        max_hits = 10
        max_score = call_hit.score * max_hits
        stats = self.__call_hits[key]
        score = stats['score'] + call_hit.score
        stats['score'] = score if score < max_score else max_score
        stats['hits'] += 1

