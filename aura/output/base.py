from abc import ABCMeta, abstractmethod

import pkg_resources

from .. import exceptions

OUTPUT_HANDLERS = None
DIFF_OUTPUT_HANDLERS = None


class AuraOutput(metaclass=ABCMeta):
    def __init__(self, metadata=None):
        if metadata is not None:
            self.metadata = metadata
        else:
            self.metadata = {}
        self.verbosity = self.metadata.get("verbosity", 1)

        self.tag_filters = []
        self.compile_filter_tags()

    def compile_filter_tags(self) -> None:
        """
        compile input filter tags into an easy to use list of lambda's so the output hits can be filtered using map

        :return: None
        """
        # Ignore if there are no filter tags defined
        if self.metadata.get("filter_tags") is None:
            return

        for t in self.metadata["filter_tags"]:
            # normalize tags to lowercase with `-` replaced to `_`
            t = t.strip().lower().replace('-', '_')

            if not t:
                continue

            if t.startswith("!"):  # It a tag is prefixed with `!` then it means to exclude findings with such tag
                self.tag_filters.append(lambda x: t[1:] not in x)
            else:
                self.tag_filters.append(lambda x: t in x)

    @abstractmethod
    def output(self, hits):
        ...

    def filtered(self, hits):
        """
        Helper function get a list of filtered results regardless of the output type
        This list of results should then be serialized by a specific output format

        :param hits: input hits/results that will be filtered
        :return: a list of filtered results
        """
        hits = sorted(hits)

        processed = []

        for x in hits:
            # normalize tags
            tags = [t.lower().replace('-', '_') for t in x.tags]

            # if verbosity is below 2, informational results are filtered
            # norm is that informational results should have a score of 0
            if self.verbosity < 2 and x.informational and x.score == 0:
                continue
            elif not all(f(tags) for f in self.tag_filters):
                continue
            else:
                processed.append(x)

        total_score = sum(x.score for x in processed)

        if self.metadata.get("min_score") and self.metadata["min_score"] > total_score:
            raise exceptions.MinimumScoreNotReached(f"Score of {total_score} did not meet the minimum {self.metadata['min_score']}")

        return processed

    @classmethod
    def get_output_formats(cls):
        global OUTPUT_HANDLERS

        if not OUTPUT_HANDLERS:
            OUTPUT_HANDLERS = {}
            for x in pkg_resources.iter_entry_points("aura.output_handlers"):
                handler = x.load()
                OUTPUT_HANDLERS[x.name] = handler

        return OUTPUT_HANDLERS


class DiffOutputBase(metaclass=ABCMeta):
    @abstractmethod
    def output_diff(self, diffs):
        ...

    @classmethod
    def get_output_formats(cls):
        global DIFF_OUTPUT_HANDLERS

        if not DIFF_OUTPUT_HANDLERS:
            DIFF_OUTPUT_HANDLERS = {}
            for x in pkg_resources.iter_entry_points("aura.diff_output_handlers"):
                handler = x.load()
                DIFF_OUTPUT_HANDLERS[x.name] = handler

        return DIFF_OUTPUT_HANDLERS
