from typing import List, Set, Union

from .base import PostAnalysisHook
from .detections import Detection
from .. import config


class BehavioralAnalysis(PostAnalysisHook):
    def post_analysis(self, detections: List[Detection], metadata: dict) -> List[Detection]:
        all_tags = set()

        analysis_results = {}

        for d in detections:
            all_tags |= d.tags

        # extract sub tags from all collected tags, for example:
        # "a:b:c" -> "a", "a:b"
        sub_tags = set()
        for tag in all_tags:
            sub_tags |= {tag[:i] for i, x in enumerate(tag) if x == ":"}

        all_tags |= sub_tags

        for rule in config.CFG["behavioral_analysis"]:
            rule_tags = rule["tags"]
            if type(rule_tags) == list:
                rule_tags = {"allOf": rule_tags}

            if self.match(rule_tags, all_tags):
                analysis_results[self.get_rule_id(rule)] = {
                    "id": self.get_rule_id(rule),
                    "name": rule["name"],
                    "description": rule.get("description", "n/a")
                }

        metadata["behavioral_analysis"] = analysis_results
        return detections

    @classmethod
    def match(cls, rule: Union[str, dict], tags: Set[str]):  # TODO: extend jsonschema to cover correct setup of this config
        if type(rule) == str:
            return rule in tags
        elif type(rule) == dict and "allOf" in rule:
            return all(cls.match(subrule, tags) for subrule in rule["allOf"])
        elif type(rule) == dict and "anyOf" in rule:
            return any(cls.match(subrule, tags) for subrule in rule["anyOf"])
        elif type(rule) == dict and "not" in rule:
            return not cls.match(rule["not"][0], tags)
        else:
            raise ValueError(f"Unknown rule type `{repr(rule)}`")

    @staticmethod
    def get_rule_id(rule: dict):
        if (rid:=rule.get("id")):
            return rid

        return rule["name"].lower().replace(" ", "_")
