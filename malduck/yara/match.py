from .rules import Yara
from ..match import RuleMatcher, RuleStringMatch
from ..procmem import ProcessMemory
from typing import List


class YaraMatcher(RuleMatcher):
    def __init__(self, rules: Yara):
        self.rules = rules

    def match(self, procmem: ProcessMemory) -> List[RuleStringMatch]:
        yara_matches = self.rules.match(data=procmem.readp(0))
        return [
            RuleStringMatch(
                rule=match.rule,
                identifier=match.identifier,
                offset=match.offset,
                content=match.content,
                namespace=match.namespace,
                meta=match.meta,
                tags=match.tags
            )
            for match in yara_matches
        ]
