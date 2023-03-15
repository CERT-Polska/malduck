from typing import List

from ..match import RuleMatcher, RuleStringMatch
from ..procmem import ProcessMemory
from .rules import Yara


class YaraMatcher(RuleMatcher):
    def __init__(self, rules: Yara):
        self.rules = rules

    def match(
        self, procmem: ProcessMemory, offset=0, length=None
    ) -> List[RuleStringMatch]:
        yara_matches = self.rules.match(data=procmem.readp(offset, length))
        return [
            RuleStringMatch(
                rule=match.rule,
                identifier=match.identifier,
                offset=match.offset + offset,
                content=match.content,
                namespace=match.namespace,
                meta=match.meta,
                tags=match.tags,
            )
            for match in yara_matches
        ]
