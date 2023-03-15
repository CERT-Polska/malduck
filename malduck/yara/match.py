from typing import TYPE_CHECKING, List

from ..match import RuleMatcher, RuleStringMatch
from .rules import Yara

if TYPE_CHECKING:
    from ..procmem import ProcessMemory


class YaraMatcher(RuleMatcher):
    def __init__(self, rules: Yara):
        self.rules = rules

    def match(
        self, procmem: "ProcessMemory", offset=0, length=None
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
