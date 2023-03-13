"""
Abstract interface for string-based rule matching

Based on yara-python objects for compatibility
but can be used for other purposes if needed
"""

import abc
from typing import Dict, List, Optional, Callable
import dataclasses

@dataclasses.dataclass
class RuleStringMatch:
    identifier: str
    offset: int
    content: bytes

    def __len__(self) -> int:
        return len(self.content)

RuleStringMapper = Callable[[RuleStringMatch], Optional[RuleStringMatch]]

@dataclasses.dataclass
class RuleMatch:
    rule: str
    strings: Dict[str, List[RuleStringMatch]]
    namespace: Optional[str] = None
    meta: Optional[Dict[str, str]] = None
    tags: List[str] = dataclasses.field(default_factory=list)

    @property
    def name(self) -> str:
        return self.rule

    @property
    def elements(self) -> Dict[str, List[RuleStringMatch]]:
        return self.strings

    def remap(self, mapper: RuleStringMapper) -> Optional["RuleMatch"]:
        mapped_strings = {}
        for identifier, string_matches in self.strings.items():
            mapped_string_matches = sorted(
                filter(lambda s: s is not None, [mapper(s) for s in string_matches]),
                key=lambda s: s.offset
            )
            if mapped_string_matches:
                mapped_strings[identifier] = mapped_string_matches

        if mapped_strings:
            return RuleMatch(
                rule=self.rule,
                strings=mapped_strings,
                namespace=self.namespace,
                meta=self.meta,
                tags=self.tags
            )
        else:
            return None


class RuleMatches:
    def __init__(self, matches: List[RuleMatch]) -> None:
        self.matches = matches

    def remap(self, mapper: RuleStringMapper) -> "RuleMatches":
        mapped_matches = []
        for match in self.matches:
            mapped_match = match.remap(mapper)
            if mapped_match:
                mapped_matches.append(mapped_match)
        return RuleMatches(mapped_matches)

class RuleMatcher(abc.ABC):
    @abc.abstractmethod
    def match(self, filepath=None, data=None) -> RuleMatches:
        raise NotImplementedError
