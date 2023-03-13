from typing import Dict, List, Optional
import dataclasses

@dataclasses.dataclass
class RuleMatch:
    rule: str
    matches: Dict[str, List[int]]
    namespace: Optional[str] = None
    meta: Optional[Dict[str, str]] = None
    tags: List[str] = dataclasses.field(default_factory=list)

    @property
    def name(self):
        return self.rule

    @property
    def elements(self):
        # emit string matches
        return self.matches

    def remap(self, mapper) -> Optional["RuleMatch"]:
        mapped_matches = {}
        for identifier, offsets in self.matches.items():
            mapped_offsets = sorted(
                filter(lambda off: off is not None, [mapper(off) for off in offsets])
            )
            if mapped_offsets:
                mapped_matches[identifier] = mapped_offsets

        if mapped_matches:
            return RuleMatch(
                rule=self.rule,
                matches=mapped_matches,
                namespace=self.namespace,
                meta=self.meta,
                tags=self.tags
            )
        else:
            return None


class RuleMatches:
    def __init__(self, matches):
        self.matches = matches

    def remap(self, mapper) -> "RuleMatches":
        mapped_matches = []
        for match in self.matches:
            mapped_match = match.remap(mapper)
            if mapped_match:
                mapped_matches.append(mapped_match)
        return RuleMatches(mapped_matches)

class RuleMatcher:
    def match(self, filepath=None, data=None) -> RuleMatches:
        raise NotImplementedError
