import dataclasses
import logging
import re
from typing import Callable, List, Mapping, Optional, Sequence, Tuple, TypeVar

from .mapping import UserMapping, aggregate

log = logging.getLogger(__name__)

OffsetMapper = Callable[[Optional[int], Optional[int]], Optional[int]]

YaraRulesString = Tuple[int, str, bytes]


@dataclasses.dataclass(frozen=True)
class StringMatch:
    rule: str
    identifier: str
    offset: int
    content: bytes
    namespace: Optional[str] = None
    meta: Optional[Mapping[str, str]] = None
    tags: Sequence[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        # Remove $ from the beginning
        # We need that hack for frozen instance
        object.__setattr__(self, "identifier", self.identifier.lstrip("$"))

    def __len__(self) -> int:
        return len(self.content)

    def replace_offset(self, offset: int) -> "StringMatch":
        return dataclasses.replace(self, offset=offset)

    @property
    def groups(self) -> Sequence[str]:
        match = re.match(r"^\$?((\w+?)_?\d*)$", self.identifier)
        if match:
            if match.group(1) != match.group(2):
                # $str1 => str1, str
                return [match.group(1), match.group(2)]
            else:
                # $str => str
                return [match.group(1)]
        else:
            # failsafe for non-standard names
            return [self.identifier.lstrip("$")]


# This should be typing.Self but it's available only for Python >=3.11
Self = TypeVar("Self", bound="RulesetMatch")


class RulesetMatch(UserMapping):
    def __init__(self, string_matches: Sequence[StringMatch]) -> None:
        self._string_matches = string_matches
        rules = aggregate(string_matches, lambda m: [m.rule])
        super().__init__(
            {
                rule: self._make_rule_match(rule, strings)
                for rule, strings in rules.items()
            }
        )

    @staticmethod
    def _make_rule_match(rule: str, strings: Sequence[StringMatch]):
        return RuleMatch(
            rule=rule,
            strings=aggregate(strings, lambda s: s.groups),
            namespace=strings[0].namespace,
            meta=strings[0].meta,
            tags=strings[0].tags,
        )

    def remap(self: Self, mapper: OffsetMapper) -> Self:
        mapped_offsets = [
            (match, mapper(match.offset, len(match))) for match in self._string_matches
        ]
        matches = [
            match.replace_offset(mapped_offset)
            for match, mapped_offset in mapped_offsets
            if mapped_offset is not None
        ]
        return self.__class__(matches)

    def get_ruleset_offsets(self) -> "RulesetOffsets":
        return RulesetOffsets(self._string_matches)


class RulesetOffsets(RulesetMatch):
    @staticmethod
    def _make_rule_match(rule: str, strings: Sequence[StringMatch]) -> "RuleOffsets":
        return RuleOffsets(rule=rule, strings=aggregate(strings, lambda s: s.groups))


class RuleMatch(UserMapping):
    def __init__(
        self,
        rule: str,
        strings: Mapping[str, Sequence[StringMatch]],
        meta: Optional[Mapping[str, str]],
        namespace: Optional[str],
        tags: Optional[Sequence[str]],
    ) -> None:
        self.rule = self.name = rule
        self.meta = meta
        self.namespace = namespace
        self.tags = tags
        super().__init__(
            {k: sorted(v, key=lambda s: s.offset) for k, v in strings.items()},
            default=[],
        )

    def get_offsets(self, string: str) -> List[int]:
        return [match.offset for match in self.elements.get(string, [])]


class RuleOffsets(UserMapping):
    def __init__(self, rule: str, strings: Mapping[str, Sequence[StringMatch]]) -> None:
        self.rule = self.name = rule
        super().__init__(
            {k: sorted([s.offset for s in v]) for k, v in strings.items()}, default=[]
        )
