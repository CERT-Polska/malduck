"""
Abstract interface for string-based rule matching

Based on yara-python objects for compatibility
but can be used for other purposes if needed
"""

import abc
import dataclasses
import typing
from collections import defaultdict
from typing import Callable, List, Mapping, Optional, Sequence, TypeVar

if typing.TYPE_CHECKING:
    from .procmem import ProcessMemory

T = TypeVar("T")


def aggregate(
    collection: Sequence[T], keyfunc: Callable[[T], str]
) -> Mapping[str, Sequence[T]]:
    mapping = defaultdict(list)
    for el in collection:
        mapping[keyfunc(el)].append(el)
    return dict(mapping)


@dataclasses.dataclass(frozen=True)
class RuleStringMatch:
    rule: str
    identifier: str
    offset: int
    content: bytes
    namespace: Optional[str] = None
    meta: Optional[Mapping[str, str]] = None
    tags: Sequence[str] = dataclasses.field(default_factory=list)

    def __len__(self) -> int:
        return len(self.content)

    def replace_offset(self, offset: int) -> "RuleStringMatch":
        return dataclasses.replace(self, offset=offset)


RuleStringMapper = Callable[[RuleStringMatch], Optional[RuleStringMatch]]


@dataclasses.dataclass(frozen=True)
class RuleMatch:
    rule: str
    strings: Mapping[str, Sequence[RuleStringMatch]]
    namespace: Optional[str] = None
    meta: Optional[Mapping[str, str]] = None
    tags: Sequence[str] = dataclasses.field(default_factory=list)

    @property
    def name(self) -> str:
        return self.rule

    @property
    def elements(self) -> Mapping[str, Sequence[RuleStringMatch]]:
        return self.strings

    def __contains__(self, item):
        return item in self.strings

    def __getitem__(self, item):
        return self.strings[item]


class RuleMatches:
    def __init__(self, string_matches: Sequence[RuleStringMatch]) -> None:
        self._string_matches = string_matches
        self._elements = self._map_elements(string_matches)

    def _map_elements(self, matches: Sequence[RuleStringMatch]):
        rules = aggregate(matches, lambda m: m.rule)
        return {
            rule: RuleMatch(
                rule=rule,
                strings=aggregate(strings, lambda s: s.identifier),
                namespace=strings[0].namespace,
                meta=strings[0].meta,
                tags=strings[0].tags,
            )
            for rule, strings in rules.items()
        }

    @property
    def string_matches(self):
        return self._string_matches

    @property
    def elements(self):
        return self._elements

    def __contains__(self, item):
        return item in self._elements

    def __getitem__(self, item):
        return self._elements[item]

    def remap(self, mapper: RuleStringMapper) -> "RuleMatches":
        mapped_matches = [mapper(match) for match in self._string_matches]
        matches = [match for match in mapped_matches if match is not None]
        return RuleMatches(matches)

    def p2v(
        self,
        procmem: "ProcessMemory",
        addr: Optional[int] = None,
        length: Optional[int] = None,
    ) -> "RuleMatches":
        _addr = procmem.regions[0].addr if addr is None else addr
        _length = procmem.regions[-1].end - _addr if length is None else length

        def mapper(match: RuleStringMatch) -> Optional[RuleStringMatch]:
            ptr = procmem.p2v(match.offset, len(match))
            if ptr is not None and _addr <= ptr < _addr + _length:
                return match.replace_offset(ptr)
            else:
                return None

        return self.remap(mapper)


class RuleMatcher(abc.ABC):
    @abc.abstractmethod
    def match(
        self, procmem: "ProcessMemory", offset: int = 0, length: Optional[int] = None
    ) -> List[RuleStringMatch]:
        raise NotImplementedError
