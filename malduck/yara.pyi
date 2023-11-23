import enum
from collections import namedtuple
from collections.abc import Callable, Iterable, KeysView
from typing import Any, Generic, TypeVar, overload

from typing_extensions import Literal, Protocol, TypeAlias

T = TypeVar("T")

YaraRulesString: TypeAlias = tuple[int, str, bytes]
OffsetMapper: TypeAlias = Callable[[int | None, int | None], int | None]

class YaraRulesMatch(Protocol):
    meta: dict[str, str]
    namespace: str
    rule: str
    strings: list[YaraRulesString]
    tags: list[str]

class _Mapper(Generic[T]):
    elements: dict[str, T]
    default: T | None
    def __init__(self, elements: dict[str, T], default: T | None = None) -> None: ...
    def keys(self) -> KeysView[str]: ...
    def get(self, item) -> T | None: ...
    def __bool__(self) -> bool: ...
    def __nonzero__(self) -> bool: ...
    def __contains__(self, item: str) -> bool: ...
    def __getitem__(self, item: str) -> T: ...
    def __getattr__(self, item: str) -> T: ...

class Yara:
    rules: Any
    def __init__(
        self,
        rule_paths: dict[str, str] | None = None,
        name: str = "r",
        strings: (str | YaraString | dict[str, str | YaraString] | None) = None,
        condition: str = "any of them",
    ) -> None: ...
    @staticmethod
    def from_dir(
        path: str, recursive: bool = True, followlinks: bool = True
    ) -> Yara: ...
    # match(...)
    # match(offset_mapper, ...)
    # match(offset_mapper, extended=False, ...)
    @overload
    def match(
        self,
        offset_mapper: OffsetMapper | None = None,
        extended: Literal[False] = False,
        **kwargs,
    ) -> YaraRulesetOffsets: ...
    # match(offset_mapper, extended=True, ...)
    @overload
    def match(
        self, offset_mapper: OffsetMapper | None, extended: Literal[True], **kwargs
    ) -> YaraRulesetMatch: ...
    # match(extended=True, ...)
    @overload
    def match(self, *, extended: Literal[True], **kwargs) -> YaraRulesetMatch: ...

class YaraStringType(enum.IntEnum):
    TEXT = 0
    HEX = 1
    REGEX = 2

class YaraString:
    TEXT = YaraStringType.TEXT
    HEX = YaraStringType.HEX
    REGEX = YaraStringType.REGEX

    value: str
    type: YaraStringType
    modifiers: list[str]
    def __init__(
        self, value: str, type: YaraStringType = YaraStringType.TEXT, **modifiers: bool
    ) -> None: ...
    def __str__(self) -> str: ...

class YaraRulesetMatch(_Mapper["YaraRuleMatch"]):
    _matches: list[YaraRulesMatch]
    def __init__(
        self,
        matches: list[YaraRulesMatch],
        offset_mapper: OffsetMapper | None = None,
    ) -> None:
        super().__init__(elements={})
    def _map_matches(
        self, matches: list[YaraRulesMatch], offset_mapper: OffsetMapper | None
    ) -> dict[str, YaraRuleMatch]: ...
    def _map_strings(
        self, strings: Iterable[YaraRulesString], offset_mapper: OffsetMapper | None
    ) -> dict[str, list[YaraStringMatch]]: ...
    def _parse_string_identifier(self, identifier: str) -> tuple[str, str]: ...
    def remap(self, offset_mapper: OffsetMapper | None = None) -> YaraRulesetMatch: ...

class YaraRulesetOffsets(_Mapper["YaraRuleOffsets"]):
    _matches: YaraRulesetMatch
    def __init__(self, matches: YaraRulesetMatch) -> None:
        super().__init__(elements={})
    def remap(
        self, offset_mapper: OffsetMapper | None = None
    ) -> YaraRulesetOffsets: ...

YaraStringMatch = namedtuple("YaraStringMatch", ["identifier", "offset", "content"])

class YaraRuleMatch(_Mapper[list[YaraStringMatch]]):
    rule: str
    name: str
    meta: dict[str, str]
    namespace: str
    tags: list[str]
    def __init__(
        self,
        rule: str,
        strings: dict[str, list[YaraStringMatch]],
        meta: dict[str, str],
        namespace: str,
        tags: list[str],
    ) -> None:
        super().__init__({})
    def get_offsets(self, string) -> list[int]: ...

class YaraRuleOffsets(_Mapper[list[int]]):
    rule: str
    name: str
    def __init__(self, rule_match: YaraRuleMatch) -> None:
        super().__init__({})

# Legacy aliases, don't use them in new code
YaraMatches = YaraRulesetOffsets
YaraMatch = YaraRuleOffsets
