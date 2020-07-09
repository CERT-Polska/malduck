from collections import namedtuple
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    List,
    Union,
    Tuple,
    TypeVar,
    Dict,
    KeysView,
    Optional,
    overload,
)
from typing_extensions import Protocol, Literal

import enum

T = TypeVar("T")
OffsetMapper = Callable[[Optional[int], Optional[int]], Optional[int]]

YaraRulesString = Tuple[int, str, bytes]

class YaraRulesMatch(Protocol):
    meta: Dict[str, str]
    namespace: str
    rule: str
    strings: List[YaraRulesString]
    tags: List[str]

class _Mapper(Generic[T]):
    elements: Dict[str, T]
    default: Optional[T]
    def __init__(self, elements: Dict[str, T], default: Optional[T] = None) -> None: ...
    def keys(self) -> KeysView[str]: ...
    def get(self, item) -> Optional[T]: ...
    def __bool__(self) -> bool: ...
    def __nonzero__(self) -> bool: ...
    def __contains__(self, item: str) -> bool: ...
    def __getitem__(self, item: str) -> T: ...
    def __getattr__(self, item: str) -> T: ...

class Yara:
    rules: Any
    def __init__(
        self,
        rule_paths: Optional[Dict[str, str]] = None,
        name: str = "r",
        strings: Union[
            str, "YaraString", Dict[str, Union[str, "YaraString"]], None
        ] = None,
        condition: str = "any of them",
    ) -> None: ...
    @staticmethod
    def from_dir(
        path: str, recursive: bool = True, followlinks: bool = True
    ) -> "Yara": ...
    # match(...)
    # match(offset_mapper, ...)
    # match(offset_mapper, extended=False, ...)
    @overload
    def match(
        self,
        offset_mapper: Optional[OffsetMapper] = None,
        extended: Literal[False] = False,
        **kwargs,
    ) -> "YaraRulesetOffsets": ...
    # match(offset_mapper, extended=True, ...)
    @overload
    def match(
        self, offset_mapper: Optional[OffsetMapper], extended: Literal[True], **kwargs
    ) -> "YaraRulesetMatch": ...
    # match(extended=True, ...)
    @overload
    def match(self, *, extended: Literal[True], **kwargs) -> "YaraRulesetMatch": ...

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
    modifiers: List[str]
    def __init__(
        self, value: str, type: YaraStringType = YaraStringType.TEXT, **modifiers: bool
    ) -> None: ...
    def __str__(self) -> str: ...

class YaraRulesetMatch(_Mapper["YaraRuleMatch"]):
    _matches: List[YaraRulesMatch]
    def __init__(
        self,
        matches: List[YaraRulesMatch],
        offset_mapper: Optional[OffsetMapper] = None,
    ) -> None:
        super().__init__(elements={})
    def _map_matches(
        self, matches: List[YaraRulesMatch], offset_mapper: Optional[OffsetMapper]
    ) -> Dict[str, "YaraRuleMatch"]: ...
    def _map_strings(
        self, strings: Iterable[YaraRulesString], offset_mapper: Optional[OffsetMapper]
    ) -> Dict[str, List["YaraStringMatch"]]: ...
    def _parse_string_identifier(self, identifier: str) -> Tuple[str, str]: ...
    def remap(
        self, offset_mapper: Optional[OffsetMapper] = None
    ) -> "YaraRulesetMatch": ...

class YaraRulesetOffsets(_Mapper["YaraRuleOffsets"]):
    _matches: YaraRulesetMatch
    def __init__(self, matches: YaraRulesetMatch) -> None:
        super().__init__(elements={})
    def remap(
        self, offset_mapper: Optional[OffsetMapper] = None
    ) -> "YaraRulesetOffsets": ...

YaraStringMatch = namedtuple("YaraStringMatch", ["identifier", "offset", "content"])

class YaraRuleMatch(_Mapper[List[YaraStringMatch]]):
    rule: str
    name: str
    meta: Dict[str, str]
    namespace: str
    tags: List[str]
    def __init__(
        self,
        rule: str,
        strings: Dict[str, List[YaraStringMatch]],
        meta: Dict[str, str],
        namespace: str,
        tags: List[str],
    ) -> None:
        super().__init__({})
    def get_offsets(self, string) -> List[int]: ...

class YaraRuleOffsets(_Mapper[List[int]]):
    rule: str
    name: str
    def __init__(self, rule_match: YaraRuleMatch) -> None:
        super().__init__({})

# Legacy aliases, don't use them in new code
YaraMatches = YaraRulesetOffsets
YaraMatch = YaraRuleOffsets
