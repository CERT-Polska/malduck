from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union, overload

import yara

from .match import RulesetMatch, RulesetOffsets
from .rules import YaraRule, YaraString

OffsetMapper = Callable[[Optional[int], Optional[int]], Optional[int]]

YaraRulesString = Tuple[int, str, bytes]

class Yara:
    rules: Any
    rulesets: List[yara.Rules]

    def __init__(
        self,
        rule_paths: Optional[Dict[str, str]] = None,
        rules: Optional[List[Union[str, YaraRule]]] = None,
        compiled_rules: Optional[List[yara.Rules]] = None,
        name: str = "r",
        strings: Optional[
            Union[str, YaraString, Dict[str, Union[str, YaraString]]]
        ] = None,
        condition: str = "any of them",
    ) -> None: ...
    @staticmethod
    def from_dir(
        path: str, recursive: bool = True, followlinks: bool = True
    ) -> "Yara": ...
    def yara_match(self, **kwargs: Any) -> List[yara.Match]: ...
    # match(...)
    # match(offset_mapper, ...)
    # match(offset_mapper, extended=False, ...)
    @overload
    def match(
        self,
        offset_mapper: Optional[OffsetMapper] = None,
        extended: Literal[False] = False,
        **kwargs,
    ) -> "RulesetOffsets": ...
    # match(offset_mapper, extended=True, ...)
    @overload
    def match(
        self, offset_mapper: Optional[OffsetMapper], extended: Literal[True], **kwargs
    ) -> "RulesetMatch": ...
    # match(extended=True, ...)
    @overload
    def match(self, *, extended: Literal[True], **kwargs) -> "RulesetMatch": ...
