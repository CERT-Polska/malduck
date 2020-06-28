import logging

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Iterator,
    Optional,
    Union,
    Tuple,
    Type,
    TypeVar,
    overload,
)
from typing_extensions import Protocol

from ..procmem import ProcessMemory, ProcessMemoryPE, ProcessMemoryELF
from ..yara import YaraRuleMatch, YaraStringMatch

from .extract_manager import ProcmemExtractManager

Config = Dict[str, Any]

T = TypeVar("T", bound="Extractor", contravariant=True)
U = TypeVar("U", bound=ProcessMemory, contravariant=True)
V = TypeVar("V", bound="ExtractorMethod")

class _StringOffsetCallback(Protocol[T, U]):
    def __call__(cls, self: T, p: U, addr: int) -> Union[Config, bool, None]: ...

class _StringCallback(Protocol[T, U]):
    def __call__(
        cls, self: T, p: U, addr: int, match: YaraStringMatch
    ) -> Union[Config, bool, None]: ...

class _RuleCallback(Protocol[T, U]):
    def __call__(
        cls, self: T, p: U, match: YaraRuleMatch
    ) -> Union[Config, bool, None]: ...

class _FinalCallback(Protocol[T, U]):
    def __call__(cls, self: T, p: U) -> Union[Config, bool, None]: ...

class ExtractorMethod(Generic[T, U]):
    """
    Represents registered extractor method
    """

    method: Union[
        _StringOffsetCallback[T, U],
        _StringCallback[T, U],
        _RuleCallback[T, U],
        _FinalCallback[T, U],
    ]
    procmem_type: Type["ProcessMemory"]
    weak: bool
    def __init__(
        self,
        method: Union[
            _StringOffsetCallback[T, U],
            _StringCallback[T, U],
            _RuleCallback[T, U],
            _FinalCallback[T, U],
        ],
    ) -> None: ...
    def __call__(self, extractor: T, procmem: U, *args, **kwargs) -> None: ...

class StringOffsetExtractorMethod(ExtractorMethod[T, U]):
    string_name: str
    def __init__(
        self, method: _StringOffsetCallback[T, U], string_name: Optional[str] = None
    ) -> None:
        super().__init__(method)

class StringExtractorMethod(ExtractorMethod[T, U]):
    string_names: List[str]
    def __init__(
        self, method: _StringCallback[T, U], string_names: Optional[List[str]] = None
    ) -> None:
        super().__init__(method)

class RuleExtractorMethod(ExtractorMethod[T, U]):
    rule_name: str
    def __init__(
        self, method: _RuleCallback[T, U], rule_name: Optional[str] = None
    ) -> None:
        super().__init__(method)

class FinalExtractorMethod(ExtractorMethod[T, U]):
    def __init__(self, method: _FinalCallback[T, U]) -> None:
        super().__init__(method)

class Extractor:
    yara_rules: Tuple[str, ...]
    family: Optional[str]
    overrides: List[str]
    parent: ProcmemExtractManager
    def __init__(self, parent: ProcmemExtractManager) -> None: ...
    def push_procmem(self, procmem: ProcessMemory, **info): ...
    def push_config(self, config): ...
    @property
    def matched(self) -> bool: ...
    @property
    def collected_config(self) -> Config: ...
    @property
    def globals(self) -> Dict[str, Any]: ...
    @property
    def log(self) -> logging.Logger: ...
    def _get_methods(self, method_type: Type[V]) -> Iterator[Tuple[str, V]]: ...
    def on_error(self, exc: Exception, method_name: str) -> None: ...
    def handle_match(self, p: ProcessMemory, match: YaraRuleMatch) -> None: ...
    # Extractor method decorators
    @overload
    @staticmethod
    def extractor(
        string_or_method: _StringOffsetCallback[T, U]
    ) -> StringOffsetExtractorMethod[T, U]: ...
    @overload
    @staticmethod
    def extractor(
        string_or_method: str,
    ) -> Callable[[_StringOffsetCallback[T, U]], StringOffsetExtractorMethod[T, U]]: ...
    @overload
    @staticmethod
    def string(
        *strings_or_method: _StringCallback[T, U]
    ) -> StringExtractorMethod[T, U]: ...
    @overload
    @staticmethod
    def string(
        *strings_or_method: str,
    ) -> Callable[[_StringCallback[T, U]], StringExtractorMethod[T, U]]: ...
    @overload
    @staticmethod
    def rule(string_or_method: _RuleCallback[T, U]) -> RuleExtractorMethod[T, U]: ...
    @overload
    @staticmethod
    def rule(
        string_or_method: str,
    ) -> Callable[[_RuleCallback[T, U]], RuleExtractorMethod[T, U]]: ...
    @staticmethod
    def final(method: _FinalCallback[T, U]) -> FinalExtractorMethod[T, U]: ...
    @staticmethod
    def needs_pe(
        method: ExtractorMethod[T, ProcessMemoryPE]
    ) -> ExtractorMethod[T, ProcessMemoryPE]: ...
    @staticmethod
    def needs_elf(
        method: ExtractorMethod[T, ProcessMemoryELF]
    ) -> ExtractorMethod[T, ProcessMemoryELF]: ...
    @staticmethod
    def weak(method: ExtractorMethod[T, U]) -> ExtractorMethod[T, U]: ...
