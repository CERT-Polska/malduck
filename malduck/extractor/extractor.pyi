import logging
from collections.abc import Callable, Iterator
from typing import Any, Generic, TypeVar, overload

from typing_extensions import Protocol

from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..yara import YaraRuleMatch, YaraStringMatch
from .extract_manager import ExtractionContext

Config = dict[str, Any]

T = TypeVar("T", bound="Extractor", contravariant=True)
U = TypeVar("U", bound=ProcessMemory, contravariant=True)
V = TypeVar("V", bound="ExtractorMethod")

class _StringOffsetCallback(Protocol[T, U]):
    def __call__(cls, self: T, p: U, addr: int) -> Config | bool | None: ...

class _StringCallback(Protocol[T, U]):
    def __call__(
        cls, self: T, p: U, addr: int, match: YaraStringMatch
    ) -> Config | bool | None: ...

class _RuleCallback(Protocol[T, U]):
    def __call__(cls, self: T, p: U, match: YaraRuleMatch) -> Config | bool | None: ...

class _FinalCallback(Protocol[T, U]):
    def __call__(cls, self: T, p: U) -> Config | bool | None: ...

class ExtractorMethod(Generic[T, U]):
    """
    Represents registered extractor method
    """

    method: (
        _StringOffsetCallback[T, U]
        | _StringCallback[T, U]
        | _RuleCallback[T, U]
        | _FinalCallback[T, U]
    )
    procmem_type: type[ProcessMemory]
    weak: bool
    def __init__(
        self,
        method: (
            _StringOffsetCallback[T, U]
            | _StringCallback[T, U]
            | _RuleCallback[T, U]
            | _FinalCallback[T, U]
        ),
    ) -> None: ...
    def __call__(self, extractor: T, procmem: U, *args, **kwargs) -> None: ...

class StringOffsetExtractorMethod(ExtractorMethod[T, U]):
    string_name: str
    def __init__(
        self, method: _StringOffsetCallback[T, U], string_name: str | None = None
    ) -> None:
        super().__init__(method)

class StringExtractorMethod(ExtractorMethod[T, U]):
    string_names: list[str]
    def __init__(
        self, method: _StringCallback[T, U], string_names: list[str] | None = None
    ) -> None:
        super().__init__(method)

class RuleExtractorMethod(ExtractorMethod[T, U]):
    rule_name: str
    def __init__(
        self, method: _RuleCallback[T, U], rule_name: str | None = None
    ) -> None:
        super().__init__(method)

class FinalExtractorMethod(ExtractorMethod[T, U]):
    def __init__(self, method: _FinalCallback[T, U]) -> None:
        super().__init__(method)

class Extractor:
    yara_rules: tuple[str, ...]
    family: str | None
    overrides: list[str]
    parent: ExtractionContext
    def __init__(self, parent: ExtractionContext) -> None: ...
    def push_procmem(self, procmem: ProcessMemory, **info): ...
    def push_config(self, config): ...
    @property
    def matched(self) -> bool: ...
    @property
    def collected_config(self) -> Config: ...
    @property
    def globals(self) -> dict[str, Any]: ...
    @property
    def log(self) -> logging.Logger: ...
    def _get_methods(self, method_type: type[V]) -> Iterator[tuple[str, V]]: ...
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
