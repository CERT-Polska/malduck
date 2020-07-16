import functools
import inspect
import logging

from ..procmem import ProcessMemory, ProcessMemoryPE, ProcessMemoryELF
from typing import List, cast

log = logging.getLogger(__name__)

__all__ = ["Extractor"]


class ExtractorMethod:
    """
    Represents registered extractor method
    """

    def __init__(self, method):
        self.method = method
        self.procmem_type = ProcessMemory
        self.weak = False
        functools.update_wrapper(self, method)

    def __call__(self, extractor, procmem, *args, **kwargs):
        if not isinstance(procmem, self.procmem_type):
            log.debug(
                "Omitting %s.%s - %s is not %s",
                self.__class__.__name__,
                self.method.__name__,
                procmem.__class__.__name__,
                self.procmem_type.__name__,
            )
            return
        # Get config from extractor method
        config = self.method(extractor, procmem, *args, **kwargs)
        if not config:
            return
        # If method returns True - family matched (for non-weak methods)
        if config is True:
            config = {}
        # If method is "strong" - "family" key will be automatically added
        if not self.weak and extractor.family and "family" not in config:
            config["family"] = extractor.family
        # If config is not empty - push it
        if config and isinstance(config, dict):
            extractor.push_config(config)


class StringOffsetExtractorMethod(ExtractorMethod):
    def __init__(self, method, string_name=None):
        super().__init__(method)
        self.string_name = string_name or method.__name__


class StringExtractorMethod(ExtractorMethod):
    def __init__(self, method, string_names=None):
        super().__init__(method)
        self.string_names = string_names or [method.__name__]


class RuleExtractorMethod(ExtractorMethod):
    def __init__(self, method, rule_name=None):
        super().__init__(method)
        self.rule_name = rule_name or method.__name__


class FinalExtractorMethod(ExtractorMethod):
    def __init__(self, method):
        super().__init__(method)


class Extractor:
    """
    Base class for extractor modules

    Following parameters need to be defined:

    * :py:attr:`family` (see :py:attr:`extractor.Extractor.family`)
    * :py:attr:`yara_rules`
    * :py:attr:`overrides` (optional, see :py:attr:`extractor.Extractor.overrides`)

    Example extractor code for Citadel:

    .. code-block:: Python

        from malduck import Extractor

        class Citadel(Extractor):
            family = "citadel"
            yara_rules = ("citadel",)
            overrides = ("zeus",)

            @Extractor.string("briankerbs")
            def citadel_found(self, p, addr, match):
                log.info('[+] `Coded by Brian Krebs` str @ %X' % addr)
                return True

            @Extractor.string
            def cit_login(self, p, addr, match):
                log.info('[+] Found login_key xor @ %X' % addr)
                hit = p.uint32v(addr + 4)
                print(hex(hit))
                if p.is_addr(hit):
                    return {'login_key': p.asciiz(hit)}

                hit = p.uint32v(addr + 5)
                print(hex(hit))
                if p.is_addr(hit):
                    return {'login_key': p.asciiz(hit)}

    Decorated methods are always called in order:

    - `@Extractor.extractor` methods
    - `@Extractor.string` methods
    - `@Extractor.rule` methods
    - `@Extractor.final` methods

    .. py:decoratormethod:: Extractor.string

        Decorator for string-based extractor methods.
        Method is called each time when string with the same identifier as method name has matched

        Extractor can be called for many number-suffixed strings e.g. `$keyex1` and `$keyex2` will call `keyex` method.

        You can optionally provide the actual string identifier as an argument if you don't want to name your method
        after the string identifier.

        Signature of decorated method:

        .. code-block:: Python

            @Extractor.string
            def string_identifier(self, p: ProcessMemory, addr: int, match: YaraStringMatch) -> Config:
                # p: ProcessMemory object that contains matched file/dump representation
                # addr: Virtual address of matched string
                # Called for each "$string_identifier" hit
                ...

        If you want to use same method for multiple different named strings, you can provide multiple identifiers
        as `@Extractor.string` decorator argument

        .. code-block::Python

            @Extractor.string("xor_call", "mov_call")
            def xxx_call(self, p: ProcessMemory, addr: int, match: YaraStringMatch) -> Config:
                # This will be called for all $xor_call and $mov_call string hits
                # You can determine which string triggered the hit via match.identifier
                if match.identifier == "xor_call":
                    ...

        Extractor methods should return `dict` object with extracted part of configuration, `True` indicating
        a match or `False`/`None` when family has not been matched.

        For strong methods: truthy values are transformed to `dict` with `{"family": self.family}` key.

        .. versionadded:: 4.0.0

            Added `@Extractor.string` as extended version of `@Extractor.extractor`

        :param strings_or_method:
            If method name doesn't match the string identifier, pass yara string identifier as decorator argument.
            Multiple strings are accepted
        :type strings_or_method: *str, optional

    .. py:decoratormethod:: Extractor.extractor

        Simplified variant of `@Extractor.string`.

        Doesn't accept multiple strings and passes only string offset to the extractor method.

        .. code-block:: Python

            from malduck import Extractor

            class Citadel(Extractor):
                family = "citadel"
                yara_rules = ("citadel",)
                overrides = ("zeus",)

                @Extractor.extractor("briankerbs")
                def citadel_found(self, p, addr):
                    # Called for each $briankerbs hit
                    ...

                @Extractor.extractor
                def cit_login(self, p, addr):
                    # Called for each $cit_login1, $cit_login2 hit
                    ...

    .. py:decoratormethod:: Extractor.rule

        Decorator for rule-based extractor methods, called once for rule match after string-based extraction methods.

        Method is called each time when rule with the same identifier as method name has matched.

        You can optionally provide the actual rule identifier as an argument if you don't want to name your method
        after the rule identifier.

        Rule identifier must appear in `yara_rules` tuple.

        Signature of decorated method:

        .. code-block:: Python

            @Extractor.rule
            def rule_identifier(self, p: ProcessMemory, matches: YaraMatch) -> Config:
                # p: ProcessMemory object that contains matched file/dump representation
                # matches: YaraMatch object with offsets of all matched strings related with the rule
                # Called for matched rule named "rule_identifier".
                ...

        .. versionadded:: 4.0.0

            Added `@Extractor.rule` decorator

        .. code-block:: Python

            from malduck import Extractor

            class Evil(Extractor):
                yara_rules = ("evil", "weird")
                family = "evil"

                ...

                @Extractor.rule
                def evil(self, p, matches):
                    # This will be called each time evil match.
                    # `matches` is YaraMatch object that contains information about
                    # all string matches related with this rule.
                    ...

        :param string_or_method:
            If method name doesn't match the rule identifier
            pass yara string identifier as decorator argument
        :type string_or_method: str, optional

    .. py:decoratormethod:: Extractor.final

        Decorator for final extractor methods, called once for each single rule match after other extraction methods.

        Behaves similarly to the @rule-decorated methods but is called for each rule match regardless of
        the rule identifier.

        Signature of decorated method:

        .. code-block:: Python

            @Extractor.rule
            def rule_identifier(self, p: ProcessMemory) -> Config:
                # p: ProcessMemory object that contains matched file/dump representation
                # Called for each matched rule in self.yara_rules
                ...

        .. code-block:: Python

            from malduck import Extractor

            class Evil(Extractor):
                yara_rules = ("evil", "weird")
                family = "evil"

                ...

                @Extractor.needs_pe
                @Extractor.final
                def get_config(self, p):
                    # This will be called each time evil or weird match
                    cfg = {"urls": self.get_cncs_from_rsrc(p)}
                    if "role" not in self.collected_config:
                        cfg["role"] = "loader"
                    return cfg

    .. py:decoratormethod:: Extractor.weak

        Use this decorator for extractors when successful extraction is not sufficient to mark family as matched.

        All "weak configs" will be flushed when "strong config" appears.

        .. versionchanged:: 4.0.0

            Method must be decorated first with `@extractor`, `@rule` or `@final` decorator

        .. code-block:: Python

            from malduck import Extractor

            class Evil(Extractor):
                yara_rules = ("evil", "weird")
                family = "evil"

                ...

                @Extractor.weak
                @Extractor.extractor
                def dga_seed(self, p, hit):
                    # Even if we're able to get the DGA seed, extractor won't produce config
                    # until is_it_really_evil match as well
                    dga_config = p.readv(hit, 128)
                    seed = self._get_dga_seed(dga_config)
                    if seed is not None:
                        return {"dga_seed": seed}

                @Extractor.final
                def is_it_really_evil(self, p):
                    # If p starts with 'evil', we can produce config
                    return p.read(p.imgbase, 4) == b'evil'

    .. py:decoratormethod:: Extractor.needs_pe

        Use this decorator for extractors that need PE instance.
        (p is guaranteed to be :class:`malduck.procmem.ProcessMemoryPE`)

        .. versionchanged:: 4.0.0

            Method must be decorated first with `@extractor`, `@rule` or `@final` decorator

    .. py:decoratormethod:: Extractor.needs_elf

        Use this decorator for extractors that need ELF instance.
        (p is guaranteed to be :class:`malduck.procmem.ProcessMemoryELF`)

        .. versionchanged:: 4.0.0

            Method must be decorated first with `@extractor`, `@rule` or `@final` decorator.

    """

    yara_rules = ()  #: Names of Yara rules for which handle_match is called
    family = None  #: Extracted malware family, automatically added to "family" key for strong extraction methods
    overrides = []  #: Family match overrides another match e.g. citadel overrides zeus

    def __init__(self, parent):
        self.parent = parent

    def push_procmem(self, procmem: ProcessMemory, **info):
        """
        Push extracted procmem object for further analysis

        :param procmem: ProcessMemory object
        :type procmem: :class:`malduck.procmem.ProcessMemory`
        :param info: Additional info about object
        """
        return self.parent.push_procmem(procmem, **info)

    def push_config(self, config):
        """
        Push partial config (used by :py:meth:`Extractor.handle_match`)

        :param config: Partial config element
        :type config: dict
        """
        return self.parent.push_config(config, self)

    @property
    def matched(self):
        """
        Returns True if family has been matched so far

        :rtype: bool
        """
        return self.parent.family is not None

    @property
    def collected_config(self):
        """
        Shows collected config so far (useful in "final" extractors)

        :rtype: dict
        """
        return self.parent.collected_config

    @property
    def globals(self):
        """
        Container for global variables associated with analysis

        :rtype: dict
        """
        return self.parent.globals

    @property
    def log(self):
        """
        Logger instance for Extractor methods

        :return: :class:`logging.Logger`
        """
        return logging.getLogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

    def _get_methods(self, method_type):
        return (
            (name, method)
            for name, method in inspect.getmembers(
                self.__class__, predicate=lambda member: isinstance(member, method_type)
            )
            if isinstance(method, method_type)
        )

    def on_error(self, exc, method_name):
        """
        Handler for all Exception's throwed by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param method_name: Name of method which throwed exception
        :type method_name: str
        """
        self.parent.on_extractor_error(exc, self, method_name)

    def handle_match(self, p, match):
        """
        Override this if you don't want to use decorators and customize ripping process
        (e.g. yara-independent, brute-force techniques)

        Called for each rule hit listed in Extractor.yara_rules.

        Overriding this method means that all Yara hits must be processed within this method.
        Ripped configurations must be reported using :py:meth:`push_config` method.

        .. versionadded: 4.0.0::

            Use :py:meth:`handle_match` instead of deprecated :py:meth:`handle_yara`.

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param match: Found yara matches for currently matched rule
        :type match: :class:`malduck.yara.YaraRuleMatch`
        """
        # Call offset-only string-based extractors
        for method_name, method in self._get_methods(StringOffsetExtractorMethod):
            identifier = method.string_name
            if identifier not in match:
                continue
            for string_match in match[identifier]:
                try:
                    log.debug(
                        "Trying %s.%s for %s@%x",
                        self.__class__.__name__,
                        method_name,
                        identifier,
                        string_match.offset,
                    )
                    method(self, p, string_match.offset)
                except Exception as exc:
                    self.on_error(exc, method_name)

        # Call string-based extractors
        for method_name, method in self._get_methods(StringExtractorMethod):
            identifiers = method.string_names
            for identifier in identifiers:
                if identifier not in match:
                    continue
                for string_match in match[identifier]:
                    try:
                        log.debug(
                            "Trying %s.%s for %s@%x",
                            self.__class__.__name__,
                            method_name,
                            string_match.identifier,
                            string_match.offset,
                        )
                        method(self, p, string_match.offset, string_match)
                    except Exception as exc:
                        self.on_error(exc, method_name)

        # Call rule-based extractors
        for method_name, method in self._get_methods(RuleExtractorMethod):
            if match.name != method.rule_name:
                continue
            log.debug("Trying %s.%s (rule)", self.__class__.__name__, method_name)
            try:
                method(self, p, match)
            except Exception as exc:
                self.on_error(exc, method_name)

        # Call final extractors
        for method_name, method in self._get_methods(FinalExtractorMethod):
            log.debug("Trying %s.%s (final)", self.__class__.__name__, method_name)
            try:
                method(self, p)
            except Exception as exc:
                self.on_error(exc, method_name)

    # Extractor method decorators
    @staticmethod
    def extractor(string_or_method):
        if callable(string_or_method):
            if isinstance(string_or_method, ExtractorMethod):
                raise TypeError("@extractor decorator must be first")
            return StringOffsetExtractorMethod(string_or_method)
        elif isinstance(string_or_method, str):
            string = cast(str, string_or_method)

            def extractor_wrapper(method):
                if isinstance(method, ExtractorMethod):
                    raise TypeError("@extractor decorator must be first")
                return StringOffsetExtractorMethod(method, string_name=string)

            return extractor_wrapper
        else:
            raise TypeError("Expected string or callable argument")

    @staticmethod
    def string(*strings_or_method):
        if callable(strings_or_method[0]) and len(strings_or_method) == 1:
            method = strings_or_method[0]
            if isinstance(method, ExtractorMethod):
                raise TypeError("@extractor decorator must be first")
            return StringExtractorMethod(method)
        elif all(isinstance(string, str) for string in strings_or_method):
            strings = cast(List[str], strings_or_method)

            def extractor_wrapper(method):
                if isinstance(method, ExtractorMethod):
                    raise TypeError("@extractor decorator must be first")
                return StringExtractorMethod(method, string_names=strings)

            return extractor_wrapper
        else:
            raise TypeError("Expected strings or single callable argument")

    @staticmethod
    def rule(string_or_method):
        if callable(string_or_method):
            if isinstance(string_or_method, ExtractorMethod):
                raise TypeError("@rule decorator must be first")
            return RuleExtractorMethod(string_or_method)
        elif isinstance(string_or_method, str):
            string = cast(str, string_or_method)

            def extractor_wrapper(method):
                if isinstance(method, ExtractorMethod):
                    raise TypeError("@rule decorator must be first")
                return RuleExtractorMethod(method, rule_name=string)

            return extractor_wrapper
        else:
            raise TypeError("Expected string or callable argument")

    @staticmethod
    def final(method):
        if isinstance(method, ExtractorMethod):
            raise TypeError("@final decorator must be first")
        return FinalExtractorMethod(method)

    @staticmethod
    def needs_pe(method):
        if not isinstance(method, ExtractorMethod):
            raise TypeError(
                "@needs_pe decorator must be placed before @final/@rule/@extractor decorator"
            )
        method.procmem_type = ProcessMemoryPE
        return method

    @staticmethod
    def needs_elf(method):
        if not isinstance(method, ExtractorMethod):
            raise TypeError(
                "@needs_elf decorator must be placed before @final/@rule/@extractor decorator"
            )
        method.procmem_type = ProcessMemoryELF
        return method

    @staticmethod
    def weak(method):
        if not isinstance(method, ExtractorMethod):
            raise TypeError(
                "@weak decorator must be placed before @final/@rule/@extractor decorator"
            )
        method.weak = True
        return method
