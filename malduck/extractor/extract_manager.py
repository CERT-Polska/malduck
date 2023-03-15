import json
import logging
import os
import warnings
from collections import defaultdict
from typing import (
    Any,
    DefaultDict,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Type,
    Union,
)

from ..match import RuleMatcher, RuleMatches
from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..procmem.binmem import ProcessMemoryBinary
from ..yara import Yara, YaraMatcher, YaraRule
from .config import ConfigSet, encode_for_json, sanitize_config
from .extractor import Extractor
from .loaders import load_modules

log = logging.getLogger(__name__)

Config = Dict[str, Any]

__all__ = ["ExtractManager", "ExtractorModules"]


class ExtractorModules:
    """
    Configuration object with loaded Extractor modules for ExtractManager

    :param modules_path: Path with module files (Extractor classes and Yara files, default '~/.malduck')
    :type modules_path: str
    """

    def __init__(self, modules_path: Optional[str] = None) -> None:
        if modules_path is None:
            modules_path = os.path.join(os.path.expanduser("~"), ".malduck")
            if not os.path.exists(modules_path):
                os.makedirs(modules_path)
        # Load Yara rules
        self.rules: Yara = Yara.from_dir(modules_path)
        # Preload modules
        loaded_modules = load_modules(modules_path, onerror=self.on_error)
        self.extractors: List[Type[Extractor]] = Extractor.__subclasses__()

        loaded_extractors = [x.__module__ for x in self.extractors]

        for module in loaded_modules.values():
            module_name = module.__name__
            if not any(x.startswith(module_name) for x in loaded_extractors):
                warnings.warn(
                    f"The extractor engine couldn't import any Extractors from module {module_name}. "
                    f"Make sure the Extractor class is imported into __init__.py",
                )

        self.family_overrides: DefaultDict[str, List[str]] = defaultdict(list)

        for extractor in self.extractors:
            if extractor.family is None:
                continue
            for override in extractor.overrides:
                self.family_overrides[override].append(extractor.family)

        self.inline_rules: List[Union[str, YaraRule]] = []

        for extractor in self.extractors:
            self.inline_rules = self.inline_rules + extractor.inline_rules

        if self.inline_rules:
            # If there are any inline rules: include them in Yara object
            self.rules = Yara(
                compiled_rules=self.rules.rulesets, rules=self.inline_rules
            )

    def on_error(self, exc: Exception, module_name: str) -> None:
        """
        Handler for all exceptions raised during module load

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param module_name: Name of module which raised the exception
        :type module_name: str
        """
        log.warning("%s not loaded: %s", module_name, exc)


class ExtractManager:
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    """

    def __init__(self, modules: ExtractorModules) -> None:
        self.modules = modules
        self.configs = ConfigSet()
        self.matchers: List[RuleMatcher] = [YaraMatcher(rules=self.modules.rules)]
        self.binary_classes: List[Type[ProcessMemoryBinary]] = [
            ProcessMemoryPE,
            ProcessMemoryELF,
        ]

    @property
    def rules(self) -> Yara:
        """
        Bound Yara rules
        :rtype: :class:`malduck.yara.Yara`
        """
        return self.modules.rules

    @property
    def extractors(self) -> List[Type[Extractor]]:
        """
        Bound extractor modules
        :rtype: List[Type[:class:`malduck.extractor.Extractor`]]
        """
        return self.modules.extractors

    @property
    def family_overrides(self) -> Mapping[str, Sequence[str]]:
        return dict(self.modules.family_overrides)

    @property
    def final_configs(self):
        return dict(self.configs)

    def on_error(self, exc: Exception, extractor: Extractor) -> None:
        """
        Handler for all exceptions raised by :py:meth:`Extractor.handle_yara`.

        .. deprecated:: 2.1.0
           Look at :py:meth:`ExtractManager.on_extractor_error` instead.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor object which raised the exception
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        self.on_extractor_error(exc, extractor, "handle_yara")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods (including :py:meth:`Extractor.handle_yara`).

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        import traceback

        log.warning(
            "%s.%s raised an exception: %s",
            extractor.__class__.__name__,
            method_name,
            traceback.format_exc(),
        )

    def extract_file(self, filepath: str, base: int = 0) -> ConfigSet:
        log.debug("Started extraction of file %s:%x", filepath, base)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.extract_procmem(p)

    def match_procmem(self, p: ProcessMemory) -> RuleMatches:
        return RuleMatches(
            [match for matcher in self.matchers for match in matcher.match(p)]
        )

    def carve_procmem(self, p: ProcessMemory) -> List[ProcessMemoryBinary]:
        binaries = []
        for binclass in self.binary_classes:
            binaries += list(binclass.load_binaries_from_memory(p))
        return binaries

    def _extract_config(
        self, p: ProcessMemory, matches: RuleMatches, configs: ConfigSet
    ) -> ConfigSet:
        log.debug("%s - ripping...", repr(p))
        manager = ProcmemExtractManager(parent=self)
        va_matches = matches.p2v(p)
        manager.push_procmem(p, va_matches)
        final_configs = manager.configs.filter_final_configs()
        families_found = final_configs.keys()
        if families_found:
            log.debug("%s - found %s!", repr(p), ", ".join(families_found))
        else:
            log.debug("%s - no luck.", repr(p))
            pass
        return configs.merge_config_sets(final_configs)

    def extract_procmem(self, p: ProcessMemory):
        matches = self.match_procmem(p)
        binaries = self.carve_procmem(p)
        configs = ConfigSet()

        configs = self._extract_config(p, matches, configs)
        for binary in binaries:
            configs = self._extract_config(binary, matches, configs)
            # image mode
            binary_image = binary.image
            if binary_image:
                configs = self._extract_config(binary_image, matches, configs)

        # Aggregate config with general collection
        self.configs = self.configs.merge_config_sets(configs)
        return configs
        # todo: handle overrides


class ProcmemExtractManager:
    """
    Single-dump extraction context (single family)
    """

    def __init__(self, parent: ExtractManager) -> None:
        #: Collected configuration so far
        self.configs: ConfigSet = ConfigSet()
        self.globals: Dict[str, Any] = {}
        self.parent = parent  #: Bound ExtractManager instance

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        self.parent.on_extractor_error(exc, extractor, method_name)

    def push_procmem(
        self, p: ProcessMemory, _matches: Optional[RuleMatches] = None
    ) -> None:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _matches: YaraRulesetMatch object (used internally)
        :type _matches: :class:`malduck.yara.YaraRulesetMatch`
        """
        matches = _matches or self.parent.match_procmem(p).p2v(p)

        # For each extractor...
        for ext_class in self.parent.extractors:
            extractor = ext_class(self)

            if type(extractor.yara_rules) is str:
                raise TypeError(
                    f'"{extractor.__class__.__name__}.yara_rules" cannot be a string, '
                    f"convert it into a list of strings"
                )

            # For each rule identifier in extractor.yara_rules...
            for rule in extractor.yara_rules:
                if rule in matches:
                    try:
                        extractor.handle_match(p, matches[rule])
                    except Exception as exc:
                        self.parent.on_error(exc, extractor)

    def push_config(self, config: Config, extractor: Extractor) -> None:
        """
        Pushes new partial config

        If strong config provides different family than stored so far
        and that family overrides stored family - set stored family
        Example: citadel overrides zeus

        :param config: Partial config object
        :type config: dict
        :param extractor: Extractor object reference
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        config = encode_for_json(config)
        try:
            json.dumps(config)
        except (TypeError, OverflowError) as e:
            log.debug("Config is not JSON-encodable (%s): %s", str(e), repr(config))
            raise RuntimeError("Config must be JSON-encodable")

        config = sanitize_config(config)

        if not config:
            return

        log.debug(
            "%s found the following config parts: %s",
            extractor.__class__.__name__,
            sorted(config.keys()),
        )

        # Weak configurations have no "family" set
        # But we still need to track the origin to merge configs accordingly
        family = config.get("family", extractor.family)
        if not family:
            raise RuntimeError(
                "Family must be set at least on Extractor level to push configs"
            )

        if "family" in config:
            log.debug(
                "%s tells it's %s", extractor.__class__.__name__, config["family"]
            )

        self.configs.push_partial_config(config, family)
