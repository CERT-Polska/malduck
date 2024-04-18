import json
import logging
import warnings
from typing import Any, Dict, Iterator, List, Optional, Type

from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..procmem.binmem import ProcessMemoryBinary
from ..yara import Yara, YaraRuleOffsets, YaraRulesetMatch
from .config_utils import (
    Config,
    apply_config_part,
    encode_for_json,
    is_config_better,
    sanitize_config,
)
from .extractor import Extractor
from .modules import ExtractorModules

log = logging.getLogger(__name__)

__all__ = ["ExtractManager"]


class ExtractManager:
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    """

    def __init__(self, modules: ExtractorModules) -> None:
        self.modules = modules
        self.binary_classes: List[Type[ProcessMemoryBinary]] = [
            ProcessMemoryPE,
            ProcessMemoryELF,
        ]
        self.configs: Dict[str, Config] = {}

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

    def push_file(self, filepath: str, base: int = 0) -> Optional[str]:
        """
        Pushes file for extraction. Config extractor entrypoint.

        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :return: Detected family if configuration looks better than already stored one
        """
        log.debug("Started extraction of file %s:%x", filepath, base)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.push_procmem(p, rip_binaries=True)

    def match_procmem(self, p: ProcessMemory) -> YaraRulesetMatch:
        """
        Performs Yara matching on ProcessMemory using modules
        bound with current ExtractManager.
        """
        matches = p.yarap(self.rules, extended=True)
        log.debug("Matched rules: %s", ",".join(list(matches.keys())))
        return matches

    def carve_procmem(self, p: ProcessMemory) -> Iterator[ProcessMemoryBinary]:
        """
        Carves binaries from ProcessMemory to try configuration extraction
        using every possible address mapping.
        """
        for binclass in self.binary_classes:
            carved_bins = binclass.load_binaries_from_memory(p)
            for carved_bin in carved_bins:
                log.debug(
                    f"carve: Found {carved_bin.__class__.__name__} "
                    f"at offset {carved_bin.regions[0].offset}"
                )
                yield carved_bin

    def push_config(self, config: Config) -> bool:
        if not config.get("family"):
            return False

        family = config["family"]
        if family in self.configs:
            if is_config_better(base_config=self.configs[family], new_config=config):
                self.configs[family] = config
                log.debug("%s config looks better than previous one", family)
                return True
            else:
                log.debug("%s config doesn't look better than previous one", family)
                return False

        if family in self.modules.override_paths:
            # 'citadel' > 'zeus'
            # If 'zeus' appears but we have already 'citadel', we should ignore 'zeus'
            # Otherwise we should get 'citadel' instead of 'zeus'
            for stored_family in self.configs.keys():
                if stored_family == family:
                    continue
                score = self.modules.compare_family_overrides(family, stored_family)
                if score == -1:
                    del self.configs[stored_family]
                    self.configs[family] = config
                    log.debug(
                        "%s config looks better (overrides %s)", family, stored_family
                    )
                    return True
                elif score == 1:
                    log.debug(
                        "%s config doesn't look better than previous one (overridden by %s)",
                        family,
                        stored_family,
                    )
                    return False

        log.debug("New %s config collected", family)
        self.configs[family] = config
        return True

    def _extract_procmem(self, p: ProcessMemory, matches) -> Optional[str]:
        log.debug("%s - ripping...", repr(p))
        # Create extraction context for single file
        manager = ExtractionContext(parent=self)
        # Map offset matches to VA using procmem address mapping
        va_matches = matches.remap(p.p2v)
        # Push ProcessMemory for extraction with mapped Yara matches
        manager.push_procmem(p, _matches=va_matches)
        # Get final configurations
        config = manager.collected_config
        if config.get("family"):
            log.debug("%s - found %s!", repr(p), config.get("family"))
            if self.push_config(config):
                return config["family"]
            else:
                return None
        else:
            log.debug("%s - no luck.", repr(p))
            return None

    def push_procmem(
        self, p: ProcessMemory, rip_binaries: bool = False
    ) -> Optional[str]:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param rip_binaries: Look for binaries (PE, ELF) in provided ProcessMemory and try to perform extraction using
            specialized variants (ProcessMemoryPE, ProcessMemoryELF)
        :type rip_binaries: bool (default: False)
        :return: Detected family if configuration looks better than already stored one
        """
        matches = self.match_procmem(p)
        if not matches:
            log.debug("No Yara matches.")
            return None

        binaries = self.carve_procmem(p) if rip_binaries else iter([])

        family = self._extract_procmem(p, matches)
        for binary in binaries:
            family = self._extract_procmem(binary, matches) or family
        return family

    @property
    def config(self) -> List[Config]:
        """
        Extracted configuration (list of configs for each extracted family)
        """
        return [config for family, config in self.configs.items()]


class ExtractionContext:
    """
    Single-dump extraction context (single family)
    """

    def __init__(self, parent: ExtractManager) -> None:
        #: Collected configuration so far (especially useful for "final" extractors)
        self.collected_config: Config = {}
        self.globals: Dict[str, Any] = {}
        self.parent = parent  #: Bound ExtractManager instance

    @property
    def family(self) -> Optional[str]:
        """Matched family"""
        return self.collected_config.get("family")

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
        self, p: ProcessMemory, _matches: Optional[YaraRulesetMatch] = None
    ) -> None:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _matches: YaraRulesetMatch object (used internally)
        :type _matches: :class:`malduck.yara.YaraRulesetMatch`
        """
        matches = _matches or p.yarav(self.parent.rules, extended=True)
        # For each extractor...
        for ext_class in self.parent.extractors:
            extractor = ext_class(self)

            if type(extractor.yara_rules) is str:
                raise TypeError(
                    f'"{extractor.__class__.__name__}.yara_rules" cannot be a string, convert it into a list of strings'
                )

            # For each rule identifier in extractor.yara_rules...
            for rule in extractor.yara_rules:
                if rule in matches:
                    try:
                        if hasattr(extractor, "handle_yara"):
                            warnings.warn(
                                "Extractor.handle_yara is deprecated, use Extractor.handle_match",
                                DeprecationWarning,
                            )
                            getattr(extractor, "handle_yara")(
                                p, YaraRuleOffsets(matches[rule])
                            )
                        else:
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

        if "family" in config:
            log.debug(
                "%s tells it's %s", extractor.__class__.__name__, config["family"]
            )
            if (
                "family" in self.collected_config
                and self.collected_config["family"] != config["family"]
            ):
                overrides = self.parent.modules.compare_family_overrides(
                    config["family"], self.collected_config["family"]
                )
                if not overrides:
                    raise RuntimeError(
                        f"Ripped both {self.collected_config['family']} and {config['family']} "
                        f"from the same ProcessMemory which is not expected"
                    )
                if overrides == -1:
                    self.collected_config["family"] = config["family"]
                else:
                    config["family"] = self.collected_config["family"]
        self.collected_config = apply_config_part(self.collected_config, config)

    @property
    def config(self) -> Config:
        """
        Returns collected config, but if family is not matched - returns empty dict.
        Family is not included in config itself, look at :py:attr:`ProcmemExtractManager.family`.
        """
        if self.family is None:
            return {}
        return self.collected_config
