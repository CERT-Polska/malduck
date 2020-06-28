import json
import logging
import os
import warnings
from typing import Any, Dict, Optional, List, Type, Union

from ..yara import Yara, YaraRuleOffsets, YaraRulesetMatch
from ..procmem import ProcessMemory
from .extractor import Extractor
from .loaders import load_modules

log = logging.getLogger(__name__)

Config = Dict[str, Any]

__all__ = ["ExtractManager", "ExtractorModules"]


def is_config_better(base_config: Config, new_config: Config) -> bool:
    """
    Checks whether new config looks more reliable than base.
    Currently just checking the amount of non-empty keys.
    """
    base = [(k, v) for k, v in base_config.items() if v]
    new = [(k, v) for k, v in new_config.items() if v]
    return len(new) > len(base)


def encode_for_json(data: Any) -> Any:
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, list) or isinstance(data, tuple):
        return [encode_for_json(item) for item in data]
    elif isinstance(data, dict):
        return {key: encode_for_json(value) for key, value in data.items()}
    else:
        return data


def sanitize_config(config: Config) -> Config:
    """
    Sanitize static configuration by removing empty strings/collections

    :param config: Configuration to sanitize
    :return: Sanitized configuration
    """
    return {k: v for k, v in config.items() if v in [0, False] or v}


def merge_configs(base_config: Config, new_config: Config) -> Config:
    """
    Merge static configurations.
    Used internally. Removes "family" key from the result, which is set explicitly by ExtractManager.push_config

    :param base_config: Base configuration
    :param new_config: Changes to apply
    :return: Merged configuration
    """
    config = dict(base_config)
    for k, v in new_config.items():
        if k == "family":
            continue
        if k not in config:
            config[k] = v
        elif config[k] == v:
            continue
        elif isinstance(config[k], list):
            for el in v:
                if el not in config[k]:
                    config[k] = config[k] + [el]
        else:
            raise RuntimeError(
                f"Extractor tries to override '{config[k]}' "
                f"value of '{k}' with '{v}'"
            )
    return config


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
        load_modules(modules_path, onerror=self.on_error)
        self.extractors: List[Type[Extractor]] = Extractor.__subclasses__()

    def on_error(self, exc: Exception, module_name: str) -> None:
        """
        Handler for all Exception's throwed during module load

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param module_name: Name of module which throwed exception
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
        Handler for all Exception's thrown by :py:meth:`Extractor.handle_yara`.

        .. deprecated:: 2.1.0
           Look at :py:meth:`ExtractManager.on_extractor_error` instead.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor object which throwed exception
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        self.on_extractor_error(exc, extractor, "handle_yara")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all Exception's thrown by extractor methods (including :py:meth:`Extractor.handle_yara`).

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which throwed exception
        :type method_name: str
        """
        import traceback

        log.warning(
            "%s.%s throwed exception: %s",
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
        :return: Family name if ripped successfully and provided better configuration than previous files.
                 Returns None otherwise.
        """
        log.debug("Started extraction of file %s:%x", filepath, base)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.push_procmem(p, rip_binaries=True)

    def push_config(self, family: str, config: Config) -> Optional[str]:
        config["family"] = family
        if family not in self.configs:
            self.configs[family] = config
            return family
        else:
            base_config = self.configs[family]
            if is_config_better(base_config, config):
                log.debug("Config looks better")
                self.configs[family] = config
                return family
            else:
                log.debug("Config doesn't look better - ignoring.")
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
        :return: Family name if ripped successfully and provided better configuration than previous procmems.
                 Returns None otherwise.
        """
        from ..procmem import ProcessMemoryPE, ProcessMemoryELF
        from ..procmem.binmem import ProcessMemoryBinary

        matches = p.yarav(self.rules, extended=True)

        if not matches:
            log.debug("No Yara matches.")
            return None

        binaries: List[Union[ProcessMemory, ProcessMemoryBinary]] = [p]
        if rip_binaries:
            binaries += list(ProcessMemoryPE.load_binaries_from_memory(p))
            binaries += list(ProcessMemoryELF.load_binaries_from_memory(p))

        def fmt_procmem(p: ProcessMemory) -> str:
            procmem_type = "IMG" if getattr(p, "is_image", False) else "DMP"
            return f"{p.__class__.__name__}:{procmem_type}:{p.imgbase:x}"

        def extract_config(procmem: ProcessMemory) -> Optional[str]:
            log.debug("%s - ripping...", fmt_procmem(procmem))
            extractor = ProcmemExtractManager(self)
            extractor.push_procmem(procmem, _matches=matches.remap(procmem.p2v))
            if extractor.family:
                log.debug("%s - found %s!", fmt_procmem(procmem), extractor.family)
                return self.push_config(extractor.family, extractor.config)
            else:
                log.debug("%s - No luck.", fmt_procmem(procmem))
            return None

        # 'list()' for prettier logs
        log.debug("Matched rules: %s", list(matches.keys()))

        ripped_family = None

        for binary in binaries:
            found_family = extract_config(binary)
            if found_family is not None:
                ripped_family = found_family
            if isinstance(binary, ProcessMemoryBinary) and binary.image is not None:
                found_family = extract_config(binary.image)
                if found_family is not None:
                    ripped_family = found_family
        return ripped_family

    @property
    def config(self) -> List[Config]:
        """
        Extracted configuration (list of configs for each extracted family)
        """
        return [config for family, config in self.configs.items()]


class ProcmemExtractManager:
    """
    Single-dump extraction context (single family)
    """

    def __init__(self, parent: ExtractManager) -> None:
        #: Collected configuration so far (especially useful for "final" extractors)
        self.collected_config: Config = {}
        self.globals: Dict[str, Any] = {}
        self.parent = parent  #: Bound ExtractManager instance
        self.family = None  #: Matched family

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all Exception's throwed by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which throwed exception
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

        self.collected_config = merge_configs(self.collected_config, config)

        if "family" in config and (
            not self.family
            or (self.family != extractor.family and self.family in extractor.overrides)
        ):
            self.family = config["family"]
            log.debug("%s tells it's %s", extractor.__class__.__name__, self.family)

    @property
    def config(self) -> Config:
        """
        Returns collected config, but if family is not matched - returns empty dict.
        Family is not included in config itself, look at :py:attr:`ProcmemExtractManager.family`.
        """
        if self.family is None:
            return {}
        return self.collected_config
