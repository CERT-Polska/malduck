import os
import warnings

from .extractor import Extractor
from .loaders import load_modules
from ..yara import Yara


def merge_configs(config, new_config):
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
            raise RuntimeError("Extractor tries to override '{old_value}' "
                               "value of '{key}' with '{new_value}'".format(key=k,
                                                                            old_value=config[k],
                                                                            new_value=v))


class ExtractorModules(object):
    """
    Configuration object with loaded Extractor modules for ExtractManager

    :param modules_path: Path with module files (Extractor classes and Yara files, default '~/.malduck')
    :type modules_path: str
    """
    def __init__(self, modules_path=None):
        if modules_path is None:
            modules_path = os.path.join(os.path.expanduser("~"), ".malduck")
            if not os.path.exists(modules_path):
                os.makedirs(modules_path)
        # Load Yara rules
        self.rules = Yara.from_dir(modules_path)
        # Preload modules
        load_modules(modules_path, onerror=self.on_error)
        self.extractors = Extractor.__subclasses__()

    def on_error(self, exc, module_name):
        """
        Handler for all Exception's throwed during module load

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param module_name: Name of module which throwed exception
        :type module_name: str
        """
        warnings.warn("{} not loaded: {}".format(module_name, exc))


class ExtractManager(object):
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    """
    def __init__(self, modules):
        self.modules = modules
        self.configs = {}

    @property
    def rules(self):
        """
        Bound Yara rules
        :rtype: :class:`malduck.yara.Yara`
        """
        return self.modules.rules

    @property
    def extractors(self):
        """
        Bound extractor modules
        :rtype: List[Type[:class:`malduck.extractor.Extractor`]]
        """
        return self.modules.extractors

    def on_error(self, exc, extractor):
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

    def on_extractor_error(self, exc, extractor, method_name):
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
        warnings.warn("{}.{} throwed exception: {}".format(
                      extractor.__class__.__name__,
                      method_name,
                      traceback.format_exc()))

    def push_file(self, filepath, base=0, pe=None, elf=None, image=None):
        """
        Pushes file for extraction. Config extractor entrypoint.
        
        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :param pe: Determines whether file contains PE (default: detect automatically)
        :type pe: bool or None ("detect")
        :param elf: Determines whether file contains ELF (default: detect automatically)
        :type elf: bool or None ("detect")
        :param image: If pe is True, determines whether file contains PE image (default: detect automatically)
        :type image: bool or None ("detect")
        """
        from ..procmem import ProcessMemory, ProcessMemoryPE, ProcessMemoryELF
        with ProcessMemory.from_file(filepath, base=base) as p:
            if pe is None and p.readp(0, 2) == b"MZ":
                pe = True
            if elf is None and p.readp(0, 4) == b"\x7fELF":
                elf = True
            if pe and elf:
                raise RuntimeError("A binary can't be both ELF and PE file")
            if pe:
                p = ProcessMemoryPE.from_memory(p, image=image, detect_image=image is None)
            elif elf:
                if image is False:
                    raise RuntimeError("ELF dumps are not supported yet")
                p = ProcessMemoryELF.from_memory(p, image=True)
            self.push_procmem(p)

    def push_procmem(self, p):
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        """
        extractor = ProcmemExtractManager(self)
        extractor.push_procmem(p)
        if extractor.config:
            if extractor.family not in self.configs:
                self.configs[extractor.family] = extractor.config
            else:
                merge_configs(self.configs[extractor.family], extractor.config)

    @property
    def config(self):
        """
        Extracted configuration (list of configs for each extracted family)
        """
        return [config for family, config in self.configs.items()]


class ProcmemExtractManager(object):
    """
    Single-dump extraction context (single family)
    """
    def __init__(self, parent):
        self.collected_config = {}  #: Collected configuration so far (especially useful for "final" extractors)
        self.globals = {}
        self.parent = parent        #: Bound ExtractManager instance
        self.family = None          #: Matched family

    def on_extractor_error(self, exc, extractor, method_name):
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

    def push_procmem(self, p):
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        """
        matched = p.yarav(self.parent.rules)
        # For each extractor...
        for ext_class in self.parent.extractors:
            extractor = ext_class(self)
            # For each rule identifier in extractor.yara_rules...
            for rule in extractor.yara_rules:
                if rule in matched:
                    try:
                        extractor.handle_yara(p, matched[rule])
                    except Exception as exc:
                        self.parent.on_error(exc, extractor)

    def push_config(self, config, extractor):
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
        if "family" in config:
            if not self.family or (
                    self.family != extractor.family and
                    self.family in extractor.overrides):
                self.family = config["family"]

        new_config = dict(self.collected_config)

        merge_configs(new_config, config)

        if self.family:
            new_config["family"] = self.family
        self.collected_config = new_config

    @property
    def config(self):
        """
        Returns collected config, but if family is not matched - returns empty dict
        """
        if self.family is None:
            return {}
        return self.collected_config
