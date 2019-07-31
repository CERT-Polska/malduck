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
            if not os.path.isdir(modules_path):
                os.makedirs(modules_path, exist_ok=True)
        # Load Yara rules
        self.rules = Yara.from_dir(modules_path)
        # Preload modules
        load_modules(modules_path)
        self.extractors = Extractor.__subclasses__()


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
        Handler for all Exception's throwed by :py:meth:`Extractor.handle_yara`.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor object which throwed exception
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        import traceback
        warnings.warn("Extractor {} throwed exception: {}".format(
            extractor.__class__.__name__,
            traceback.format_exc()))

    def push_file(self, filepath, base=0, pe=None, image=None):
        """
        Pushes file for extraction. Config extractor entrypoint. 
        
        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :param pe: Determines whether file contains PE (default: detect automatically)
        :type pe: bool or None ("detect")
        :param image: If pe is True, determines whether file contains PE image (default: detect automatically)
        :type image: bool or None ("detect")
        """
        from ..procmem import ProcessMemory, ProcessMemoryPE
        with ProcessMemory.from_file(filepath, base=base) as p:
            if pe is None and p.readp(0, 2) == "MZ":
                pe = True
            if pe:
                p = ProcessMemoryPE.from_memory(p, image=image, detect_image=image is None)
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
