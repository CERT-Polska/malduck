import importlib.util
import logging
import os
import pkgutil
import sys
import warnings
from collections import defaultdict
from importlib.abc import FileLoader, PathEntryFinder
from typing import Any, Callable, DefaultDict, Dict, List, Optional, Type, cast

from ..yara import Yara
from .extractor import Extractor

log = logging.getLogger(__name__)


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
        self.override_paths = make_override_paths(self.extractors)

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

    def compare_family_overrides(self, first: str, second: str) -> int:
        """
        Checks which family supersedes which. Relations can be transitive,
        so ExtractorModules builds all possible paths and checks the order.
        If there is no such relationship between families, function returns None.
        """
        if first not in self.override_paths or second not in self.override_paths:
            return 0
        for path in self.override_paths[first]:
            try:
                if path.index(first) < path.index(second):
                    return -1
                else:
                    return 1
            except ValueError:
                pass
        return 0


def make_override_paths(extractors: List[Type[Extractor]]) -> Dict[str, List[str]]:
    # Make override trees and get roots
    overrides: DefaultDict[str, List[str]] = defaultdict(list)
    parents = set()
    children = set()
    for extractor in extractors:
        if extractor.family is None:
            continue
        for overridden_family in extractor.overrides:
            overrides[extractor.family].append(overridden_family)
            parents.add(extractor.family)
            children.add(overridden_family)
    roots = parents.difference(children)
    unvisited = parents.union(children)
    # Perform DFS and collect all override paths
    override_paths = defaultdict(list)

    def make_override_path(node, visited, current_path=None):
        if node in visited:
            raise RuntimeError(
                f"Override cycle detected: {node} already visited during tree traversal"
            )
        visited.add(node)
        unvisited.remove(node)
        current_path = [*(current_path or []), node]
        if not overrides[node]:
            # Leaf: override path is complete
            for family in current_path:
                override_paths[family].append(current_path)
        else:
            # Not a leaf: go deeper
            for family in overrides[node]:
                make_override_path(family, visited=visited, current_path=current_path)

    for root in roots:
        make_override_path(root, visited=set())
    # Root undetected
    if unvisited:
        raise RuntimeError(
            f"Override cycle detected: {list(unvisited)} not visited during tree traversal"
        )
    return dict(override_paths)


def import_module_by_finder(finder: PathEntryFinder, module_name: str) -> Any:
    """
    Imports module from arbitrary path using importer returned by pkgutil.iter_modules
    """
    if module_name in sys.modules:
        return sys.modules[module_name]

    # https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
    module_spec = finder.find_spec(module_name)
    if module_spec is None or module_spec.loader is None:
        raise Exception("Couldn't find module spec for %s", module_name)
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    try:
        loader: FileLoader = cast(FileLoader, module_spec.loader)
        loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    return module


def load_modules(
    search_path: str, onerror: Optional[Callable[[Exception, str], None]] = None
) -> Dict[str, Any]:
    """
    Loads plugin modules under specified paths

    .. note::

        This method is considered to be used internally (see also :class:`extractor.ExtractorModules`)

    :param search_path: Path searched for modules
    :type search_path: str
    :param onerror: Exception handler (default: ignore exceptions)
    :return: dict {name: module}
    """
    modules: Dict[str, Any] = {}
    for finder, module_name, is_pkg in pkgutil.iter_modules(
        [search_path], "malduck.extractor.modules."
    ):
        if not is_pkg:
            continue
        if module_name in modules:
            log.warning("Module collision - %s overridden", module_name)
        try:
            modules[module_name] = import_module_by_finder(
                cast(PathEntryFinder, finder), module_name
            )
        except Exception as exc:
            if onerror:
                onerror(exc, module_name)
    return modules
