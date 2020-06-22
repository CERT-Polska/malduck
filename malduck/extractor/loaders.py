import importlib.util
import logging
import pkgutil
import sys

log = logging.getLogger(__name__)


def import_module_by_finder(finder, module_name):
    """
    Imports module from arbitrary path using importer returned by pkgutil.iter_modules
    """
    if module_name in sys.modules:
        return sys.modules[module_name]

    # https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
    module_spec = finder.find_spec(module_name)
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    try:
        module = module_spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    return module


def load_modules(search_path, onerror=None):
    """
    Loads plugin modules under specified paths

    .. note::

        This method is considered to be used internally (see also :class:`extractor.ExtractorModules`)

    :param search_path: Path searched for modules
    :type search_path: str
    :param onerror: Exception handler (default: ignore exceptions)
    :return: dict {name: module}
    """
    modules = {}
    for finder, module_name, is_pkg in pkgutil.iter_modules(
        [search_path], "malduck.extractor.modules."
    ):
        if not is_pkg:
            continue
        if module_name in modules:
            log.warning("Module collision - {} overridden".format(module_name))
        try:
            modules[module_name] = import_module_by_finder(finder, module_name)
        except Exception as exc:
            if onerror:
                onerror(exc, module_name)
    return modules
