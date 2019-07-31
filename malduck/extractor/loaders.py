
import pkgutil
import warnings

from ..py2compat import import_module


def load_modules_onerror(exc, module_name):
    warnings.warn("{} not loaded: {}".format(module_name, exc))


def load_modules(search_path, onerror=load_modules_onerror):
    """
    Loads plugin modules under specified paths

    :param search_path: Path searched for modules
    :type search_path: str
    :param onerror: Exception handler (default: exceptions are generating warnings)
    :return: dict {name: module}
    """
    modules = {}
    for importer, module_name, is_pkg in pkgutil.iter_modules([search_path], "malduck.extractor.modules."):
        if not is_pkg:
            continue
        if module_name in modules:
            warnings.warn("Module collision - {} overriden".format(module_name))
        try:
            modules[module_name] = import_module(importer, module_name)
        except Exception as exc:
            if onerror:
                onerror(exc, module_name)
    return modules
