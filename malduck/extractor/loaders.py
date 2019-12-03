
import logging
import pkgutil

from ..py2compat import import_module

log = logging.getLogger(__name__)


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
    for importer, module_name, is_pkg in pkgutil.iter_modules([search_path], "malduck.extractor.modules."):
        if not is_pkg:
            continue
        if module_name in modules:
            log.warning("Module collision - {} overridden".format(module_name))
        try:
            modules[module_name] = import_module(importer, module_name)
        except Exception as exc:
            if onerror:
                onerror(exc, module_name)
    return modules
