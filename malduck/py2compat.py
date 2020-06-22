# Python 2/3 compatibility module
import sys
from six import (
    add_metaclass,
    integer_types,
    string_types,
    binary_type,
    PY3,
    int2byte,
    indexbytes,
    text_type,
)
from six import iterbytes as iterbytes_ord

if PY3:
    from builtins import int as long
else:
    from __builtin__ import long

__all__ = [
    "add_metaclass",
    "integer_types",
    "string_types",
    "binary_type",
    "int2byte",
    "indexbytes",
    "text_type",
    "iterbytes_ord",
    "long",
    "PY3",
    "is_integer",
    "is_string",
    "is_binary",
    "iterbytes",
    "ensure_bytes",
    "ensure_string",
    "import_module_by_finder",
]


def is_integer(v):
    return isinstance(v, integer_types)


def is_string(v):
    return isinstance(v, string_types)


def is_binary(v):
    return isinstance(v, binary_type)


def iterbytes(b):
    """Returns single bytes rather than sequence of ints"""
    return [b[i : i + 1] for i in range(len(b))]


def ensure_bytes(v):
    """
    Py2: str -> str; unicode -> str
    Py3: bytes -> bytes; str -> bytes
    """
    return v.encode("utf8") if not isinstance(v, binary_type) else v


def ensure_string(v):
    """
    Py2: str -> str; unicode -> unicode
    Py3: bytes -> str; str -> str
    """
    if PY3 and isinstance(v, binary_type):
        return v.decode("utf8")
    elif isinstance(v, string_types):
        return v
    else:
        raise TypeError("v should be str/unicode/bytes instead of " + str(type(v)))


def import_module_by_finder(finder, module_name):
    """
    Imports module from arbitrary path using importer returned by pkgutil.iter_modules
    """
    if module_name in sys.modules:
        return sys.modules[module_name]
    if PY3:
        import importlib.util

        # https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
        module_spec = finder.find_spec(module_name)
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[module_name] = module
        try:
            module = module_spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[module_name]
            raise
    else:
        # These days it was pretty simple
        module = finder.find_module(module_name).load_module(module_name)
    return module
