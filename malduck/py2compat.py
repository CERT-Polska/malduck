from six import add_metaclass, integer_types, string_types, binary_type, PY3, int2byte, indexbytes, text_type
from six import iterbytes as iterbytes_ord

if PY3:
    from builtins import int as long
else:
    from __builtin__ import long


def is_integer(v):
    return isinstance(v, integer_types)


def is_string(v):
    return isinstance(v, string_types)


def is_binary(v):
    return isinstance(v, binary_type)


def iterbytes(b):
    """Returns single bytes rather than sequence of ints"""
    return [b[i:i+1] for i in range(len(b))]


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
        raise TypeError('v should be str/unicode/bytes instead of ' + str(type(v)))


def import_module(importer, module_name):
    """
    Imports module from arbitrary path using importer returned by pkgutil.iter_modules
    """
    if PY3:
        module = importer.find_spec(module_name).loader.load_module()
    else:
        module = importer.find_module(module_name).load_module(module_name)
    return module
