import functools
import types
import warnings

from ..procmem.procmempe import ProcessMemoryPE

from ..py2compat import add_metaclass


class MetaExtractor(type):
    """
    Metaclass for Extractor. Handles proper registration of decorated extraction methods
    """
    def __new__(cls, name, bases, attrs):
        """
        Collect ext_yara_string and ext_final methods
        """
        klass = type.__new__(cls, name, bases, attrs)

        klass.extractor_methods = dict(getattr(klass, "extractor_methods", {}))
        klass.final_methods = list(getattr(klass, "final_methods", []))

        for name, method in attrs.items():
            if hasattr(method, 'ext_yara_string'):
                klass.extractor_methods[method.ext_yara_string] = name
            if hasattr(method, 'ext_final'):
                klass.final_methods.append(name)

        return klass


class ExtractorBase(object):
    family = None   #: Extracted malware family, automatically added to "family" key for strong extraction methods
    overrides = []  #: Family match overrides another match e.g. citadel overrides zeus

    def __init__(self, parent):
        self.parent = parent  #: ProcmemExtractManager instance

    def push_procmem(self, procmem, **info):
        """
        Push procmem object for further analysis

        :param procmem: ProcessMemory object
        :type procmem: :class:`malduck.procmem.ProcessMemory`
        :param info: Additional info about object
        """
        return self.parent.push_procmem(procmem, **info)

    def push_config(self, config):
        """
        Push partial config (used by :py:meth:`Extractor.handle_yara`)

        :param config: Partial config element
        :type config: dict
        """
        return self.parent.push_config(config, self)

    @property
    def matched(self):
        """
        Returns True if family has been matched so far

        :rtype: bool
        """
        return self.parent.family is not None

    @property
    def collected_config(self):
        """
        Shows collected config so far (useful in "final" extractors)

        :rtype: dict
        """
        return self.parent.collected_config

    @property
    def globals(self):
        """
        Container for global variables associated with analysis

        :rtype: dict
        """
        return self.parent.globals


@add_metaclass(MetaExtractor)
class Extractor(ExtractorBase):
    """
    Base class for extractor modules

    Following parameters need to be defined:

    * :py:attr:`family` (:py:attr:`extractor.ExtractorBase.family`)
    * :py:attr:`yara_rules`
    * :py:attr:`overrides` (optional, :py:attr:`extractor.ExtractorBase.overrides`)

    Example extractor code for Citadel:

    .. code-block:: Python

        from ripper import Extractor

        class Citadel(Extractor):
            family = "citadel"
            yara_rules = ["citadel"]
            overrides = ["zeus"]

            @Extractor.extractor("briankerbs")
            def citadel_found(self, p, addr):
                log.info('[+] `Coded by Brian Krebs` str @ %X' % addr)
                return True

            @Extractor.extractor
            def cit_login(self, p, addr):
                log.info('[+] Found login_key xor @ %X' % addr)
                hit = p.uint32v(addr + 4)
                print(hex(hit))
                if p.is_addr(hit):
                    return {'login_key': p.asciiz(hit)}

                hit = p.uint32v(addr + 5)
                print(hex(hit))
                if p.is_addr(hit):
                    return {'login_key': p.asciiz(hit)}

    .. py:decoratormethod:: Extractor.extractor

        Decorator for string-based extractor methods.
        Method is called each time when string with the same identifier as method name has matched

        Extractor can be called for many number-suffixed strings e.g. `$keyex1` and `$keyex2` will call `keyex` method.

    .. py:decoratormethod:: Extractor.extractor(string_or_method, final=False)

        Specialized `@extractor` variant

        :param string_or_method:
            If method name doesn't match the string identifier
            pass yara string identifier as decorator argument
        :type string_or_method: str
        :param final:
            Extractor will be called whenever Yara rule has been matched,
            but always after string-based extractors
        :type final: bool

    .. py:decoratormethod:: Extractor.final

        Decorator for final extractors, called after regular extraction methods.

        .. code-block:: Python

            from ripper import Extractor

            class Evil(Extractor):
                yara_rules = ["evil"]
                family = "evil"

                ...

                @Extractor.needs_pe
                @Extractor.final
                def get_config(self, p):
                    cfg = {"urls": self.get_cncs_from_rsrc(p)}
                    if "role" not in self.collected_config:
                        cfg["role"] = "loader"
                    return cfg

    .. py:decoratormethod:: Extractor.weak

        Use this decorator for extractors when successful extraction is not sufficient to mark family as matched.

        All "weak configs" will be flushed when "strong config" appears.

    .. py:decoratormethod:: Extractor.needs_pe

        Use this decorator for extractors that need PE instance. (:class:`malduck.procmem.ProcessMemoryPE`)

    """
    yara_rules = []  #: Names of Yara rules for which handle_yara is called

    def on_error(self, exc, method_name):
        """
        Handler for all Exception's throwed by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param method_name: Name of method which throwed exception
        :type method_name: str
        """
        import traceback
        warnings.warn("{}.{} throwed exception: {}".format(
            self.__class__.__name__,
            method_name,
            traceback.format_exc()))

    def handle_yara(self, p, match):
        """
        Override this if you don't want to use decorators and customize ripping process
        (e.g. yara-independent, brute-force techniques)

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param match: Found yara matches for this family
        :type match: List[:class:`malduck.yara.YaraMatch`]
        """
        # Call string-based extractors
        for identifier, method_name in self.extractor_methods.items():
            if identifier not in match:
                continue
            method = getattr(self, method_name)
            for va in match[identifier]:
                try:
                    if hasattr(method, "ext_needs_pe"):
                        # If extractor explicitly needs this and p is raw procmem: find PE for specified offset
                        p_pe = ProcessMemoryPE.from_memory(p, base=p.findmz(va)) \
                            if not isinstance(p, ProcessMemoryPE) else p
                        method(p_pe, va)
                    else:
                        method(p, va)
                except Exception as exc:
                    self.on_error(exc, method_name)

        # Call final extractors
        for method_name in getattr(self, "final_methods", []):
            method = getattr(self, method_name)
            if hasattr(method, "ext_needs_pe") and not isinstance(p, ProcessMemoryPE):
                warnings.warn('Method {}.{} not called because object is not ProcessMemoryPE'.format(
                    self.__class__.__name__, method_name))
                continue
            try:
                method(p)
            except Exception as exc:
                self.on_error(exc, method_name)

    # Extractor method decorators

    @staticmethod
    def needs_pe(method):
        Extractor._set_extattr(method, "needs_pe")
        return method

    @staticmethod
    def weak(method):
        Extractor._set_extattr(method, "weak")
        return method

    @staticmethod
    def extractor(string_or_method=None, final=False):
        if final and string_or_method:
            raise ValueError("String identifier is unnecessary for final methods")

        def extractor_wrapper(method):
            @functools.wraps(method)
            def extractor_method(self, *args, **kwargs):
                # Get config from extractor method
                config = method(self, *args, **kwargs)
                if config:
                    # If method is "strong" - "family" key will be automatically added
                    if not getattr(method, "ext_weak", False):
                        # If method returns True - family matched
                        if config is True:
                            config = {}
                        # Add "family" for strong configs
                        if self.family and "family" not in config:
                            config["family"] = self.family
                    self.push_config(config)

            # If there is no alias for Yara string - use method name
            if not string_or_method or isinstance(string_or_method, types.FunctionType):
                yara_string = method.__name__
            else:
                yara_string = string_or_method

            # Final extractors doesn't match specific string
            if not final:
                Extractor._set_extattr(extractor_method, "yara_string", yara_string)
            else:
                Extractor._set_extattr(extractor_method, "final")
            return extractor_method

        if isinstance(string_or_method, types.FunctionType):
            return extractor_wrapper(string_or_method)
        else:
            return extractor_wrapper

    @staticmethod
    def final(method):
        return Extractor.extractor(final=True)(method)

    # Internals

    @staticmethod
    def _is_extattr_set(method, flag):
        """
        Check whether method is marked using extra flag
        """
        return hasattr(method, "ext_" + flag)

    @staticmethod
    def _set_extattr(method, flag, value=True):
        if flag == "final":
            if Extractor._is_extattr_set(method, "yara_string") or Extractor._is_extattr_set(method, "final"):
                raise ValueError("Extractor can't be used both as yara handler and final")
        setattr(method, "ext_" + flag, value)
