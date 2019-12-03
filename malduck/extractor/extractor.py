import functools
import logging

from ..procmem import ProcessMemoryPE, ProcessMemoryELF

from ..py2compat import add_metaclass

log = logging.getLogger(__name__)


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

        if type(getattr(klass, "yara_rules")) not in (list, tuple):
            raise TypeError("'yara_rules' field must be 'list' or 'tuple' in {}".format(str(name)))

        for name, method in attrs.items():
            if isinstance(method, ExtractorMethod):
                if method.final:
                    klass.final_methods.append(name)
                else:
                    if method.yara_string in klass.extractor_methods:
                        raise TypeError('There can be only one extractor method '
                                        'for "{}" string'.format(method.yara_string))
                    klass.extractor_methods[method.yara_string] = name

        return klass


class ExtractorMethod(object):
    """
    Represents registered extractor method
    """
    def __init__(self, method):
        self.method = method
        self.weak = False
        self.needs_exec = None
        self.final = False
        self.yara_string = method.__name__
        functools.update_wrapper(self, method)

    def __call__(self, extractor, *args, **kwargs):
        # Get config from extractor method
        config = self.method(extractor, *args, **kwargs)
        if not config:
            return
        # If method returns True - family matched (for non-weak methods)
        if config is True:
            config = {}
        # If method is "strong" - "family" key will be automatically added
        if not self.weak and extractor.family and "family" not in config:
            config["family"] = extractor.family
        # If config is not empty - push it
        if config:
            extractor.push_config(config)


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

    @property
    def log(self):
        """
        Logger instance for Extractor methods

        :return: :class:`logging.Logger`
        """
        return logging.getLogger("{}.{}".format(
            self.__class__.__module__,  # should be malduck.extractor.modules (see malduck.extractor.loaders)
            self.__class__.__name__))


@add_metaclass(MetaExtractor)
class Extractor(ExtractorBase):
    """
    Base class for extractor modules

    Following parameters need to be defined:

    * :py:attr:`family` (see :py:attr:`extractor.ExtractorBase.family`)
    * :py:attr:`yara_rules`
    * :py:attr:`overrides` (optional, see :py:attr:`extractor.ExtractorBase.overrides`)

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

    .. py:decoratormethod:: Extractor.needs_elf

        Use this decorator for extractors that need ELF instance. (:class:`malduck.procmem.ProcessMemoryELF`)

    """
    yara_rules = ()  #: Names of Yara rules for which handle_yara is called

    def on_error(self, exc, method_name):
        """
        Handler for all Exception's throwed by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param method_name: Name of method which throwed exception
        :type method_name: str
        """
        self.parent.on_extractor_error(exc, self, method_name)

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
                    if method.needs_exec and not isinstance(p, method.needs_exec):
                        log.debug("Omitting %s.%s for %s@%x - %s is not %s",
                                  self.__class__.__name__,
                                  method_name,
                                  identifier,
                                  va,
                                  p.__class__.__name__,
                                  method.needs_exec.__name__)
                        continue
                    log.debug("Trying %s.%s for %s@%x",
                              self.__class__.__name__,
                              method_name,
                              identifier,
                              va)
                    method(self, p, va)
                except Exception as exc:
                    self.on_error(exc, method_name)

        # Call final extractors
        for method_name in self.final_methods:
            method = getattr(self, method_name)
            if method.needs_exec and not isinstance(p, method.needs_exec):
                log.debug("Omitting %s.%s (final) - %s is not %s",
                          self.__class__.__name__,
                          method_name,
                          p.__class__.__name__,
                          method.needs_exec.__name__)
                continue
            log.debug("Trying %s.%s (final)",
                      self.__class__.__name__,
                      method_name)
            try:
                method(self, p)
            except Exception as exc:
                self.on_error(exc, method_name)

    # Extractor method decorators

    @staticmethod
    def needs_pe(method):
        method = Extractor._extractor_method(method)
        method.needs_exec = ProcessMemoryPE
        return method

    @staticmethod
    def needs_elf(method):
        method = Extractor._extractor_method(method)
        method.needs_exec = ProcessMemoryELF
        return method

    @staticmethod
    def weak(method):
        method = Extractor._extractor_method(method)
        method.weak = True
        return method

    @staticmethod
    def extractor(string_or_method=None, final=False):
        if final and string_or_method:
            raise ValueError("String identifier is unnecessary for final methods")

        def extractor_wrapper(method):
            extractor_method = Extractor._extractor_method(method)
            # If there is string provided, use it as yara_string
            if string_or_method and not callable(string_or_method):
                extractor_method.yara_string = string_or_method
            extractor_method.final = final
            return extractor_method

        if callable(string_or_method):
            return extractor_wrapper(string_or_method)
        else:
            return extractor_wrapper

    @staticmethod
    def final(method):
        return Extractor.extractor(final=True)(method)

    # Internals

    @staticmethod
    def _extractor_method(method):
        # Check whether method is already wrapped by ExtractorMethod
        if isinstance(method, ExtractorMethod):
            return method
        else:
            return ExtractorMethod(method)
