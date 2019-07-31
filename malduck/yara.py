from __future__ import absolute_import

import json
import os
import re
import warnings
import yara

_YARA_RULE_FORMAT = """
rule {name} {{
    strings:
        {strings}
    condition:
        {condition}
}}"""


class Yara(object):
    """
    Represents Yara ruleset. Rules can be compiled from set of files or defined in code (single rule only).

    Most simple rule (with default identifiers left):

    .. code-block:: python

        from malduck.yara import Yara, YaraString

        Yara(strings="MALWR").match(data=b"MALWRMALWARMALWR").r.string == [0, 11]

    Example of more complex rule defined in Python:

    .. code-block:: python

        from malduck.yara import Yara, YaraString

        ruleset = Yara(name="MalwareRule",
        strings={
            "xor_stub": YaraString("This program cannot", xor=True, ascii=True),
            "code_ref": YaraString("E2 34 ?? C8 A? FB", type=YaraString.HEX),
            "mal1": "MALWR",
            "mal2": "MALRW"
        }, condition="( $xor_stub and $code_ref ) or any of ($mal*)")

        # If mal1 or mal2 are matched, they are grouped into "mal"

        # Print appropriate offsets

        match = ruleset.match(data=b"MALWR MALRW")

        if match:
            # ["mal1", "mal", "mal2"]
            print(match.MalwareRule.keys())
            if "mal" in match.MalwareRule:
                # Note: Order of offsets for grouped is arbitrary
                print("mal*", match.MalwareRule["mal"])

    :param rule_paths: Dictionary of {"namespace": "rule_path"}. See also :py:meth:`Yara.from_dir`.
    :type rule_paths: dict
    :param name: Name of generated rule (default: "r")
    :type name: str
    :param strings: Dictionary representing set of string patterns ({"string_identifier": YaraString or plain str})
    :type strings: dict or str or :class:`YaraString`
    :param condition: Yara rule condition (default: "any of them")
    :type condition: str
    """
    def __init__(self, rule_paths=None, name="r", strings=None, condition="any of them"):
        if rule_paths:
            self.rules = yara.compile(filepaths=rule_paths)
            return

        if not strings:
            raise ValueError("No strings specified")

        if isinstance(strings, str) or isinstance(strings, YaraString):
            strings = {"string": strings}

        yara_strings = "\n        ".join([
            "${key} = {value}".format(key=key,
                                      value=str(YaraString(value) if isinstance(value, str) else value))
            for key, value in strings.items()
        ])
        yara_source = _YARA_RULE_FORMAT.format(
            name=name,
            strings=yara_strings,
            condition=condition
        )

        self.rules = yara.compile(source=yara_source)

    @staticmethod
    def from_dir(path, recursive=True):
        """
        Find rules (recursively) in specified path. Supported extensions: *.yar, *.yara

        :param path: Root path for searching
        :type path: str
        :param recursive: Search recursively (default: enabled)
        :type recursive: bool
        :rtype: :class:`Yara`
        """
        rule_paths = {}
        for root, _, files in os.walk(path):
            for fname in files:
                if not fname.endswith(".yar") and not fname.endswith(".yara"):
                    continue
                ruleset_name = os.path.splitext(os.path.basename(fname))[0]
                ruleset_path = os.path.join(root, fname)
                if ruleset_name in rule_paths:
                    warnings.warn("Yara file name collision - {} overriden by {}".format(
                        rule_paths[ruleset_name],
                        ruleset_path
                    ))
                rule_paths[ruleset_name] = ruleset_path
            if not recursive:
                break
        return Yara(rule_paths=rule_paths)

    def match(self, offset_mapper=None, **kwargs):
        """
        Perform matching on file or data block

        :param filepath: Path to the file to be scanned
        :type filepath: str
        :param data: Data to be scanned
        :type data: str
        :param offset_mapper: Offset mapping function. For unmapped region, should returned None.
                              Used by :py:meth:`malduck.procmem.ProcessMemory.yarav`
        :type offset_mapper: function
        :rtype: :class:`YaraMatches`
        """
        return YaraMatches(self.rules.match(**kwargs), offset_mapper=offset_mapper)


class YaraString(object):
    """
    Formatter for Yara string patterns

    :param value: Pattern value
    :type value: str
    :param type: Pattern type (default is :py:attr:`YaraString.TEXT`)
    :type type: :py:attr:`YaraString.TEXT` / :py:attr:`YaraString.HEX` / :py:attr:`YaraString.REGEX`
    :param modifiers: Yara string modifier flags
    """

    TEXT = 0   #: Text string ( `'value' => '"value"'` )
    HEX = 1    #: Hexadecimal string ( `"aa bb cc dd" => '{ aa bb cc dd }'` )
    REGEX = 2  #: Regex string ( `'value' => '/value/'` )

    def __init__(self, value, type=TEXT, **modifiers):
        self.value = value
        self.type = type
        self.modifiers = [k for k, v in modifiers.items() if v is True]

    def __str__(self):
        if self.type == YaraString.TEXT:
            str_value = json.dumps(self.value)
        elif self.type == YaraString.HEX:
            str_value = '{{ {} }}'.format(self.value)
        elif self.type == YaraString.REGEX:
            str_value = '/{}/'.format('\\/'.join(self.value.split("/")))
        else:
            raise ValueError("Unknown YaraString type: {}".format(self.type))
        return str_value + "".join([" " + modifier for modifier in self.modifiers])


class YaraMatches(object):
    """
    Represented matching results. Returned by :py:meth:`Yara.match`.

    Rules can be referenced by both attribute and index.
    """
    def __init__(self, match_results, offset_mapper=None):
        self.matched_rules = {}
        for match in match_results:
            yara_match = YaraMatch(match, offset_mapper=offset_mapper)
            if yara_match:
                self.matched_rules[match.rule] = yara_match

    def keys(self):
        """List of matched rule identifiers"""
        return self.matched_rules.keys()

    def __bool__(self):
        return bool(self.matched_rules)

    def __nonzero__(self):
        return self.__bool__()

    def __contains__(self, item):
        return item in self.matched_rules

    def __getitem__(self, item):
        return self.matched_rules[item]

    def __getattr__(self, item):
        try:
            return self[item]
        except IndexError:
            raise AttributeError()


class YaraMatch(object):
    """
    Represented matching results for rules. Returned by `YaraMatches.<rule>`.

    Strings can be referenced by both attribute and index.
    """
    def __init__(self, match, offset_mapper=None):
        self.rule = self.name = match.rule

        self.offsets = {}

        for off, ident, buf in match.strings:
            real_ident = ident.lstrip("$")
            # Add group identifiers ($str1, $str2 => "str")
            group_ident = re.match(r"^\$(\w+?[a-zA-Z])(\d*)$", ident)
            if not group_ident:
                group_ident = real_ident
            else:
                group_ident = group_ident.group(1)

            # Map offset if offset_mapper is provided
            if offset_mapper is not None:
                off = offset_mapper(off, len(buf))
                if off is None:
                    # Ignore match for unmapped region
                    continue

            # Register offset for full identifier
            if real_ident not in self.offsets:
                self.offsets[real_ident] = []
            self.offsets[real_ident].append(off)

            # Register offset for grouped identifier
            if real_ident != group_ident:
                if group_ident not in self.offsets:
                    self.offsets[group_ident] = []
                self.offsets[group_ident].append(off)

    def keys(self):
        """List of matched string identifiers"""
        return self.offsets.keys()

    def get(self, item):
        """Get matched string offsets or empty list if not matched"""
        return self.offsets.get(item, [])

    def __bool__(self):
        return bool(self.offsets)

    def __nonzero__(self):
        return self.__bool__()

    def __contains__(self, item):
        return item in self.offsets

    def __getitem__(self, item):
        return self.offsets[item]

    def __getattr__(self, item):
        try:
            return self[item]
        except IndexError:
            raise AttributeError()

