from collections import namedtuple, defaultdict
from typing import Callable, Dict, Optional, Tuple, TypeVar

import enum
import json
import logging
import os
import re
import textwrap
import yara

__all__ = [
    "Yara",
    "YaraString",
    "YaraRulesetMatch",
    "YaraRulesetOffsets",
    "YaraRuleMatch",
    "YaraRuleOffsets",
    "YaraStringMatch",
    "YaraMatches",
    "YaraMatch",
]

log = logging.getLogger(__name__)

T = TypeVar("T")
OffsetMapper = Callable[[Optional[int], Optional[int]], Optional[int]]

YaraRulesString = Tuple[int, str, bytes]


class _Mapper:
    def __init__(self, elements, default=None):
        self.elements = elements
        self.default = default

    def keys(self):
        """List of matched string identifiers"""
        return self.elements.keys()

    def get(self, item):
        """Get matched string offsets or default if not matched"""
        return self.elements.get(item, self.default)

    def __bool__(self):
        return bool(self.elements)

    def __nonzero__(self):
        return self.__bool__()

    def __contains__(self, item):
        return item in self.elements

    def __getitem__(self, item):
        return self.elements[item]

    def __getattr__(self, item):
        try:
            return self[item]
        except IndexError:
            raise AttributeError()


class Yara:
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
                # Note: Order of offsets for grouped strings is undetermined
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

    def __init__(
        self, rule_paths=None, name="r", strings=None, condition="any of them"
    ):
        if rule_paths:
            self.rules = yara.compile(filepaths=rule_paths)
            return

        if not strings:
            raise ValueError("No strings specified")

        if isinstance(strings, str) or isinstance(strings, YaraString):
            strings = {"string": strings}

        yara_strings = "\n        ".join(
            [
                f"${key} = {str(YaraString(value) if isinstance(value, str) else value)}"
                for key, value in strings.items()
            ]
        )
        yara_source = textwrap.dedent(
            f"""
            rule {name} {{
                strings:
                    {yara_strings}
                condition:
                    {condition}
            }}
        """
        )

        self.rules = yara.compile(source=yara_source)

    @staticmethod
    def from_dir(path, recursive=True, followlinks=True):
        """
        Find rules (recursively) in specified path. Supported extensions: *.yar, *.yara

        :param path: Root path for searching
        :type path: str
        :param recursive: Search recursively (default: enabled)
        :type recursive: bool
        :param followlinks: Follow symbolic links (default: enabled)
        :type followlinks: bool
        :rtype: :class:`Yara`
        """
        rule_paths: Dict[str, str] = {}
        for root, _, files in os.walk(path, followlinks=followlinks):
            for fname in files:
                if not fname.endswith(".yar") and not fname.endswith(".yara"):
                    continue
                ruleset_name = os.path.splitext(os.path.basename(fname))[0]
                ruleset_path = os.path.join(root, fname)
                if ruleset_name in rule_paths:
                    log.warning(
                        f"Yara file name collision - {rule_paths[ruleset_name]} "
                        f"overridden by {ruleset_path}"
                    )
                rule_paths[ruleset_name] = ruleset_path
            if not recursive:
                break
        return Yara(rule_paths=rule_paths)

    def match(self, offset_mapper=None, extended=False, **kwargs):
        """
        Perform matching on file or data block

        :param filepath: Path to the file to be scanned
        :type filepath: str
        :param data: Data to be scanned
        :type data: str
        :param offset_mapper: Offset mapping function. For unmapped region, should returned None.
                              Used by :py:meth:`malduck.procmem.ProcessMemory.yarav`
        :type offset_mapper: function
        :param extended: Returns extended information about matched strings and rules
        :type extended: bool (optional, default False)
        :rtype: :class:`malduck.yara.YaraRulesetOffsets` or :class:`malduck.yara.YaraRulesetMatches`
                if extended is set to True
        """
        matches = YaraRulesetMatch(
            self.rules.match(**kwargs), offset_mapper=offset_mapper
        )
        return YaraRulesetOffsets(matches) if not extended else matches


class YaraStringType(enum.IntEnum):
    TEXT = 0
    HEX = 1
    REGEX = 2


class YaraString:
    """
    Formatter for Yara string patterns

    :param value: Pattern value
    :type value: str
    :param type: Pattern type (default is :py:attr:`YaraString.TEXT`)
    :type type: :py:attr:`YaraString.TEXT` / :py:attr:`YaraString.HEX` / :py:attr:`YaraString.REGEX`
    :param modifiers: Yara string modifier flags
    """

    TEXT = YaraStringType.TEXT
    HEX = YaraStringType.HEX
    REGEX = YaraStringType.REGEX

    def __init__(self, value, type=YaraStringType.TEXT, **modifiers):
        self.value = value
        self.type = type
        self.modifiers = [k for k, v in modifiers.items() if v is True]

    def __str__(self):
        if self.type == YaraStringType.TEXT:
            str_value = json.dumps(self.value)
        elif self.type == YaraStringType.HEX:
            str_value = f"{{ {self.value} }}"
        elif self.type == YaraStringType.REGEX:
            str_regex = "\\/".join(self.value.split("/"))
            str_value = f"/{str_regex}/"
        else:
            raise ValueError(f"Unknown YaraString type: {self.type}")
        return str_value + "".join([" " + modifier for modifier in self.modifiers])


class YaraRulesetMatch(_Mapper):
    """
    Yara ruleset matches. Returned by :py:meth:`Yara.match`.

    Rules can be referenced by both attribute and index.
    """

    def __init__(self, matches, offset_mapper=None):
        self._matches = matches
        super().__init__(elements=self._map_matches(matches, offset_mapper))

    def _map_matches(self, matches, offset_mapper):
        mapped_matches = [
            (match, self._map_strings(match.strings, offset_mapper))
            for match in matches
        ]
        return {
            match.rule: YaraRuleMatch(
                match.rule, strings, match.meta, match.namespace, match.tags
            )
            for match, strings in mapped_matches
            if strings
        }

    def _map_strings(self, strings, offset_mapper):
        mapped_strings = defaultdict(list)
        for offset, identifier, content in strings:
            # Get identifier without "$" and group identifier
            real_ident, group_ident = self._parse_string_identifier(identifier)
            # Map offset if offset_mapper is provided
            if offset_mapper is not None:
                _offset = offset_mapper(offset, len(content))
                if _offset is None:
                    # Ignore match for unmapped region
                    continue
                offset = _offset
            # Register offset for full identifier
            mapped_strings[real_ident].append(
                YaraStringMatch(real_ident, offset, content)
            )
            # Register offset for grouped identifier
            if real_ident != group_ident:
                mapped_strings[group_ident].append(
                    YaraStringMatch(real_ident, offset, content)
                )
        return mapped_strings

    def _parse_string_identifier(self, identifier):
        real_ident = identifier.lstrip("$")
        # Add group identifiers ($str1, $str2 => "str")
        match_ident = re.match(r"^\$(\w+?[a-zA-Z])_?(\d*)$", identifier)
        group_ident = match_ident.group(1) if match_ident else real_ident
        return real_ident, group_ident

    def remap(self, offset_mapper=None):
        return YaraRulesetMatch(self._matches, offset_mapper=offset_mapper)


class YaraRulesetOffsets(_Mapper):
    def __init__(self, matches):
        self._matches = matches
        super().__init__(
            elements={k: YaraRuleOffsets(v) for k, v in matches.elements.items()}
        )

    def remap(self, offset_mapper=None):
        return YaraRulesetOffsets(self._matches.remap(offset_mapper))


YaraStringMatch = namedtuple("YaraStringMatch", ["identifier", "offset", "content"])


class YaraRuleMatch(_Mapper):
    """
    Rule matches. Returned by `YaraMatches.<rule>`.

    Strings can be referenced by both attribute and index.
    """

    def __init__(self, rule, strings, meta, namespace, tags):
        self.rule = self.name = rule
        self.meta = meta
        self.namespace = namespace
        self.tags = tags
        super().__init__(
            elements={k: sorted(v, key=lambda s: s.offset) for k, v in strings.items()}
        )

    def get_offsets(self, string):
        return [match.offset for match in self.elements.get(string, [])]


class YaraRuleOffsets(_Mapper):
    def __init__(self, rule_match):
        self.rule = self.name = rule_match.rule
        super().__init__(
            {
                identifier: [match.offset for match in string_matches]
                for identifier, string_matches in rule_match.elements.items()
            },
            default=[],
        )


# Legacy aliases, don't use them in new code
YaraMatches = YaraRulesetOffsets
YaraMatch = YaraRuleOffsets
