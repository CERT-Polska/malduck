import enum
import json
import logging
import os
import textwrap
import yara
from typing import Union, Dict, Optional, List

log = logging.getLogger(__name__)

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

class YaraRule:
    def __init__(
        self,
        name: str = "r",
        strings: Union[str, YaraString, Dict[str, Union[str, YaraString]]] = "",
        condition: str = "any of them"
    ) -> None:
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
        self.source = textwrap.dedent(
            f"""
            rule {name} {{
                strings:
                    {yara_strings}
                condition:
                    {condition}
            }}
        """)

    def __str__(self) -> str:
        return self.source

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
        self,
        rule_paths: Optional[Dict[str, str]] = None,
        rules: Optional[List[Union[str, YaraRule]]] = None,
        compiled_rules: Optional[List[yara.Rules]] = None,
        name: str = "r",
        strings: Optional[Union[str, YaraString, Dict[str, Union[str, YaraString]]]] = None,
        condition: str = "any of them"
    ) -> None:
        self.rulesets = compiled_rules or []

        if rule_paths:
            self.rulesets.append(yara.compile(filepaths=rule_paths))

        _source_rules = rules or []
        if strings is not None:
            _source_rules.append(YaraRule(name=name, strings=strings, condition=condition))

        if _source_rules:
            self.rulesets.append(yara.compile(source="\n".join(map(str, _source_rules))))

    @staticmethod
    def from_dir(path: str, recursive: bool = True, followlinks: bool = True) -> "Yara":
        """
        Find rules (recursively) in specified path. Supported extensions: \\*.yar, \\*.yara

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

    def match(self, **kwargs) -> List[yara.Match]:
        return [
            match
            for rules in self.rulesets
            for match in rules.match(**kwargs)
        ]
