import enum
import json
import logging
import textwrap
from typing import Dict, List, Union

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

    def __init__(
        self, value: str, type: YaraStringType = YaraStringType.TEXT, **modifiers: bool
    ) -> None:
        self.value: str = value
        self.type: YaraStringType = type
        self.modifiers: List[str] = [k for k, v in modifiers.items() if v is True]

    def __str__(self) -> str:
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
    """
    Formatter for Yara rule

    :param name: Rule name
    :param strings: Single string or mapping of strings
    :param condition: Rule condition
    """

    def __init__(
        self,
        name: str = "r",
        strings: Union[str, YaraString, Dict[str, Union[str, YaraString]]] = "",
        condition: str = "any of them",
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
            """
        )

    def __str__(self) -> str:
        return self.source
