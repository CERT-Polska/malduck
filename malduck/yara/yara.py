import logging
import os
from typing import Callable, Dict, Optional

import yara

from .match import RulesetMatch, RulesetOffsets, StringMatch
from .rules import YaraRule

log = logging.getLogger(__name__)
OffsetMapper = Callable[[Optional[int], Optional[int]], Optional[int]]


class Yara:
    """
    Represents Yara ruleset. Rules can be compiled from set of files or defined in code.

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
    :param rules: Dictionary of {"namespace": YaraRule} object.
    :type rules: dict
    :param compiled_rules: List of precompiled yara.Rules objects
    :type compiled_rules: list
    :param name: Name of generated rule (default: "r")
    :type name: str
    :param strings: Dictionary representing set of string patterns ({"string_identifier": YaraString or plain str})
    :type strings: dict or str or :class:`YaraString`
    :param condition: Yara rule condition (default: "any of them")
    :type condition: str
    """

    def __init__(
        self,
        rule_paths=None,
        rules=None,
        compiled_rules=None,
        name="r",
        strings=None,
        condition="any of them",
    ) -> None:
        self.rulesets = compiled_rules or []

        if rule_paths:
            self.rulesets.append(yara.compile(filepaths=rule_paths))

        _source_rules = rules or []
        if strings is not None:
            _source_rules.append(
                YaraRule(name=name, strings=strings, condition=condition)
            )

        if _source_rules:
            self.rulesets.append(
                yara.compile(source="\n".join(map(str, _source_rules)))
            )

    @staticmethod
    def from_dir(path, recursive=True, followlinks=True):
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

    def yara_match(self, **kwargs):
        return [match for rules in self.rulesets for match in rules.match(**kwargs)]

    def match(
        self,
        offset_mapper: Optional[OffsetMapper] = None,
        extended: bool = False,
        **kwargs,
    ):
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
        yara_matches = self.yara_match(**kwargs)
        match_class = RulesetMatch if extended else RulesetOffsets
        matches = match_class(
            [
                StringMatch(
                    rule=m.rule,
                    identifier=identifier,
                    offset=offset,
                    content=content,
                    namespace=m.namespace,
                    meta=m.meta,
                    tags=m.tags,
                )
                for m in yara_matches
                for offset, identifier, content in m.strings
            ]
        )
        if offset_mapper:
            matches = matches.remap(offset_mapper)
        return matches
