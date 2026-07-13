from .match import RuleMatch, RuleOffsets, RulesetMatch, RulesetOffsets, StringMatch
from .rules import YaraRule, YaraString, YaraStringType
from .yara import Yara

# Legacy aliases for backward compatibility
YaraMatches = RulesetOffsets
YaraMatch = RuleOffsets
YaraStringMatch = StringMatch

__all__ = [
    "YaraRule",
    "YaraString",
    "YaraStringType",
    "Yara",
    "RulesetMatch",
    "RulesetOffsets",
    "RuleMatch",
    "RuleOffsets",
    "StringMatch",
    "YaraMatches",
    "YaraMatch",
    "YaraStringMatch",
]
