from malduck import Extractor


class MultiRule(Extractor):
    family = "multistring_v2"
    yara_rules = "MultiString", "MultiString_v2"

    @Extractor.rule("MultiString")
    def multi_string_rule(self, p, matches):
        return (
            "first_string" not in matches
            and "third_string" in matches
            and matches.third_string[0].offset == 0
        )

    @Extractor.rule
    def MultiString_v2(self, p, matches):
        if matches.rule != "MultiString_v2":
            return {
                "matched": ["something wrong happened"]
            }
        if matches.var_string[0].content == b"a0a1b2b3c4c5d6d7e8":
            return {
                "matched": ["v2"]
            }
