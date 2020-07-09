from malduck import Extractor


class MultiString(Extractor):
    family = "multistring"
    yara_rules = "MultiString",

    @Extractor.string("first_string", "second_string")
    def first_strings(self, p, addr, match):
        if p.readv(addr, len(match.content)) == match.content:
            return {
                "first": [match.content]
            }

    @Extractor.weak
    @Extractor.string
    def third_string(self, p, addr, match):
        if p.readv(addr, len(match.content)) == match.content:
            return {
                "third": [match.content]
            }
