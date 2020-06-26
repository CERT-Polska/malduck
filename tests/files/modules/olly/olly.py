from malduck.extractor import Extractor


class Ollydbg(Extractor):
    yara_rules = "WhatOllyIs", "WhatOllyIsNot"
    family = "ollydbg"

    @Extractor.extractor
    def olly_is(self, p, hit):
        return {"olly": [p.asciiz(hit).decode("utf8")]}

    @Extractor.extractor("olly_is_not")
    def olly_isnt(self, p, hit):
        return {"olly": [p.asciiz(hit).decode("utf8")]}

    @Extractor.rule("WhatOllyIsNot")
    def olly_isnt_rule(self, p, matches):
        return {"matches": list(matches.keys())}
