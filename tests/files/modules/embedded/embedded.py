from malduck.extractor import Extractor
from malduck import base64, procmempe

@Extractor.yara(r"""
rule embedded_test
{
    strings:
        $start = "Start with this and nothing else..."
    condition:
        all of them and $start at 0
}
""")
class Embedded(Extractor):
    family = "embedded"

    @Extractor.final
    def embedded(self, p):
        return {"embedded": True}
