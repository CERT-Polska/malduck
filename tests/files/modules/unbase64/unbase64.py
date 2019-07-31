from malduck.extractor import Extractor
from malduck import base64, procmempe


class Unbase64(Extractor):
    yara_rules = ["Based64Binary"]
    family = "base64"

    @Extractor.final
    def unbase(self, p):
        contents = base64.decode(p.readp(0))
        extracted = procmempe(contents, detect_image=True)
        self.push_procmem(extracted)
        return {"base64": True}
