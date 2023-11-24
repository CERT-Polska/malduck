from malduck import align_down, procmem, procmempe
from malduck.compression.aplib import aPLib
from malduck.extractor import Extractor


class aPLiebe(Extractor):
    family = "apliebe"
    overrides = "base64",
    yara_rules = "aPLiebe",

    @Extractor.needs_pe
    @Extractor.extractor("apliebe")
    def entrypoint(self, p, hit):
        hit = align_down(hit, 0x200)
        payload = aPLib().decompress(
            p.readv(hit, p.imgend)
        )
        embed_pe = procmem(payload, base=0)
        # Fix headers
        embed_pe.patchp(0, b"MZ")
        embed_pe.patchp(embed_pe.uint32p(0x3C), b"PE")
        # Load patched image into procmempe
        embed_pe = procmempe.from_memory(embed_pe, image=True)
        self.push_procmem(embed_pe)

    @Extractor.extractor
    def strtoint(self, p, hit):
        return {"str_to_int_offs": [hit]}
