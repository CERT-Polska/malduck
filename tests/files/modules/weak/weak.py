from malduck.extractor import Extractor


class Weaky(Extractor):
    yara_rules = "WeakWhat",
    family = "weaky"

    @Extractor.weak
    @Extractor.extractor
    def weaky(self, p, hit):
        return {"weak": True}

    @Extractor.weak
    @Extractor.extractor
    def weaky2(self, p, hit):
        return {"weaky": True}

    @Extractor.extractor
    def strongy(self, p, hit):
        return True

    @Extractor.weak
    @Extractor.extractor
    def nonsense_weak(self, p, hit):
        return True
