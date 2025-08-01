from malduck.extractor import Extractor


class ConfigMerge(Extractor):
    yara_rules = "configmerge",
    family = "ConfigMerge"

    @Extractor.final
    def final(self, p):
        return {
            "constant": "CONST",
            "mem_types": [str(type(p))],
            "dict": {
                hex(p.imgbase): "imagebase"
            }
        }
