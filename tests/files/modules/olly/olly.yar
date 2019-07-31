rule WhatOllyIs
{
    strings:
        $olly_is1 = " - OllyDbg is a"
        $olly_is2 = " - OllyDbg is in"
        $olly_is3 = " - OllyDbg is something"
    condition:
        any of them
}

rule WhatOllyIsNot
{
    strings:
        $olly_is_not1 = " - OllyDbg is not"
    condition:
        all of them
}