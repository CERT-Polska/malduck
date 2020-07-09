rule MultiString
{
    strings:
        $first_string1 = "fIrSt string"
        $first_string2 = "FiRsT string"
        $second_string = "second string" nocase
        $third_string = "ThIrD string"
    condition:
        any of them
}

rule MultiString_v2
{
    strings:
        $var_string = { 61 30 61 31 62 [2-6] 63 (65 | 35) 64 36 64 37 65 38 }
        $fourth_string = "FoUrTh string"
    condition:
        all of them
}
