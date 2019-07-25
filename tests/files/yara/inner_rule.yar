import "pe"

rule Calc {
    strings:
        $rsrc_name = "WEVT_TEMPLATE" wide
        $calc = "CALC.EXE" wide
    condition:
        all of them
}

rule FourSectionPE {
    condition:
        pe.number_of_sections == 4
}