rule configmerge {
    strings:
        $calc_exe_0x80000 = { E5 ED 2D 7A 0E 1D 32 DB 8E 73 56 1E 1C 95 93 A4 }
    condition:
        any of them
}