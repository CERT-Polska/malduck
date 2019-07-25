rule DummyRoachRule {
    strings:
        $region_bc1 = { 42 42 42 42 [24] 43 43 43 43 }
        $region_bc2 = { 41 41 41 41 [24] 42 42 42 42 }
    condition:
        all of ($region_bc*)
}