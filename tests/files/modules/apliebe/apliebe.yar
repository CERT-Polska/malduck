rule aPLiebe
{
    strings:
        $apliebe = { 44 4f 7e 53 03 6d 6f }
        $strtoint = "StrToIntExA"
    condition:
        any of them
}
