rule Based64Binary
{
    strings:
        $tv = "TVq"
        $nullbytes = "AAAAAAAAAAAAAAAAAAA"
    condition:
        all of them
}