rule WeakWhat
{
    strings:
        $weaky = "weaky"
        $weaky2 = "weakyx"
        $nonsense_weak = "weak"
        $strongy = "strongy"
    condition:
        any of them
}
