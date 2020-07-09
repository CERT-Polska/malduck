rule DigitGroup {
    strings:
        $grouped_00 = "digit_group_confirmed0"
        $grouped_1  = "1digit_group_confirmed"
        $grouped2   = "digit_group_confirmed02"
        $grouped03  = "31digit_group_confirmed"
        $ungrouped  = "digit_group_unconfirmed"
    condition:
        any of them
}