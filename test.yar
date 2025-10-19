rule test_wachizungu
{
    meta:
        author = "@wachizungu"
        info = "Part of test - UPDATE"

    strings:
        $a1 = "DELAY"
        $a3 = "STRING"
    condition:
        1 of them
}