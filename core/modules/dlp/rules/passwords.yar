rule Hardcoded_Password {
    strings:
        $p1 = "password=" nocase
        $p2 = "passwd="   nocase
        $p3 = "secret="   nocase
        $p4 = "api_key="  nocase
        $p5 = "apikey="   nocase
    condition:
        any of them
}