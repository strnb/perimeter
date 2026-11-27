rule Netrc_File {
    meta:
        type = "password"
        severity = "high"
        kb_id = "VULN-006"
    strings:
        $machine = "machine " nocase
        $login = "login " nocase
        $password = "password " nocase
    condition:
        all of them
}
