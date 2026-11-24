rule AWS_Access_Key {
    strings:
        $key = /AKIA[0-9A-Z]{16}/
    condition:
        $key
}