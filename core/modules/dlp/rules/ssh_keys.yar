rule SSH_Private_Key {
    strings:
        $rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $dsa     = "-----BEGIN DSA PRIVATE KEY-----"
        $ec      = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}