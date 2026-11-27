rule AWS_Credentials_File {
    meta:
        type = "aws_credentials"
        severity = "critical"
        kb_id = "VULN-007"
    strings:
        $key = "aws_access_key_id" nocase
        $secret = "aws_secret_access_key" nocase
    condition:
        all of them
}
