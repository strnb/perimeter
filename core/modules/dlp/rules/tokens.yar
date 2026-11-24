rule API_Token {
    strings:
        $github = "ghp_"
        $openai = "sk-"
        $jwt    = "eyJ"
    condition:
        any of them
}