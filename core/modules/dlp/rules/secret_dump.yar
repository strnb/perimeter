rule Secret_Dump {
    meta:
        type = "secret_dump"
        severity = "high"
        kb_id = "VULN-042"
    strings:
        // Пять и более присваиваний секретов в одном файле — это дамп, а не строка кода
        $assign = /(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)[ \t]*[:=][ \t]*[^\s:]+/ nocase
    condition:
        #assign >= 5
}
