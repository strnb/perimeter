rule Hardcoded_Password_Assignment {
    strings:
        $p1 = /password\s*=+\s*["'][^\s"';,]{3,}/   nocase
        $p2 = /passwd\s*=+\s*["'][^\s"';,]{3,}/     nocase
        $p3 = /secret\s*=+\s*["'][^\s"';,]{3,}/     nocase
        $p4 = /api_key\s*=+\s*["'][^\s"';,]{3,}/    nocase
        $p5 = /apikey\s*=+\s*["'][^\s"';,]{3,}/     nocase
        $p6 = /pwd\s*=+\s*["'][^\s"';,]{3,}/        nocase
    condition:
        any of them
}

rule Hardcoded_Password_Comparison {
    strings:
        $p1 = /[Pp]assword\s*(==|===|\.equals\()\s*["'][^"']{3,}["']/
        $p2 = /[Pp]asswd\s*(==|===|\.equals\()\s*["'][^"']{3,}["']/
        $p3 = /[Rr]aw[Pp]assword\s*(==|===)\s*["'][^"']{3,}["']/
        $p4 = /[Pp]in\s*(==|===)\s*["'][0-9]{3,}["']/
        $p5 = /[Ss]ecret\s*(==|===)\s*["'][^"']{3,}["']/
    condition:
        any of them
}

rule Hardcoded_Password_In_Call {
    strings:
        $p1 = /[Aa]uth\w*\s*\([^)]*["'][^"']{3,}["'][^)]*\)/
        $p2 = /[Cc]heck[Pp]assword\s*\([^)]*["'][^"']{3,}["']/
        $p3 = /\bauthenticate\s*\([^)]*["'][^"']{3,}["']/  nocase
    condition:
        any of them
}

// Правило 4 — без вложенных циклов, используем proximity через regex
// Ищем паттерн "admin/root" + слабый пароль в одной строке напрямую
rule Hardcoded_Admin_Credentials {
    strings:
        // Сравнение логина с admin/root рядом с захардкоженным паролем в одной строке
        $combo1 = /["']admin["'].*["'](12345|password|123456|qwerty|admin|1234|0000)["']/  nocase
        $combo2 = /["']root["'].*["'](12345|password|123456|qwerty|admin|1234|0000)["']/   nocase
        // Или в обратном порядке — сначала пароль, потом логин
        $combo3 = /["'](12345|password|123456|qwerty)["'].*["']admin["']/  nocase
        $combo4 = /["'](12345|password|123456|qwerty)["'].*["']root["']/   nocase
    condition:
        any of them
}

rule Hardcoded_Config_Credential {
    strings:
        $p1 = /DB_PASSWORD\s*[=:]\s*["'][^\s"']{3,}/   nocase
        $p2 = /DB_PASS\s*[=:]\s*["'][^\s"']{3,}/       nocase
        $p3 = /DATABASE_PASSWORD\s*[=:]\s*["'][^\s"']{3,}/ nocase
        $p4 = /MYSQL_PWD\s*[=:]\s*["'][^\s"']{3,}/     nocase
        $p5 = /MYSQL_PASSWORD\s*[=:]\s*["'][^\s"']{3,}/ nocase
        $p6 = /POSTGRES_PASSWORD\s*[=:]\s*["'][^\s"']{3,}/ nocase
        $p7 = /REDIS_PASSWORD\s*[=:]\s*["'][^\s"']{3,}/ nocase
        $p8 = /APP_SECRET\s*[=:]\s*["'][^\s"']{3,}/    nocase
        $p9 = /AUTH_TOKEN\s*[=:]\s*["'][^\s"']{3,}/    nocase
    condition:
        any of them
}
