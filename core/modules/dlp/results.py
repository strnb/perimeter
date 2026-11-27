from dataclasses import dataclass

# Допустимые значения severity: "critical", "high", "medium"

# Находки-секреты маскируются в отчётах; код-риски (SQLi и т.п.) — нет
NON_SECRET_TYPES = {"sql_injection", "command_injection", "weak_session_id"}

@dataclass
class Finding:
    type: str
    severity: str
    file: str
    line: int
    value: str
    kb_id: str = None
    
    def to_dict(self) -> dict:
        res = {
            "type": self.type,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "value": self.value,
            "secret": self.type not in NON_SECRET_TYPES,
        }
        if self.kb_id:
            res["kb_id"] = self.kb_id
        return res
