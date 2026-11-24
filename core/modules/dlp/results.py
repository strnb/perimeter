from dataclasses import dataclass

# Допустимые значения severity: "critical", "high", "medium"

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
        }
        if self.kb_id:
            res["kb_id"] = self.kb_id
        return res
