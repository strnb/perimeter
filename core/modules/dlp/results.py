from dataclasses import dataclass

@dataclass
class Finding:
    type: str
    severity: str
    file: str
    line: int
    value: str

    def to_dict(self):
        return {
            "type": self.type,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "value": self.value,
        }