"""Thin wrappers around external CLI tools (readelf/objdump/nm/...)."""
import shutil
import subprocess


def have(tool):
    """True if `tool` is on PATH."""
    return shutil.which(tool) is not None


def run(cmd, data=None):
    """Run `cmd` (a list), return stdout as text ('' on any failure)."""
    try:
        p = subprocess.run(
            cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return p.stdout.decode("latin-1", "replace")
    except Exception:
        return ""
