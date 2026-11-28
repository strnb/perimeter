"""ELF loading, symbol extraction, and shared heuristic tables.

Exposes pwntools' ELF/ROP when available (HAVE_PWNTOOLS), plus a tiny
dependency-free MiniELF parser used as a fallback.
"""
import re
import struct

from .shell import have, run

# --- optional pwntools -------------------------------------------------------
try:
    from pwn import ELF, ROP, context  # type: ignore
    HAVE_PWNTOOLS = True
except Exception:  # pragma: no cover - environment dependent
    ELF = ROP = context = None  # type: ignore
    HAVE_PWNTOOLS = False


# --- heuristic tables --------------------------------------------------------
DANGEROUS = {
    "gets": "unbounded stdin read -> classic stack BOF",
    "strcpy": "no bounds -> BOF if src attacker-controlled",
    "strcat": "no bounds -> BOF",
    "sprintf": "no bounds -> BOF",
    "vsprintf": "no bounds -> BOF",
    "scanf": "check format: %s is unbounded",
    "__isoc99_scanf": "check format: %s is unbounded",
    "read": "fixed size? compare to buffer size",
    "memcpy": "size attacker-controlled? -> BOF",
    "system": "command exec -> ret2system / backdoor",
    "execve": "process exec -> shellcode/backdoor",
    "execl": "process exec",
    "printf": "if arg is user-controlled -> format string",
    "fprintf": "format string if arg user-controlled",
    "snprintf": "format string if fmt user-controlled",
    "mprotect": "RWX page -> shellcode via ret2mprotect",
    "mmap": "map RWX -> shellcode",
    "malloc": "heap chall? check free/double-free",
    "free": "heap chall? UAF / double-free",
    "puts": "handy for GOT leak (ret2puts)",
    "write": "handy for arbitrary leak",
    "alloca": "dynamic stack alloc",
    "strncpy": "off-by-one null? check lengths",
    "fgets": "bounded, but check size vs buffer",
}

BACKDOOR_HINTS = re.compile(
    r"(win|shell|backdoor|give.?shell|get.?flag|print.?flag|cat.?flag|"
    r"admin|debug|secret|magic|cheat|unlock|sys|pwn|vuln|target)",
    re.IGNORECASE,
)


# --- minimal ELF parser (fallback) ------------------------------------------
class MiniELF:
    """Just enough ELF parsing to answer triage questions without pwntools."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        if self.data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file")
        self.ei_class = self.data[4]           # 1=32bit, 2=64bit
        self.ei_data = self.data[5]            # 1=LE, 2=BE
        self.bits = 64 if self.ei_class == 2 else 32
        self.endian = "little" if self.ei_data == 1 else "big"
        e = "<" if self.endian == "little" else ">"
        self.e_type = struct.unpack_from(e + "H", self.data, 16)[0]
        self.e_machine = struct.unpack_from(e + "H", self.data, 18)[0]

    @property
    def arch(self):
        return {0x3E: "amd64", 0x03: "i386", 0xB7: "aarch64",
                0x28: "arm", 0x08: "mips"}.get(
                    self.e_machine, f"0x{self.e_machine:x}")

    @property
    def pie(self):
        # ET_DYN (3) usually => PIE; ET_EXEC (2) => no PIE
        return self.e_type == 3


def load_binary(path):
    """Return (pwn_elf_or_None, mini_elf). Raises ValueError on non-ELF."""
    mini = MiniELF(path)
    pelf = None
    if HAVE_PWNTOOLS:
        try:
            context.log_level = "error"
            pelf = ELF(path, checksec=False)
        except Exception:
            pelf = None
    return pelf, mini


def get_symbols(pelf, mini):
    """Return (local_funcs: dict name->addr, imported: set of names)."""
    local = {}
    imported = set()
    if pelf is not None:
        for name, addr in pelf.symbols.items():
            if isinstance(name, str) and addr:
                local[name] = addr
        imported = set(pelf.plt.keys()) if pelf.plt else set()
        try:
            imported |= set(pelf.got.keys())
        except Exception:
            pass
        return local, imported

    # Fallback via nm / readelf
    if have("nm"):
        out = run(["nm", mini.path])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:
                addr, typ, name = parts
                if typ in ("T", "t", "W"):
                    try:
                        local[name] = int(addr, 16)
                    except ValueError:
                        pass
                elif typ == "U":
                    imported.add(name)
    if have("readelf"):
        out = run(["readelf", "--dyn-syms", "-W", mini.path])
        for line in out.splitlines():
            m = re.search(r"FUNC\s+\w+\s+\w+\s+UND\s+(\S+)", line)
            if m:
                imported.add(m.group(1).split("@")[0])
    return local, imported
