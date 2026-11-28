"""Full reverse-engineering triage of an ELF."""
import re

from .checksec import checksec
from .elf import (BACKDOOR_HINTS, DANGEROUS, HAVE_PWNTOOLS, get_symbols,
                  load_binary)
from .rop import show_got_plt
from .shell import have, run
from .ui import C, good, hdr, info, kv, warn

INTERESTING_STR = re.compile(
    r"(/bin/sh|/bin/bash|/bin/cat|flag|FLAG\{|\.txt|%s|%n|%p|%x|%d|"
    r"system|/proc/|password|passwd|secret|key|token|http[s]?://|"
    r"\$\{|sh\x00|cat |nc |socket|ptrace|/dev/|puts|gets)",
    re.IGNORECASE,
)


def analyze_functions(pelf, mini):
    local, imported = get_symbols(pelf, mini)

    hdr("Imported functions of interest")
    hits = []
    for fn in sorted(imported):
        base = fn.split("@")[0]
        if base in DANGEROUS:
            hits.append(base)
            warn(f"{C.BOLD}{base:<18}{C.RST} {C.DIM}{DANGEROUS[base]}{C.RST}")
    if not hits:
        info("no obviously dangerous imports (or symbols stripped)")

    hdr("Potential win/backdoor functions")
    wins = []
    for name, addr in sorted(local.items(), key=lambda x: x[1]):
        if BACKDOOR_HINTS.search(name) and not name.startswith("_"):
            wins.append((name, addr))
            good(f"{name:<24} @ {C.CY}0x{addr:x}{C.RST}")
    if not wins:
        info("no named win-like functions (stripped? check decompiler)")

    return local, imported, hits, wins


def interesting_strings(mini, limit=40):
    hdr("Interesting strings")
    text = mini.data
    found = []
    cur = bytearray()
    off = 0
    results = []
    for i, b in enumerate(text):
        if 0x20 <= b < 0x7F:
            if not cur:
                off = i
            cur.append(b)
        else:
            if len(cur) >= 4:
                results.append((off, cur.decode("latin-1")))
            cur = bytearray()
    if len(cur) >= 4:
        results.append((off, cur.decode("latin-1")))

    shown = 0
    for off, s in results:
        if INTERESTING_STR.search(s):
            found.append((off, s))
            if shown < limit:
                sn = s if len(s) <= 70 else s[:67] + "..."
                print(f"  {C.GR}0x{off:06x}{C.RST}  {C.W}{sn}{C.RST}")
                shown += 1
    if not found:
        info("nothing jumped out")
    elif len(found) > limit:
        info(f"... and {len(found) - limit} more "
             f"(run `strings {mini.path}` for all)")
    return found


def guess_vuln(sec, hits, wins):
    hdr("Likely attack path (heuristic)")
    suggestions = []
    h = set(hits)

    if "gets" in h:
        suggestions.append("`gets` present -> classic stack buffer overflow. "
                           "Find offset with cyclic, then overwrite saved RIP.")
    if {"printf", "fprintf", "snprintf"} & h and "gets" not in h:
        suggestions.append("printf-family present -> check for format string "
                           "(user-controlled format). Leak with %p / write %n.")
    if "system" in h:
        if wins:
            suggestions.append("`system` + named function -> probably ret2win / "
                               "call system(\"/bin/sh\").")
        else:
            suggestions.append("`system` present -> ret2system: need \"/bin/sh\" "
                               "string + control of RDI.")
    if {"malloc", "free"} & h:
        suggestions.append("malloc/free present -> likely a HEAP challenge "
                           "(UAF / double-free / tcache). Try `ctfkit heap <bin>`.")
    if {"mprotect", "mmap"} & h and not sec["nx"]:
        suggestions.append("RWX possible -> shellcode injection on stack.")
    if not sec["nx"]:
        suggestions.append("NX disabled -> you can execute shellcode on the stack.")
    if not sec["canary"] and ("gets" in h or "read" in h or "scanf" in h):
        suggestions.append("No stack canary -> straight overflow to RIP is viable.")
    if sec["pie"]:
        suggestions.append("PIE enabled -> you need an address leak before using "
                           "any binary address.")
    else:
        suggestions.append("No PIE -> binary addresses are fixed; ret2win/plt easy.")
    if sec["relro"] != "Full" and ("printf" in h or "free" in h):
        suggestions.append("Partial/No RELRO -> GOT is writable (GOT overwrite).")

    if not suggestions:
        info("no strong signal; open it in a decompiler (ghidra/IDA).")
    for s in suggestions:
        print(f"  {C.M}->{C.RST} {s}")


def decompile_preview(mini, local):
    """If objdump present, show disasm of main (and vuln/win funcs)."""
    if not have("objdump"):
        return
    targets = [n for n in ("main", "vuln", "win", "challenge") if n in local]
    if not targets:
        return
    hdr("Disassembly preview (objdump)")
    out = run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", mini.path])
    for fn in targets[:2]:
        m = re.search(rf"<{re.escape(fn)}>:\n(.*?)(?:\n\n|\Z)", out, re.DOTALL)
        if m:
            print(f"  {C.BOLD}{fn}:{C.RST}")
            body = m.group(1).splitlines()
            for line in body[:30]:
                print(f"    {C.DIM}{line.strip()}{C.RST}")
            if len(body) > 30:
                info(f"... {len(body) - 30} more lines (objdump -d {mini.path})")


def cmd_triage(path):
    pelf, mini = load_binary(path)
    hdr("Target")
    kv("File", path)
    kv("Type", "PIE/shared" if mini.pie else "EXEC")
    kv("pwntools", "yes" if HAVE_PWNTOOLS else "no (fallback mode)")
    if have("file"):
        ft = run(["file", "-b", path]).strip()
        if ft:
            kv("file(1)", ft[:80])

    sec = checksec(pelf, mini)
    local, imported, hits, wins = analyze_functions(pelf, mini)
    interesting_strings(mini)
    show_got_plt(pelf, mini)
    decompile_preview(mini, local)
    guess_vuln(sec, hits, wins)
    print()
    info(f"Next: {C.BOLD}ctfkit pwn {path}{C.RST} to generate an exploit skeleton.")
