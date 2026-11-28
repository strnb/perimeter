"""Inspect a binary's seccomp filter.

Prefers `seccomp-tools dump <bin>` (gem install seccomp-tools), which runs the
binary and prints the BPF syscall filter. Without it, falls back to a static
heuristic: does the binary reference prctl / seccomp at all?
"""
from .elf import get_symbols, load_binary
from .shell import have, run
from .ui import bad, hdr, info, warn


def static_hint(mini, imported):
    """True if the binary plausibly installs a seccomp filter."""
    bases = {fn.split("@")[0] for fn in imported}
    if {"prctl", "seccomp"} & bases:
        return True
    return b"seccomp" in mini.data or b"SECCOMP" in mini.data


def cmd_seccomp(binary):
    hdr("seccomp filter")
    if have("seccomp-tools"):
        warn("this runs the target binary (seccomp-tools dump)")
        out = run(["seccomp-tools", "dump", binary])
        print(out.rstrip() if out.strip() else "  (no filter dumped — maybe none)")
        return
    try:
        pelf, mini = load_binary(binary)
    except ValueError as e:
        bad(str(e))
        return
    _, imported = get_symbols(pelf, mini)
    if static_hint(mini, imported):
        warn("binary references prctl/seccomp — it likely installs a filter")
        info("dump it with seccomp-tools:  gem install seccomp-tools")
        info(f"then:  seccomp-tools dump {binary}")
    else:
        info("no obvious seccomp usage (no prctl/seccomp references found)")
