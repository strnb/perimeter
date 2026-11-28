"""Automatic stack-overflow offset finder.

Feeds a De Bruijn ("cyclic") pattern to the target, catches the crash under
gdb, and recovers the distance from the start of input to the saved return
address by locating the faulting $pc inside the pattern.

Why this is robust:
  * The recovered offset comes from the *pattern bytes* that landed in RIP,
    so it is independent of ASLR and PIE (those change addresses, not which
    pattern bytes get popped into RIP).
  * It needs no pwntools: `cyclic` is implemented here and the run is driven
    by plain `gdb -batch`.

Caveats:
  * This RUNS THE TARGET BINARY locally (under gdb). Only use it on a binary
    you intend to exploit (your CTF challenge).
  * If a stack canary is enabled, overflowing to RIP trips __stack_chk_fail
    *before* the `ret`, so the crash is not a clean RIP overwrite -> the
    offset reported is to the canary region, not RIP. ctfkit warns about this.
"""
import os
import re
import struct
import tempfile

from .shell import have, run
from .ui import C, bad, good, hdr, info, warn

# Match pwntools' default so offsets agree across tools.
DEFAULT_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def _de_bruijn(alphabet, n):
    """Lazy De Bruijn sequence generator (yields indices into `alphabet`)."""
    k = len(alphabet)
    a = [0] * (k * n)

    def db(t, p):
        if t > n:
            if n % p == 0:                     # FKM guard (as in pwntools)
                for j in range(1, p + 1):
                    yield a[j]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


def cyclic(length, n=4, alphabet=DEFAULT_ALPHABET):
    """Return `length` bytes of a De Bruijn pattern with unique n-grams.

    Compatible with pwntools `cyclic(length)` for the default alphabet/n,
    so offsets found here match pwntools' `cyclic_find`.
    """
    out = bytearray()
    for idx in _de_bruijn(alphabet, n):
        out.append(alphabet[idx])
        if len(out) >= length:
            break
    return bytes(out)


def cyclic_find(subseq, length=0x10000, n=4, alphabet=DEFAULT_ALPHABET):
    """Return the index of `subseq` (bytes or int) in the pattern, or -1."""
    if isinstance(subseq, int):
        subseq = struct.pack("<I", subseq & 0xFFFFFFFF)
    subseq = subseq[:n]
    return cyclic(length, n=n, alphabet=alphabet).find(subseq)


def _parse_hexes(text, marker_count=2):
    """Pull the first `marker_count` `= 0x...` values from gdb output, in order."""
    return [int(m, 16) for m in re.findall(r"=\s*(0x[0-9a-fA-F]+)", text)][:marker_count]


def _run_gdb_crash(binary, pat, arg=False):
    """Run `binary` under gdb feeding `pat`; return (pc:int|None, err:str|None)."""
    if not have("gdb"):
        return None, "gdb not found (apt install gdb)"

    patfile = None
    try:
        exe = [
            "gdb", "-q", "-nx", "-batch",
            "-ex", "set pagination off",
            "-ex", "set disable-randomization on",
        ]
        if arg:
            exe += ["-ex", "run " + pat.decode("latin-1")]
        else:
            fd, patfile = tempfile.mkstemp(prefix="ctfkit_pat_")
            os.write(fd, pat + b"\n")
            os.close(fd)
            exe += ["-ex", f"run < {patfile}"]
        exe += ["-ex", "print/x $pc", os.path.abspath(binary)]
        out = run(exe)
    finally:
        if patfile and os.path.exists(patfile):
            os.unlink(patfile)

    hexes = _parse_hexes(out, 1)          # $pc at crash
    return (hexes[0] if hexes else None), None


def find_offset(binary, length=200, arg=False, quiet=False):
    """Return (offset:int or None, info:dict). Drives gdb, no pwntools needed.

    The offset is recovered from the faulting $pc, which holds the pattern
    bytes that were popped into RIP by the overflowed `ret` -- so it is
    independent of ASLR/PIE. If $pc is not part of the pattern (no clean RIP
    overwrite, e.g. a canary fired, or the input never reached saved RIP),
    we return None rather than guess.
    """
    pat = cyclic(length)
    pc, err = _run_gdb_crash(binary, pat, arg=arg)
    meta = {"pc": pc, "error": err, "length": length, "method": None}
    if err:
        return None, meta
    if pc is not None:
        off = pat.find(struct.pack("<I", pc & 0xFFFFFFFF))
        if off != -1:
            meta["method"] = "rip"
            return off, meta
    return None, meta


def patch_offset_in(path, offset):
    """Rewrite an `OFFSET = 0 ...` line in a generated exploit to the found value."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except OSError as e:
        return False, str(e)
    new, count = re.subn(
        r"^OFFSET\s*=\s*\d+.*$",
        f"OFFSET = {offset}  # auto-found by ctfkit (cyclic)",
        src, count=1, flags=re.MULTILINE,
    )
    if count == 0:
        return False, "no `OFFSET = ...` line found"
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    return True, None


def cmd_offset(path, length=200, arg=False, update=None):
    hdr("Auto offset finder")
    info(f"running target under gdb with a {length}-byte cyclic pattern ...")
    warn("this executes the target binary locally")
    off, meta = find_offset(path, length=length, arg=arg)
    if meta["error"]:
        bad(meta["error"])
        return
    if off is None:
        bad("could not locate the pattern in the crash state")
        if meta["pc"] is not None:
            info(f"$pc at crash = {hex(meta['pc'])} (not from our pattern)")
            info("the input may not reach saved RIP, or a canary stopped it early.")
            info(f"try a longer pattern:  ctfkit offset {path} --len {length * 2}")
        else:
            info("no crash captured — does the binary read from stdin? try --arg,")
            info("or feed it the pattern manually and check it segfaults.")
        return
    good(f"offset to saved RIP = {C.BOLD}{off}{C.RST}  (method: {meta['method']})")
    info(f"use in your exploit:  payload = b'A' * {off} + p64(TARGET)")
    if update:
        ok, why = patch_offset_in(update, off)
        if ok:
            good(f"patched OFFSET = {off} into {update}")
        else:
            warn(f"could not patch {update}: {why}")
