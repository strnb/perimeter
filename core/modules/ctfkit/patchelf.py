"""Make a challenge run locally against a downloaded libc, via patchelf.

When a pwn binary needs a libc different from your system's, you patch its
interpreter to the matching loader (ld) and point its NEEDED libc at the
downloaded one:

    patchelf --set-interpreter ./ld-2.31.so ./chall
    patchelf --replace-needed libc.so.6 ./libc.so.6 ./chall

`ctfkit patchelf <bin> --libc <libc.so>` finds the loader next to the libc,
prints these commands, and with --apply runs them on a COPY of the binary
(the original is left untouched).
"""
import glob
import os
import re
import shutil
import subprocess

from .shell import have
from .ui import C, bad, good, hdr, info, warn

_LD_GLOBS = ("ld-linux*.so*", "ld-*.so*", "ld.so.*")
_VER_RE = re.compile(rb"(?:release version|glibc|GLIBC)[ -]?(\d+\.\d+)", re.IGNORECASE)


def find_ld(directory):
    """Return a loader (ld-*.so) found in `directory`, or None."""
    for pat in _LD_GLOBS:
        hits = sorted(glob.glob(os.path.join(directory, pat)))
        if hits:
            return hits[0]
    return None


def libc_version(libc_path):
    """Best-effort glibc version string ('2.31') from the libc file, or None."""
    try:
        with open(libc_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    m = _VER_RE.search(data)
    return m.group(1).decode() if m else None


def build_commands(binary, libc, ld, out):
    """Return the shell commands (as strings) that produce a patched `out`."""
    import shlex
    q = shlex.quote
    cmds = [f"cp {q(binary)} {q(out)}"]
    if ld:
        cmds.append(f"patchelf --set-interpreter {q(os.path.abspath(ld))} {q(out)}")
    cmds.append(
        f"patchelf --replace-needed libc.so.6 {q(os.path.abspath(libc))} {q(out)}")
    return cmds


def cmd_patchelf(binary, libc, ld=None, out=None, apply=False):
    hdr("patchelf for libc")
    if not os.path.exists(binary):
        bad(f"binary not found: {binary}")
        return
    if not libc or not os.path.exists(libc):
        bad("give an existing libc with --libc (e.g. from `ctfkit libcid --download`)")
        return

    ver = libc_version(libc)
    info(f"libc: {libc}" + (f"  (glibc {ver})" if ver else "  (version unknown)"))
    if ld is None:
        ld = find_ld(os.path.dirname(os.path.abspath(libc)))
    if ld:
        good(f"loader: {ld}")
    else:
        warn("no loader (ld-*.so) found next to the libc.")
        info("pass one with --ld, or grab the full libs set from libc.rip "
             "(the match's libs_url) so ld-linux is alongside the libc.")

    out = out or (binary + ".patched")
    cmds = build_commands(binary, libc, ld, out)
    print()
    for c in cmds:
        print(f"  {C.CY}{c}{C.RST}")
    print()

    if not apply:
        info("re-run with --apply to execute these (on the copy, not the original)")
        return
    if not have("patchelf"):
        bad("patchelf not installed (apt install patchelf); commands printed above")
        return
    try:
        shutil.copy(binary, out)
        subprocess.run(["chmod", "+x", out], check=False)
        if ld:
            subprocess.run(["patchelf", "--set-interpreter",
                            os.path.abspath(ld), out], check=True)
        subprocess.run(["patchelf", "--replace-needed", "libc.so.6",
                        os.path.abspath(libc), out], check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        bad(f"patchelf failed: {e}")
        return
    good(f"patched copy written: {C.BOLD}{out}{C.RST}")
    info(f"run it with:  ./{os.path.basename(out)}")
