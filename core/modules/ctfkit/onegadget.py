"""Wrapper around the `one_gadget` CLI.

one_gadget (https://github.com/david942j/one_gadget, `gem install one_gadget`)
finds "magic" addresses in a libc: a single jump target that executes
execve("/bin/sh", NULL, NULL) provided a few register/memory constraints hold.
Invaluable once you have a libc leak and control of RIP.

This module shells out to the real tool (the constraint analysis is non-trivial
and not worth reimplementing) and parses its output into structured gadgets.
When the tool is absent we say so and how to install it, instead of guessing.
"""
import os
import re

from .shell import have, run
from .ui import C, bad, good, hdr, info

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_HEAD = re.compile(r"^(0x[0-9a-fA-F]+)\s+(.*execve.*)$")


def available():
    return have("one_gadget")


def parse(out):
    """Parse one_gadget pretty output into a list of gadget dicts."""
    out = _ANSI.sub("", out)
    gadgets = []
    for block in re.split(r"\n\s*\n", out.strip()):
        lines = [ln.rstrip() for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        m = _HEAD.match(lines[0].strip())
        if not m:
            continue
        gadget = {"offset": int(m.group(1), 16),
                  "target": m.group(2).strip(),
                  "constraints": []}
        in_cons = False
        for ln in lines[1:]:
            s = ln.strip()
            if s.lower().startswith("constraints"):
                in_cons = True
                continue
            if in_cons and s:
                gadget["constraints"].append(s)
        gadgets.append(gadget)
    return gadgets


def find(libc, level=0):
    """Return (gadgets:list or None, error:str or None)."""
    if not available():
        return None, "one_gadget not found (install: gem install one_gadget)"
    cmd = ["one_gadget", os.path.abspath(libc)]
    if level:
        cmd += ["-l", str(level)]
    out = run(cmd)
    gadgets = parse(out)
    if not gadgets:
        return None, "one_gadget found nothing (wrong libc? try a higher --level)"
    return gadgets, None


def cmd_onegadget(libc, level=0, raw=False):
    hdr("one_gadget")
    gadgets, err = find(libc, level=level)
    if err:
        bad(err)
        return
    if raw:
        print("  " + " ".join(hex(g["offset"]) for g in gadgets))
        return
    for g in gadgets:
        good(f"{hex(g['offset'])}  {C.DIM}{g['target']}{C.RST}")
        for c in g["constraints"]:
            print(f"      {C.GR}{c}{C.RST}")
    info("usage: og = libc.address + <offset>; return to it with constraints met")
