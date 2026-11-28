"""Symbolic crackme solver via angr (optional, heavy dependency).

`ctfkit solve <bin> --find "Correct"` symbolically explores the binary to find
the input (stdin by default, or argv[1] with --arg) that reaches a success
state -- either a string appearing on stdout (--find TEXT) or a target address
(--find-addr 0x..) -- while avoiding --avoid states. Prints the solving input.

angr is imported lazily: it is large and slow to import, so it must not touch
the rest of ctfkit. Install it (ideally in its own venv) with `pip install angr`.
"""
from .ui import C, bad, good, hdr, info


def _load_angr():
    """Import angr lazily. Returns (angr, claripy) or (None, None)."""
    try:
        import angr
        import claripy
        return angr, claripy
    except Exception:
        return None, None


def parse_addr(s):
    """'0x401234' / '401234' -> int, or None for a falsy input."""
    if not s:
        return None
    return int(s, 16)


def _format_solution(sol):
    printable = sol.split(b"\x00")[0]
    good("solution found:")
    print(f"    bytes : {sol!r}")
    try:
        print(f"    ascii : {C.CY}{printable.decode('latin-1')}{C.RST}")
    except Exception:
        pass
    print(f"    hex   : {sol.hex()}")


def cmd_solve(binary, find=None, find_addr=None, avoid=None, avoid_addr=None,
              length=32, use_arg=False):
    hdr("angr solve")
    if not (find or find_addr):
        bad("give a success condition: --find TEXT or --find-addr 0xADDR")
        return
    angr, claripy = _load_angr()
    if angr is None:
        bad("angr not installed  (pip install angr — heavy; prefer its own venv)")
        return

    import logging
    for name in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.ERROR)

    info(f"loading {binary} (auto_load_libs off) ...")
    try:
        proj = angr.Project(binary, auto_load_libs=False)
    except Exception as e:
        bad(f"angr could not load the binary: {e}")
        return

    flag = claripy.BVS("input", 8 * length)
    if use_arg:
        state = proj.factory.full_init_state(args=[binary, flag])
    else:
        stdin = angr.SimFileStream(name="stdin", content=flag, has_end=False)
        state = proj.factory.full_init_state(stdin=stdin)

    find_cond = parse_addr(find_addr) if find_addr else \
        (lambda s: find.encode() in s.posix.dumps(1))
    avoid_cond = None
    if avoid_addr:
        avoid_cond = parse_addr(avoid_addr)
    elif avoid:
        avoid_cond = (lambda s: avoid.encode() in s.posix.dumps(1))

    info("exploring symbolically (this can take a while) ...")
    simgr = proj.factory.simgr(state)
    try:
        if avoid_cond is not None:
            simgr.explore(find=find_cond, avoid=avoid_cond)
        else:
            simgr.explore(find=find_cond)
    except Exception as e:
        bad(f"exploration error: {e}")
        return

    if not simgr.found:
        bad("no solution found (try larger --len, a different --find, or --avoid)")
        return
    found = simgr.found[0]
    sol = found.solver.eval(flag, cast_to=bytes) if use_arg else found.posix.dumps(0)
    _format_solution(sol)
