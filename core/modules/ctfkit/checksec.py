"""Binary mitigations (checksec): printing + a silent variant for codegen."""
from .shell import have, run
from .ui import C, hdr, info, kv


def _fallback_sec(mini):
    """Best-effort mitigations via readelf/nm (no pwntools). Returns dict."""
    pie = mini.pie
    nx = True
    canary = False
    relro = "No"
    if have("readelf"):
        prog = run(["readelf", "-lW", mini.path])
        for line in prog.splitlines():
            if "GNU_STACK" in line and "RWE" in line:
                nx = False
        if "GNU_RELRO" in prog:
            dyn = run(["readelf", "-dW", mini.path])
            relro = "Full" if "BIND_NOW" in dyn else "Partial"
    syms = run(["nm", mini.path]) if have("nm") else ""
    dynsyms = run(["readelf", "-sW", mini.path]) if have("readelf") else ""
    if "__stack_chk_fail" in syms or "__stack_chk_fail" in dynsyms:
        canary = True
    return {"canary": canary, "nx": nx, "pie": pie, "relro": relro,
            "arch": mini.arch, "bits": mini.bits}


def checksec(pelf, mini):
    """Print mitigations and return the sec dict."""
    hdr("Mitigations (checksec)")
    if pelf is not None:
        relro = ("Full" if pelf.relro == "Full"
                 else ("Partial" if pelf.relro else "No"))
        canary, nx, pie = pelf.canary, pelf.nx, pelf.pie
        fortify = getattr(pelf, "fortify", False)
        kv("Arch", f"{pelf.arch}-{pelf.bits}-"
                   f"{'le' if pelf.endian == 'little' else 'be'}")
        kv("RELRO", relro, C.G if relro == "Full" else C.Y)
        kv("Stack Canary", "Yes" if canary else "No", C.Y if canary else C.G)
        kv("NX", "Enabled" if nx else "Disabled", C.Y if nx else C.G)
        kv("PIE", "Enabled" if pie else "No PIE", C.Y if pie else C.G)
        kv("FORTIFY", "Yes" if fortify else "No")
        if getattr(pelf, "runpath", None):
            kv("RUNPATH", pelf.runpath, C.CY)
        if getattr(pelf, "rpath", None):
            kv("RPATH", pelf.rpath, C.CY)
        return {"canary": bool(canary), "nx": bool(nx), "pie": bool(pie),
                "relro": relro, "arch": pelf.arch, "bits": pelf.bits}

    sec = _fallback_sec(mini)
    kv("Arch", f"{sec['arch']}-{sec['bits']}-{mini.endian[:2]}")
    kv("RELRO", sec["relro"], C.G if sec["relro"] == "Full" else C.Y)
    kv("Stack Canary", "Yes" if sec["canary"] else "No",
       C.Y if sec["canary"] else C.G)
    kv("NX", "Enabled" if sec["nx"] else "Disabled",
       C.Y if sec["nx"] else C.G)
    kv("PIE", "Enabled" if sec["pie"] else "No PIE",
       C.Y if sec["pie"] else C.G)
    info("(fallback mode: install pwntools for exact checksec)")
    return sec


def silent_sec(pelf, mini):
    """Same mitigations as checksec() but without any printing (for codegen)."""
    if pelf is not None:
        relro = ("Full" if pelf.relro == "Full"
                 else ("Partial" if pelf.relro else "No"))
        return {"canary": bool(pelf.canary), "nx": bool(pelf.nx),
                "pie": bool(pelf.pie), "relro": relro,
                "arch": pelf.arch, "bits": pelf.bits}
    return _fallback_sec(mini)
