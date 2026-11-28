"""Interactive menu (shown when ctfkit is run with no subcommand)."""
import os

from .elf import HAVE_PWNTOOLS, load_binary
from .heap import cmd_heap
from .libc import cmd_libc
from .libcid import cmd_libcid
from .offset import cmd_offset
from .patchelf import cmd_patchelf
from .pwngen import cmd_pwn
from .rop import cmd_rop
from .seccomp import cmd_seccomp
from .shellcode import cmd_shellcode
from .solve import cmd_solve
from .triage import cmd_triage
from .ui import BANNER, C, bad, warn
from .web import cmd_web


def tui():
    print(f"{C.CY}{BANNER}{C.RST}")
    if not HAVE_PWNTOOLS:
        warn("pwntools not found -> fallback mode (readelf/objdump/nm).")
    binpath = input(f"{C.BOLD}Path to ELF binary:{C.RST} ").strip()
    binpath = binpath.strip('"').strip("'")
    if not binpath or not os.path.exists(binpath):
        bad("file not found")
        return
    try:
        load_binary(binpath)
    except Exception as e:
        bad(f"not a valid ELF: {e}")
        return

    while True:
        print(f"""
{C.BOLD}Choose an action for {C.CY}{binpath}{C.RST}{C.BOLD}:{C.RST}
  {C.G}1{C.RST}) Full triage (checksec, imports, strings, win funcs, vuln guess)
  {C.G}2{C.RST}) Generate pwntools exploit skeleton
  {C.G}3{C.RST}) ROP gadgets + /bin/sh
  {C.G}4{C.RST}) GOT/PLT + ret2libc notes
  {C.G}5{C.RST}) Auto-find overflow offset (runs the binary)
  {C.G}6{C.RST}) Identify libc from a leak (libc.rip / local)
  {C.G}7{C.RST}) Scaffold a heap exploit (menu wrappers)
  {C.G}8{C.RST}) Launch the web UI (browser)
  {C.G}9{C.RST}) Symbolic solve a crackme (angr)
  {C.G}p{C.RST}) patchelf: run under a downloaded libc
  {C.G}c{C.RST}) seccomp filter dump
  {C.G}s{C.RST}) generate shellcode
  {C.G}q{C.RST}) Quit
""")
        choice = input(f"{C.BOLD}> {C.RST}").strip().lower()
        if choice == "1":
            cmd_triage(binpath)
        elif choice == "2":
            out = input("  output file [exploit.py]: ").strip() or "exploit.py"
            host = input("  remote host [CHANGE_ME]: ").strip() or "CHANGE_ME"
            port = input("  remote port [0]: ").strip() or "0"
            try:
                port = int(port)
            except ValueError:
                port = 0
            ao = input("  auto-find offset now? (runs binary) [y/N]: ").strip().lower()
            lc = input("  libc path for one_gadget (optional): ").strip() or None
            cmd_pwn(binpath, out, host, port,
                    auto_offset=ao in ("y", "yes"), libc=lc)
        elif choice == "3":
            cmd_rop(binpath)
        elif choice == "4":
            lc = input("  libc path (optional): ").strip() or None
            cmd_libc(binpath, lc)
        elif choice == "5":
            ln = input("  pattern length [200]: ").strip() or "200"
            try:
                ln = int(ln)
            except ValueError:
                ln = 200
            upd = input("  patch into which exploit file? (optional): ").strip() or None
            cmd_offset(binpath, length=ln, update=upd)
        elif choice == "6":
            raw = input("  leaks (e.g. puts=0x..340 printf=0x..f90): ").strip()
            leaks = [t for t in raw.split() if "=" in t]
            if not leaks:
                warn("no leaks given")
                continue
            libs = input("  local libc folder? (blank = query libc.rip): ").strip() or None
            dl = None
            if libs is None:
                ans = input("  download the matched libc? [y/N]: ").strip().lower()
                dl = "." if ans in ("y", "yes") else None
            cmd_libcid(leaks, libs=libs, online=libs is None, download=dl)
        elif choice == "7":
            out = input("  output file [heap.py]: ").strip() or "heap.py"
            cmd_heap(binpath, out, "CHANGE_ME", 0)
        elif choice == "8":
            cmd_web()                       # blocks until Ctrl-C, then back to menu
        elif choice == "9":
            txt = input("  success string on stdout (e.g. Correct): ").strip()
            ln = input("  input length [32]: ").strip() or "32"
            try:
                ln = int(ln)
            except ValueError:
                ln = 32
            cmd_solve(binpath, find=(txt or None), length=ln)
        elif choice == "p":
            lc = input("  libc path: ").strip()
            if lc:
                ap = input("  apply patchelf now? [y/N]: ").strip().lower()
                cmd_patchelf(binpath, lc, apply=ap in ("y", "yes"))
            else:
                warn("no libc given")
        elif choice == "c":
            cmd_seccomp(binpath)
        elif choice == "s":
            kind = input("  kind [sh/orw/cat/exec/srop] (sh): ").strip() or "sh"
            a = input("  arg (file for orw/cat, prog for exec): ").strip() or None
            cmd_shellcode(kind, arg=a)
        elif choice in ("q", "quit", "exit"):
            break
        else:
            warn("unknown choice")
