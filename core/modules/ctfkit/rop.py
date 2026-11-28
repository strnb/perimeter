"""ROP gadget discovery and GOT/PLT listing."""
import re

from .elf import ROP, load_binary
from .shell import have, run
from .ui import C, good, hdr, info, warn


def find_gadgets(pelf, mini):
    hdr("Useful ROP gadgets")
    if pelf is not None:
        try:
            rop = ROP(pelf)
        except Exception:
            rop = None
        if rop is not None:
            want = {
                "pop rdi; ret": ["pop", "rdi"],
                "pop rsi; ret": ["pop", "rsi"],
                "pop rdx; ret": ["pop", "rdx"],
                "pop rax; ret": ["pop", "rax"],
                "ret": ["ret"],
            }
            for label, regs in want.items():
                try:
                    g = rop.find_gadget(regs)
                    if g:
                        good(f"{label:<16} @ {C.CY}0x{g.address:x}{C.RST}")
                except Exception:
                    pass
            try:
                sh = next(pelf.search(b"/bin/sh\x00"), None)
                if sh is not None:
                    good(f"{'/bin/sh':<16} @ {C.CY}0x{sh:x}{C.RST}")
                else:
                    info("no /bin/sh string in binary (look in libc)")
            except Exception:
                pass
            return

    # Fallback: ROPgadget / ropper if present
    for tool in ("ROPgadget", "ropper"):
        if have(tool):
            info(f"using {tool}")
            if tool == "ROPgadget":
                out = run(["ROPgadget", "--binary", mini.path])
            else:
                out = run(["ropper", "-f", mini.path])
            wanted = re.compile(
                r"(pop rdi ; ret|pop rsi ; ret|pop rdx ; ret|pop rax ; ret|"
                r"leave ; ret|syscall ; ret|: ret$)")
            seen = set()
            for line in out.splitlines():
                if wanted.search(line) and line not in seen:
                    seen.add(line)
                    print(f"  {C.CY}{line.strip()}{C.RST}")
                    if len(seen) > 20:
                        break
            sh = mini.data.find(b"/bin/sh")
            if sh != -1:
                good(f"/bin/sh at file offset 0x{sh:x} (adjust to vaddr)")
            return
    warn("install pwntools, ROPgadget, or ropper for gadget search")


def show_got_plt(pelf, mini):
    hdr("GOT / PLT")
    if pelf is not None:
        try:
            for name in sorted(pelf.got):
                plt = pelf.plt.get(name)
                plt_s = f"plt 0x{plt:x}" if plt else "plt -"
                print(f"  {name:<20} got {C.CY}0x{pelf.got[name]:x}{C.RST}"
                      f"  {plt_s}")
        except Exception:
            info("could not read GOT/PLT")
        return
    if have("objdump"):
        out = run(["objdump", "-R", mini.path])
        for line in out.splitlines():
            if "JUMP_SLOT" in line or "GLOB_DAT" in line:
                print(f"  {C.DIM}{line.strip()}{C.RST}")
    else:
        info("install pwntools or binutils for GOT/PLT")


def cmd_rop(path):
    pelf, mini = load_binary(path)
    find_gadgets(pelf, mini)
    show_got_plt(pelf, mini)
