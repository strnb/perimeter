"""GOT/PLT listing and ret2libc helper (optionally dumps libc offsets)."""
from .elf import ELF, HAVE_PWNTOOLS, load_binary
from .onegadget import cmd_onegadget
from .rop import show_got_plt
from .ui import C, bad, hdr, info, warn


def cmd_libc(path, libc):
    pelf, mini = load_binary(path)
    show_got_plt(pelf, mini)
    hdr("ret2libc notes")
    info("Leak a libc address (e.g. puts@got via puts@plt), then:")
    print("    libc.address = leak - libc.symbols['puts']")
    print("    system = libc.symbols['system']; binsh = next(libc.search(b'/bin/sh'))")
    if libc:
        if HAVE_PWNTOOLS:
            try:
                lc = ELF(libc, checksec=False)
                for s in ("system", "puts", "printf", "read", "gets"):
                    if s in lc.symbols:
                        print(f"    {s:<8} offset {C.CY}0x{lc.symbols[s]:x}{C.RST}")
                sh = next(lc.search(b"/bin/sh\x00"), None)
                if sh:
                    print(f"    /bin/sh  offset {C.CY}0x{sh:x}{C.RST}")
            except Exception as e:
                bad(f"could not parse libc: {e}")
        else:
            warn("install pwntools to inspect the libc offsets")
        cmd_onegadget(libc)        # magic execve("/bin/sh") gadgets, if available
    else:
        info("pass a libc path as 3rd arg to dump offsets + one_gadgets: "
             "ctfkit libc <bin> <libc.so>")
