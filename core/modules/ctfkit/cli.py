"""Command-line interface: argument parsing and dispatch."""
import argparse
import os
import sys
import textwrap

from . import __version__
from .heap import cmd_heap
from .libc import cmd_libc
from .libcid import cmd_libcid
from .offset import cmd_offset
from .onegadget import cmd_onegadget
from .patchelf import cmd_patchelf
from .pwngen import cmd_pwn
from .rop import cmd_rop
from .seccomp import cmd_seccomp
from .shellcode import cmd_shellcode
from .solve import cmd_solve
from .triage import cmd_triage
from .tui import tui
from .ui import bad
from .web import cmd_web


def build_parser():
    p = argparse.ArgumentParser(
        prog="ctfkit",
        description="CTF helper for Linux ELF x86-64 (rev + pwn).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              ctfkit triage ./chall
              ctfkit pwn ./chall -o exploit.py --host ctf.io --port 1337
              ctfkit pwn ./chall --auto-offset        # run it, bake OFFSET in
              ctfkit pwn ./chall --libc ./libc.so.6   # embed libc + one_gadgets
              ctfkit offset ./chall                   # just find the BOF offset
              ctfkit onegadget ./libc.so.6            # magic execve gadgets
              ctfkit libcid --leak puts=0x7f..340     # identify libc from a leak
              ctfkit heap ./chall                     # scaffold a heap exploit
              ctfkit solve ./crackme --find Correct   # symbolic solve (angr)
              ctfkit patchelf ./chall --libc ./libc.so.6 --apply   # run under that libc
              ctfkit seccomp ./chall                  # dump the seccomp filter
              ctfkit shellcode orw --arg flag.txt     # generate shellcode
              ctfkit web                              # local web UI (browser)
              ctfkit rop ./chall
              ctfkit libc ./chall ./libc.so.6
              ctfkit                 # interactive menu
        """),
    )
    p.add_argument("--version", action="version",
                   version=f"ctfkit {__version__}")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("triage", help="full RE triage of a binary")
    sp.add_argument("binary")

    sp = sub.add_parser("pwn", help="generate a pwntools exploit skeleton")
    sp.add_argument("binary")
    sp.add_argument("-o", "--out", default="exploit.py", help="output script path")
    sp.add_argument("--host", default="CHANGE_ME", help="remote host")
    sp.add_argument("--port", type=int, default=0, help="remote port")
    sp.add_argument("--auto-offset", action="store_true",
                    help="run the binary under gdb to auto-fill OFFSET (executes it)")
    sp.add_argument("--off-len", type=int, default=200,
                    help="cyclic pattern length for --auto-offset (default 200)")
    sp.add_argument("--libc", default=None, metavar="LIBC",
                    help="embed libc ELF + one_gadget offsets into the skeleton")
    sp.add_argument("--libc-leak", action="append", metavar="SYM=ADDR", default=[],
                    help="identify+download libc from a leak (libc.rip), then embed it")

    sp = sub.add_parser("onegadget", help="list one_gadget execve gadgets in a libc")
    sp.add_argument("libc")
    sp.add_argument("-l", "--level", type=int, default=0,
                    help="one_gadget search level (higher = more gadgets)")
    sp.add_argument("--raw", action="store_true", help="print just the offsets")

    sp = sub.add_parser("libcid", help="identify libc from a leaked symbol address")
    sp.add_argument("--leak", action="append", metavar="SYM=ADDR", default=[],
                    help="a leaked symbol address, e.g. puts=0x7f..340 (repeatable)")
    sp.add_argument("--libs", default=None, metavar="DIR",
                    help="match offline against a folder of libc files (no network)")
    sp.add_argument("--offline", action="store_true",
                    help="do not query libc.rip (requires --libs)")
    sp.add_argument("--timeout", type=int, default=10,
                    help="libc.rip request timeout in seconds (default 10)")
    sp.add_argument("--download", nargs="?", const=".", default=None, metavar="DIR",
                    help="download the best-matching libc from libc.rip into DIR (default .)")

    sp = sub.add_parser("offset", help="auto-find the stack overflow offset (runs it)")
    sp.add_argument("binary")
    sp.add_argument("--len", type=int, default=200, dest="length",
                    help="cyclic pattern length (default 200)")
    sp.add_argument("--arg", action="store_true",
                    help="deliver the pattern as argv[1] instead of stdin")
    sp.add_argument("--update", default=None, metavar="FILE",
                    help="patch OFFSET = <n> into an existing exploit script")

    sp = sub.add_parser("heap", help="scaffold a heap exploit (menu wrappers)")
    sp.add_argument("binary")
    sp.add_argument("-o", "--out", default="heap.py", help="output script path")
    sp.add_argument("--host", default="CHANGE_ME", help="remote host")
    sp.add_argument("--port", type=int, default=0, help="remote port")
    sp.add_argument("--libc", default=None, help="libc ELF to reference in the skeleton")

    sp = sub.add_parser("patchelf", help="patch a binary to run under a given libc")
    sp.add_argument("binary")
    sp.add_argument("--libc", required=True, help="the libc.so.6 to run against")
    sp.add_argument("--ld", default=None, help="loader (auto-found next to libc if omitted)")
    sp.add_argument("-o", "--out", default=None, help="patched copy path (default <bin>.patched)")
    sp.add_argument("--apply", action="store_true",
                    help="actually run patchelf on the copy (needs patchelf installed)")

    sp = sub.add_parser("solve", help="symbolic crackme solver (angr)")
    sp.add_argument("binary")
    sp.add_argument("--find", default=None, metavar="TEXT",
                    help="success = this text appears on stdout")
    sp.add_argument("--find-addr", default=None, metavar="ADDR",
                    help="success = reaching this address (hex)")
    sp.add_argument("--avoid", default=None, metavar="TEXT",
                    help="avoid = this text appears on stdout")
    sp.add_argument("--avoid-addr", default=None, metavar="ADDR",
                    help="avoid = reaching this address (hex)")
    sp.add_argument("--len", type=int, default=32, dest="length",
                    help="symbolic input length in bytes (default 32)")
    sp.add_argument("--arg", action="store_true",
                    help="feed the input as argv[1] instead of stdin")

    sp = sub.add_parser("seccomp", help="dump a binary's seccomp filter")
    sp.add_argument("binary")

    sp = sub.add_parser("shellcode", help="generate shellcode via pwntools shellcraft")
    sp.add_argument("kind", choices=["sh", "orw", "cat", "exec", "srop"],
                    help="payload type")
    sp.add_argument("--arg", default=None, help="file path (orw/cat) or program (exec)")
    sp.add_argument("--arch", default="amd64", choices=["amd64", "i386"],
                    help="target arch (default amd64)")
    sp.add_argument("-o", "--out", default=None, help="write raw bytes to this file")

    sp = sub.add_parser("web", help="launch a local web UI in the browser")
    sp.add_argument("--port", type=int, default=8777, help="port (default 8777)")
    sp.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; keep it local)")
    sp.add_argument("--no-browser", action="store_true",
                    help="don't auto-open the browser")

    sp = sub.add_parser("rop", help="dump useful ROP gadgets")
    sp.add_argument("binary")

    sp = sub.add_parser("libc", help="GOT/PLT and ret2libc helper")
    sp.add_argument("binary")
    sp.add_argument("libc", nargs="?", default=None, help="optional libc.so path")

    return p


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd is None:
        try:
            tui()
        except (KeyboardInterrupt, EOFError):
            print()
        return 0

    # commands that take a filesystem path as their positional argument
    if args.cmd in ("triage", "pwn", "offset", "rop", "libc", "heap", "solve",
                    "patchelf", "seccomp"):
        target = args.binary
    elif args.cmd == "onegadget":
        target = args.libc
    else:
        target = None                       # libcid: no positional file
    if target is not None and not os.path.exists(target):
        bad(f"file not found: {target}")
        return 1
    try:
        if args.cmd == "triage":
            cmd_triage(args.binary)
        elif args.cmd == "pwn":
            cmd_pwn(args.binary, args.out, args.host, args.port,
                    auto_offset=args.auto_offset, off_len=args.off_len,
                    libc=args.libc, libc_leak=args.libc_leak)
        elif args.cmd == "onegadget":
            cmd_onegadget(args.libc, level=args.level, raw=args.raw)
        elif args.cmd == "libcid":
            cmd_libcid(args.leak, libs=args.libs, online=not args.offline,
                       timeout=args.timeout, download=args.download)
        elif args.cmd == "offset":
            cmd_offset(args.binary, length=args.length, arg=args.arg,
                       update=args.update)
        elif args.cmd == "heap":
            cmd_heap(args.binary, args.out, args.host, args.port, libc=args.libc)
        elif args.cmd == "solve":
            cmd_solve(args.binary, find=args.find, find_addr=args.find_addr,
                      avoid=args.avoid, avoid_addr=args.avoid_addr,
                      length=args.length, use_arg=args.arg)
        elif args.cmd == "patchelf":
            cmd_patchelf(args.binary, args.libc, ld=args.ld, out=args.out,
                         apply=args.apply)
        elif args.cmd == "seccomp":
            cmd_seccomp(args.binary)
        elif args.cmd == "shellcode":
            cmd_shellcode(args.kind, arg=args.arg, arch=args.arch, out=args.out)
        elif args.cmd == "web":
            cmd_web(port=args.port, no_browser=args.no_browser, host=args.host)
        elif args.cmd == "rop":
            cmd_rop(args.binary)
        elif args.cmd == "libc":
            cmd_libc(args.binary, args.libc)
    except ValueError as e:
        bad(str(e))
        return 1
    except KeyboardInterrupt:
        print()
    return 0
