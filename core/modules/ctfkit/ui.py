"""Terminal presentation: colors, status lines, banner.

Colors auto-disable when stdout is not a TTY or NO_COLOR is set.
"""
import os
import sys


class C:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
        M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
        BOLD = "\033[1m"; DIM = "\033[2m"; RST = "\033[0m"
    else:
        R = G = Y = B = M = CY = W = GR = BOLD = DIM = RST = ""


def force_color():
    """Force-enable ANSI on C (used by the web UI, which converts it to HTML)."""
    C.R = "\033[31m"; C.G = "\033[32m"; C.Y = "\033[33m"; C.B = "\033[34m"
    C.M = "\033[35m"; C.CY = "\033[36m"; C.W = "\033[37m"; C.GR = "\033[90m"
    C.BOLD = "\033[1m"; C.DIM = "\033[2m"; C.RST = "\033[0m"


def hdr(title):
    print(f"\n{C.BOLD}{C.CY}== {title} =={C.RST}")


def good(msg):
    print(f"  {C.G}[+]{C.RST} {msg}")


def warn(msg):
    print(f"  {C.Y}[!]{C.RST} {msg}")


def bad(msg):
    print(f"  {C.R}[-]{C.RST} {msg}")


def info(msg):
    print(f"  {C.GR}[*]{C.RST} {msg}")


def kv(key, val, color=""):
    print(f"  {C.DIM}{key:<16}{C.RST} {color}{val}{C.RST}")


BANNER = r"""
   __  ____ _____ _    _ _
  / _||  _ \_   _| |/ /(_) |_
 | |  | | | || | | ' / | | __|   CTF helper - rev + pwn (Linux ELF x86-64)
 | |_ | |_| || | | . \ | | |_
  \__||____/ |_| |_|\_\|_|\__|
"""
