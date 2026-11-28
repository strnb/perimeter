"""Identify a libc from a leaked symbol address, then resolve its offsets.

Two modes:
  * online  -- query the libc.rip database (https://libc.rip/api/find). Only the
               symbol offsets you pass are sent; the User-Agent is a generic
               "ctfkit/<version>" with no identifying info.
  * offline -- `--libs DIR`: match your leak against a folder of candidate libc
               files locally (low 12 bits of a symbol address are ASLR-invariant).

A leak is `symbol=address`, e.g.  puts=0x7f3b2c0a4340 .  Give one or more; more
leaks disambiguate better.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .elf import ELF, HAVE_PWNTOOLS
from .shell import have, run
from .ui import C, bad, good, hdr, info, warn

LIBC_RIP = "https://libc.rip/api/find"
USER_AGENT = f"ctfkit/{__version__}"       # generic on purpose: no user identity
# downloads are only ever fetched from libc.rip, never a host the API echoes back
_DOWNLOAD_HOSTS = ("libc.rip",)
_MAX_LIBC_BYTES = 64 * 1024 * 1024         # a libc is ~2 MiB; cap well above that


# --- leak parsing & math -----------------------------------------------------
def parse_leaks(pairs):
    """['puts=0x..340', ...] -> {'puts': 0x..340}. Raises ValueError on junk."""
    leaks = {}
    for p in pairs or []:
        if "=" not in p:
            raise ValueError(f"bad --leak '{p}', expected symbol=address")
        name, val = p.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name or not val:
            raise ValueError(f"bad --leak '{p}', expected symbol=address")
        # addresses are hex; accept with or without the 0x prefix
        try:
            leaks[name] = int(val, 16)
        except ValueError:
            raise ValueError(f"bad --leak '{p}', address must be hex")
    if not leaks:
        raise ValueError("no leaks given (use --leak symbol=address)")
    return leaks


def low12(x):
    return x & 0xFFF


def symbol_matches(leaks, symbols):
    """True if every leaked symbol exists in `symbols` with matching low 12 bits."""
    for name, addr in leaks.items():
        if name not in symbols:
            return False
        if low12(addr) != low12(symbols[name]):
            return False
    return True


def resolve(leaks, symbols):
    """Return (base:int or None, {sym: absolute_addr}) using the first usable leak."""
    base = None
    for name, addr in leaks.items():
        if name in symbols:
            base = addr - symbols[name]
            break
    resolved = {}
    if base is not None:
        for name, off in symbols.items():
            resolved[name] = base + off
    return base, resolved


# --- online: libc.rip --------------------------------------------------------
def _hexmap(leaks):
    return {name: hex(addr) for name, addr in leaks.items()}


def query_libc_rip(leaks, timeout=10):
    """Return (matches:list, error:str or None). Each match is libc.rip's dict."""
    body = json.dumps({"symbols": _hexmap(leaks)}).encode()
    req = urllib.request.Request(
        LIBC_RIP, data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return None, f"libc.rip HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"no network / libc.rip unreachable ({e.reason})"
    except (TimeoutError, json.JSONDecodeError, OSError) as e:
        return None, f"libc.rip query failed ({e})"
    if not isinstance(data, list):
        return None, "unexpected response from libc.rip"
    return data, None


def _match_symbols_to_ints(sym_dict):
    """libc.rip gives hex strings; convert to ints, skip unparseable."""
    out = {}
    for name, val in (sym_dict or {}).items():
        try:
            out[name] = int(val, 16) if isinstance(val, str) else int(val)
        except (ValueError, TypeError):
            pass
    return out


def download_libc(url, dest, timeout=30):
    """Download a libc from libc.rip to `dest`. Returns (size:int or None, err).

    Guards: only https libc.rip URLs, size-capped, and the payload must be an
    ELF -- so a tampered API response cannot redirect the download elsewhere or
    drop arbitrary content on disk.
    """
    parsed = urllib.parse.urlparse(url or "")
    host = parsed.hostname or ""
    allowed = any(host == h or host.endswith("." + h) for h in _DOWNLOAD_HOSTS)
    if parsed.scheme != "https" or not allowed:
        return None, f"refusing to download from untrusted URL ({url})"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(_MAX_LIBC_BYTES + 1)
    except urllib.error.URLError as e:
        return None, f"download failed ({e.reason})"
    except (TimeoutError, OSError) as e:
        return None, f"download failed ({e})"
    if len(data) > _MAX_LIBC_BYTES:
        return None, "download too large (>64 MiB), aborted"
    if data[:4] != b"\x7fELF":
        return None, "downloaded data is not an ELF (unexpected response)"
    try:
        with open(dest, "wb") as f:
            f.write(data)
    except OSError as e:
        return None, f"could not write {dest} ({e})"
    return len(data), None


def identify_and_download(leaks, dest_dir=".", timeout=15):
    """Identify libc via libc.rip and download the best match.

    Returns (path:str or None, match:dict or None, err:str or None).
    """
    matches, err = query_libc_rip(leaks, timeout=timeout)
    if err:
        return None, None, err
    if not matches:
        return None, None, "no match on libc.rip"
    best = matches[0]
    url = best.get("download_url")
    if not url:
        return None, best, "best match has no download_url"
    name = (best.get("id") or "libc") + ".so"
    dest = os.path.join(dest_dir, os.path.basename(name))
    size, derr = download_libc(url, dest, timeout=timeout)
    if derr:
        return None, best, derr
    return dest, best, None


# --- offline: a folder of candidate libc files -------------------------------
def _libc_symbols(path):
    """Exported symbol offsets of a libc file (+ str_bin_sh when possible)."""
    syms = {}
    if HAVE_PWNTOOLS:
        try:
            e = ELF(path, checksec=False)
            for name, addr in e.symbols.items():
                if isinstance(name, str) and addr:
                    syms[name] = addr
            sh = next(e.search(b"/bin/sh\x00"), None)
            if sh is not None:
                syms["str_bin_sh"] = sh
            return syms
        except Exception:
            pass
    if have("nm"):
        for line in run(["nm", "-D", "--defined-only", path]).splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    syms[parts[-1]] = int(parts[0], 16)
                except ValueError:
                    pass
    return syms


def local_candidates(libs_dir, leaks):
    """Return [(filename, symbols_dict), ...] whose symbols match every leak."""
    cands = []
    for fn in sorted(os.listdir(libs_dir)):
        path = os.path.join(libs_dir, fn)
        if not os.path.isfile(path):
            continue
        syms = _libc_symbols(path)
        if syms and symbol_matches(leaks, syms):
            cands.append((fn, syms))
    return cands


# --- display -----------------------------------------------------------------
_KEY_SYMS = ("system", "str_bin_sh", "puts", "printf", "read", "write",
             "dup2", "execve", "__libc_start_main_ret", "__libc_start_main")


def _show_resolved(leaks, symbols):
    base, resolved = resolve(leaks, symbols)
    if base is not None:
        kv = f"{C.DIM}libc base{C.RST} {C.CY}{hex(base)}{C.RST}"
        print(f"      {kv}")
        for s in _KEY_SYMS:
            if s in symbols:
                print(f"        {s:<22} off {C.GR}{hex(symbols[s])}{C.RST}"
                      f"   addr {C.CY}{hex(resolved[s])}{C.RST}")
    else:
        for s in _KEY_SYMS:
            if s in symbols:
                print(f"        {s:<22} off {C.GR}{hex(symbols[s])}{C.RST}")


def cmd_libcid(leak_pairs, libs=None, online=True, timeout=10, download=None):
    hdr("libc identify")
    try:
        leaks = parse_leaks(leak_pairs)
    except ValueError as e:
        bad(str(e))
        return
    info("leaks: " + ", ".join(f"{k}={hex(v)}" for k, v in leaks.items()))

    if libs:
        if not os.path.isdir(libs):
            bad(f"not a directory: {libs}")
            return
        info(f"matching against local libc files in {libs} ...")
        cands = local_candidates(libs, leaks)
        if not cands:
            bad("no local libc matched all leaks")
            info("add more leaks, or check the folder has the right libc files.")
            return
        good(f"{len(cands)} local match(es):")
        for fn, syms in cands:
            good(f"{fn}")
            _show_resolved(leaks, syms)
        return

    if not online:
        warn("offline mode needs --libs DIR; nothing to do")
        return
    info("querying libc.rip (sends only the symbol offsets above) ...")
    matches, err = query_libc_rip(leaks, timeout=timeout)
    if err:
        bad(err)
        info("offline alternative:  ctfkit libcid --leak ... --libs <dir-of-libcs>")
        return
    if not matches:
        bad("libc.rip found no match (try adding another leaked symbol)")
        return
    good(f"{len(matches)} match(es) from libc.rip:")
    for m in matches[:8]:
        name = m.get("id") or m.get("buildid") or "?"
        good(f"{name}")
        if m.get("download_url"):
            print(f"      {C.DIM}{m['download_url']}{C.RST}")
        _show_resolved(leaks, _match_symbols_to_ints(m.get("symbols")))
    if len(matches) > 8:
        info(f"... and {len(matches) - 8} more (add another leak to narrow it down)")

    if download is not None:
        if len(matches) > 1:
            warn("multiple matches; downloading the first — add a leak to be sure")
        best = matches[0]
        dest_dir = download if isinstance(download, str) else "."
        url = best.get("download_url")
        if not url:
            bad("best match has no download_url")
            return
        info(f"downloading {best.get('id')} from {url} ...")
        dest = os.path.join(dest_dir, os.path.basename((best.get("id") or "libc") + ".so"))
        size, derr = download_libc(url, dest, timeout=max(timeout, 30))
        if derr:
            bad(derr)
            return
        good(f"saved {C.BOLD}{dest}{C.RST} ({size} bytes)")
        info(f"next:  ctfkit pwn <bin> --libc {dest}")
