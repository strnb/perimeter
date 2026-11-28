"""ctfkit - CTF helper for Linux ELF x86-64 (rev + pwn).

A small toolkit that automates the boring first 10 minutes of a rev/pwn
challenge: triage, exploit-skeleton generation, ROP/GOT helpers.

Works best with pwntools installed; degrades gracefully to readelf/objdump/nm
so it stays useful even on a bare remote box.

Vendored into Perimeter from the standalone project rev-pwn
(https://github.com/Demian-Chern/rev-pwn, MIT). Imported here as the
``core.modules.ctfkit`` subpackage; all internal imports are relative, so the
package runs unchanged. Exposed to the CLI/UI through ``api.revpwn`` and the
``perimeter rev ...`` passthrough command.
"""

__version__ = "1.0.0"
