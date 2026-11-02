#!/usr/bin/env python3
"""Refuse a host build that holds anything of a game, on the runner, before it is uploaded.

Usage: check_host_artifact.py <BotWHost.app.zip> <host_exports.txt>

The job has no game file to leak. This checks that it stayed so: the patch or a later change could still let
recompiled code or a stray file through.
"""
import plistlib, re, struct, sys, zipfile

FORBIDDEN_NAMES = re.compile(r"(^|/)(generated|game|content|code|meta)(/|$)|Guest\.framework|U-King|\.(rpx|rpl|wud|wux|key|keys|tik|tmd|h3|sarc|pack|sbfres|bfres|nsp|xci|nca|ipa)$", re.I)
GUEST_SYMBOL = re.compile(r"^_(f_[0-9a-f]{8}|g_guest_functions|g_guest_imports)$")
RPX_MAGIC = b"\x7fELF\x01\x02\x01\xca\xfe"
MAX_EXECUTABLE = 150 * 1024 * 1024   # The real binary with the game's code is 383 MB. The host alone must be far below.
ONLY_MEMORY_LIMIT = {"com.apple.developer.kernel.increased-memory-limit": True}
REQUIRED_EXPORTS = {"_rt_call", "_rt_trap", "_rt_unimplemented", "_rt_bad_return", "_g_mem", "_botw_split_ping", "_botw_boot_step"}


def signature_entitlements(exe):
    """The entitlements plist in a thin executable's signature, or None."""
    if len(exe) < 32 or struct.unpack_from("<I", exe, 0)[0] != 0xFEEDFACF:
        return None
    at, where = 32, None
    for _ in range(struct.unpack_from("<I", exe, 16)[0]):
        cmd, size = struct.unpack_from("<2I", exe, at)
        if cmd == 0x1D:
            where = struct.unpack_from("<2I", exe, at + 8)
        at += size
    if not where or struct.unpack_from(">I", exe, where[0])[0] != 0xFADE0CC0:
        return None
    blob = exe[where[0]:where[0] + where[1]]
    for i in range(struct.unpack_from(">I", blob, 8)[0]):
        kind, offset = struct.unpack_from(">2I", blob, 12 + i * 8)
        if kind == 5:
            magic, size = struct.unpack_from(">2I", blob, offset)
            return blob[offset + 8:offset + size] if magic == 0xFADE7171 else None
    return None


def entitlement_problems(exe, requested):
    """Exactly the memory limit, asked for and signed in. Extended addressing needs a paid team, and the tests pass without it."""
    out = []
    try:
        wanted = plistlib.loads(requested)
    except Exception:
        return ["requested.entitlements is missing or unreadable"]
    if wanted != ONLY_MEMORY_LIMIT:
        out.append("requested.entitlements asks for something else: %s" % sorted(wanted))
    raw = signature_entitlements(exe)
    if raw is None:
        return out + ["the host's signature holds no entitlements"]
    try:
        signed = plistlib.loads(raw)
    except Exception:
        return out + ["the signature's entitlements are unreadable"]
    if signed != ONLY_MEMORY_LIMIT:
        out.append("the signature holds something else: %s" % sorted(signed))
    return out


def problems(zip_path, exports_path):
    out = []
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        for i in infos:
            if FORBIDDEN_NAMES.search(i.filename):
                out.append("forbidden file: %s" % i.filename)
            if i.is_dir():
                continue
            with z.open(i) as f:
                if f.read(len(RPX_MAGIC)) == RPX_MAGIC:
                    out.append("a Wii U executable: %s" % i.filename)
        executables = [i for i in infos if i.filename.count("/") == 1 and i.filename.endswith("/BotWRecomp")]
        if len(executables) != 1:
            out.append("the app's executable was not found")
        elif executables[0].file_size > MAX_EXECUTABLE:
            out.append("the executable is %d MiB: it may hold recompiled code" % (executables[0].file_size >> 20))
        if len(executables) == 1:
            names = {i.filename for i in infos}
            requested = "BotWRecomp.app/requested.entitlements"
            out += entitlement_problems(z.read(executables[0]), z.read(requested) if requested in names else b"")
            if any("_CodeSignature" in n for n in names):
                out.append("a bundle seal, which adding the framework would break")
    with open(exports_path, encoding="utf-8") as f:
        exports = {l.strip() for l in f if l.strip()}
    guest = sorted(s for s in exports if GUEST_SYMBOL.match(s))
    if guest:
        out.append("%d symbols of recompiled code, such as %s" % (len(guest), guest[0]))
    missing = sorted(REQUIRED_EXPORTS - exports)
    if missing:
        out.append("not exported, so Guest.framework could not bind: %s" % missing)
    if not any(s.startswith("_hle_") for s in exports):
        out.append("no hle_ symbol is exported")
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    found = problems(sys.argv[1], sys.argv[2])
    for p in found:
        print("REFUSED:", p)
    if found:
        sys.exit(1)
    print("no game file, no recompiled code, the host exports what a framework binds, and it asks for the memory limit alone")


if __name__ == "__main__":
    main()
