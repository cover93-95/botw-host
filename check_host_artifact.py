#!/usr/bin/env python3
"""Refuse a host build that holds anything of a game, on the runner, before it is uploaded.

Usage: check_host_artifact.py <BotWHost.app.zip> <host_exports.txt>

The job has no game file to leak. This checks that it stayed so: the patch or a later change could still let
recompiled code or a stray file through.
"""
import re, sys, zipfile

FORBIDDEN_NAMES = re.compile(r"(^|/)(generated|game|content|code|meta)(/|$)|Guest\.framework|U-King|\.(rpx|rpl|wud|wux|key|keys|tik|tmd|h3|sarc|pack|sbfres|bfres|nsp|xci|nca|ipa)$", re.I)
GUEST_SYMBOL = re.compile(r"^_(f_[0-9a-f]{8}|g_guest_functions|g_guest_imports)$")
RPX_MAGIC = b"\x7fELF\x01\x02\x01\xca\xfe"
MAX_EXECUTABLE = 150 * 1024 * 1024   # The real binary with the game's code is 383 MB. The host alone must be far below.
REQUIRED_EXPORTS = {"_rt_call", "_rt_trap", "_rt_unimplemented", "_rt_bad_return", "_g_mem", "_botw_split_ping"}


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
    print("no game file, no recompiled code, and the host exports what a framework binds")


if __name__ == "__main__":
    main()
