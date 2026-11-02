# BotW host build

Builds the iOS host of [BotWRecomp](https://github.com/IshaanKalra2103/BotWRecomp) on GitHub Actions, for people with no Mac.

**This repository holds no game file, no key and no recompiled code, and neither does what it builds.** The host does nothing on its own: without a separately built `Guest.framework`, it only runs a memory diagnostic. There is no download-and-play build here, and there will not be one.

| File | Purpose |
|---|---|
| `host-split.patch` | Lets the host build without `generated/` and load `Guest.framework` at launch |
| `check_host_artifact.py` | Refuses an artifact holding anything of a game, before upload |
| `.github/workflows/build-host.yml` | Started by hand only, unsigned output |

Licenses: see `NOTICE.md`.
