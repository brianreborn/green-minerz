# green-minerz

Privilege-isolated Windows mining workers.
High-priv orchestrator (NiceHash and equivalents) launches miners as today; `nhwrap.exe` is the IFEO interposer that drops the worker to Medium IL, proxies stdio, and returns the miner’s exit code.

Private: https://github.com/brianreborn/green-minerz

## Layout

- `docs/NH-WRAP-ARCH-001.md` — architecture spec (open questions resolved)
- `src/` — native C++17 wrapper (PR-01, not started)
- `setup/` — installer / IFEO allowlist (PR-09)
- `tests/` — fake miner, loop, privilege, IFEO lab (PR-01…PR-10)

## Not in v1

- Dedicated `NHMiner` account (mode 0 only)
- Session-0 GPU mining
- Loading WinRing0 as the only MSR driver
- Public IFEO hooks for arbitrary image names
