# Privilege-Isolated Interposition Process Wrapper for Windows

**Project:** [green-minerz](https://github.com/brianreborn/green-minerz)  
**Subtitle:** Mining Worker Sandboxing and Hardware Acceleration Specification  
**Author:** Brian Fundakowski Feldman  
**Date:** 2026-09-01  
**Status:** Draft — open questions resolved  
**Document ID:** NH-WRAP-ARCH-001  
**Revision:** 2026-09-01-oq-resolved  
**Primary implementation language:** Native C++17 (console subsystem Win32 EXE), alternatively Rust (`windows` / `windows-sys` crates)  
**Non-production reference:** PowerShell / .NET `ProcessStartInfo` algorithm in Appendix A  

---

## Overview

High-privilege mining orchestrators (NiceHash Miner and equivalents) currently launch third-party miner binaries in the same security context as the parent. That couples GPU/CPU tuning that *does* need a brief administrative token (Model-Specific Register / kernel-driver initialization) with long-running untrusted worker code that *must not* retain that token. A compromised or malicious miner then inherits a High integrity administrative primary token, IFEO-writable HKLM access (if the parent is admin), and the ability to persist.

This design introduces a signed, installer-deployed **interposer** (`nhwrap.exe`) registered as the Image File Execution Options (IFEO) `Debugger` for an **allowlist** of miner image names. Windows therefore launches the interposer *instead of* the miner. The interposer:

1. Parses the IFEO argument vector correctly (`argv[1]` is the original command-line image token — often a path, sometimes a relative name; see §1.3). The `Debugger` REG_SZ must contain **no extra switches** so the target stays at argv[1] after `CommandLineToArgvW`.
2. Breaks IFEO re-entry with a dual-layer bypass (environment sentinel + ancestry) plus a **technically reliable** spawn path that does not re-hit IFEO.
3. Optionally runs a **synchronous, elevated, recursion-safe** hardware preflight (e.g. XMRig `--msr-only`).
4. Drops to a Medium integrity, non-admin primary token and creates the miner in that context.
5. Proxies stdin/stdout/stderr across the privilege boundary until exit, then returns the miner’s exit code so the orchestrator believes it still launched the miner.

The production binary is a small native console EXE. PowerShell is explicitly **not** the IFEO debugger: it is slow to cold-start, AV-hostile, and a poor parent for job objects and overlapped I/O.

---

## Background & Motivation

### Current state

Orchestrators call `CreateProcess` / .NET `Process.Start` on vendor miners (`xmrig.exe`, `lolminer.exe`, `t-rex.exe`, etc.) with `CreateNoWindow`, redirected stdio, and (often) an elevated token so RandomX MSR helpers and vendor GPU tools succeed. Pain points:

| Pain | Effect |
|------|--------|
| Long-lived admin token in miner process | RCE in miner = full machine compromise |
| IFEO not used today | No central policy point; every orchestrator reimplements launch |
| MSR setup racy | `Sleep` after spawning WinRing0-style tools; hashrate regression if MSR not committed |
| Stdio in headless jobs | `[Console]::KeyAvailable` throws `InvalidOperationException` when there is no console |
| PID-based “parent checks” | WMI `ParentProcessId` races with PID reuse |

### Why IFEO

IFEO `Debugger` is **user-mode `CreateProcess` / `KERNELBASE!CreateProcessInternalW` command-line prepending**, not a kernel image rewrite. It does not require hooking `CreateProcess` inside NiceHash, does not poll the filesystem, and matches by **image basename** regardless of the miner’s install directory. The orchestrator’s existing launch code is unchanged. It does **not** intercept raw `NtCreateUserProcess` (some packers/native helpers); those callers use `--run` or remain unwrapped (residual bypass). `ShellExecuteEx` typically ends in `CreateProcess` and **is** intercepted. The cost is that IFEO `Debugger` is also **MITRE ATT&CK T1546.012** (persistence). This product therefore treats IFEO writes as an **explicit, elevating installer action** on a miner allowlist, never as a per-launch side effect, and never for `System32` or arbitrary EXEs.

---

## Goals & Non-Goals

### Goals

- Intercept allowlisted miner image names **globally** (any directory, any parent) via IFEO.
- Split privilege: brief High IL use for hardware preflight; permanent Medium IL for the worker.
- Transparent stdio and exit-code compatibility with NiceHash-style parsers.
- Recursion-safe child spawn for both preflight and sandboxed worker.
- Job-object lifetime coupling: killing the wrapper kills the miner and its descendants.
- Bounded, concurrency-safe logging.
- Authenticode-signed installer that can set Defender exclusions **narrowly** and remove all persistence on uninstall.

### Non-Goals

- A general-purpose application sandbox (no Chromium-style GPU process broker, no Win32k lockdown).
- Hiding mining from the user or from AV (this is a disclosed, installed product).
- Hooking all of `System32` or intercepting `cmd.exe` / `powershell.exe`.
- Guaranteeing MSR/GPU preflight success on locked-down machines without a signed driver.
- Running the miner at Low integrity by default (GPU device interfaces often fail at Low IL).
- Implementing the miner algorithms themselves.
- Cross-OS support (this document is Windows 10 21H2+ / Windows 11 / Server 2019+).

---

## SYSTEM REQUIREMENTS SUMMARY MATRIX

| FUNCTIONAL ELEMENT | CORE OPERATIONAL MECHANISM | CRITICAL TRAP TO AVOID |
| --- | --- | --- |
| Interception Rule | Registry-driven IFEO `Debugger` hijacking hooks under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary_name.exe>` (`CreateProcessInternalW` prepend; **not** a kernel image rewrite) | Index parsing error: with a Debugger value that is **only** quoted `nhwrap.exe` (no extra switches), the original image token is **index 1**, not 0; naive `split(' ')` breaks quoted paths with spaces; argv[1] may be a relative name |
| Loop Prevention | Dual-layer: distinct environment sentinel **and** process-tree lineage verification, plus a spawn path that skips IFEO | Relying on environment variables alone (child runtimes can scrub blocks); treating NiceHash as a *bypass* ancestor (that is the *intercept* case); WMI PID reuse; re-executing the same image name without a skip |
| Token Sandboxing | Restricted / linked filtered token or dedicated standard user via `CreateProcessWithLogonW` / `CreateProcessAsUser` / `CreateProcessWithTokenW` | .NET `UseShellExecute=false` + `UserName`/`Password` Access Denied; `cmd.exe /c` string concatenation (argument injection); leaking an admin primary token into the child |
| Hardware Injection | Synchronous privileged Ring-0 MSR/driver preflight (`WaitForSingleObject` on process handle with **bounded** `MsrTimeoutMs`, default 30000; then `TerminateProcess`) | Race conditions; never guess via `Sleep` as success. Never default to `INFINITE` (wrong flags can start a full elevated miner). Preflight is itself IFEO-visible. MSRs persist until overwritten, reset, or reboot — not “forever” |
| Conduit Proxying | Concurrent stdout/stderr reader threads (or overlapped named pipes) + stdin pump on the OS handle | Headless crashes from `[Console]::KeyAvailable`; reading only stdout (stderr fill → child deadlock); dropping the miner’s exit code |
| Storage Protection | Pre-write log size check, mutex-guarded rotate to timestamped archive, 10 MiB ceiling | Unbounded log growth filling the system drive during multi-week mining runs; unsynchronized rotate tearing the file under concurrent wrapper instances |

---

## Key Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| KD-1 Implementation language | Signed native **C++17** console EXE (`nhwrap.exe`); Rust acceptable | IFEO debugger is invoked on the hot path of every miner start. PowerShell cold-start is 200–800 ms+ and AV-flagged. Native gives job objects, tokens, overlapped I/O, and a single Authenticode subject. |
| KD-2 IFEO scope | **Allowlist of miner image names only**, written by the elevated installer | IFEO Debugger is T1546.012. Hooking `*.exe` or `System32` is unacceptable. |
| KD-3 Re-entry bypass | Honor **Layer A (env)** + **Layer B (ancestry)** as required; **correct** the NiceHash ancestor rule; add **Layer C (IFEO-safe spawn)** | Env can be stripped. WMI is slow/racy. Re-launching `xmrig.exe` by name **always** re-enters IFEO. NiceHash as parent is the *intended intercept*, not a bypass. |
| KD-4 IFEO-safe spawn | **Spawn-API matrix (mandatory):** C1 `DEBUG_*` only on in-process `CreateProcessW` / `CreateProcessAsUserW`. **Never** pass `DEBUG_*` into `CreateProcessWithTokenW` / `CreateProcessWithLogonW` (seclogon becomes the debugger; child freezes). Production intercept: **AsUser+C1** if `SeAssignPrimaryTokenPrivilege` is available; else **C2 alternate filename in the miner directory** + WithTokenW; depth-2 chain is last resort. | IFEO keys by **image filename**. Seclogon is not nhwrap. Sibling drivers need `GetModuleFileNameW` in the miner dir (C2 must not use `%ProgramData%` as the module dir). |
| KD-5 Privilege drop | **v1 ships mode 0 only:** linked filtered token (`TokenLinkedToken`) or `CreateRestrictedToken` (Administrators deny-only, Medium IL). Dedicated `NHMiner` / `CreateProcessWithLogonW` is **not a v1 SKU** (documented future/unsupported). `cmd.exe /c` is **compatibility-only**, not production. | Passwordless; no second account; no WinSta ACL widen. (Resolved OQ-2.) |
| KD-6 Integrity level | Miner: **Medium IL** default; Low IL opt-in (`ForceLowIL`) behind GPU soak. **Wrapper stays High IL in v1** (inherited from elevated parent). | Low IL often cannot open GPU devices. Wrapper drop-after-spawn is deferred (Resolved OQ-3). |
| KD-7 Hardware preflight | Allowlist-driven; **version-specific MSR flag table** from `xmrig --help` / `--version`; refuse preflight if `--help` lacks the configured flag; **skip preflight if `WinRing0x64.sys` is the only adjacent MSR driver**; bounded wait (`MsrTimeoutMs` default 30000, then `TerminateProcess`); fail-open default | Wrong flags can start a full elevated miner. WinRing0 is unsigned/vulnerable (Resolved OQ-1, OQ-5). |
| KD-8 Stdio | Anonymous pipes + two reader threads + one stdin pump; optional overlapped named pipes | Anonymous pipes deadlock if stdout and stderr are not both drained. No console APIs in the headless path. |
| KD-9 Lifetime | Job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Parent killing the wrapper must kill the miner and grandchildren. |
| KD-10 Defender exclusion | **Installer-only**, file or wrapper-directory scope, never whole volumes | Exclusions are a favorite malware trick; the hot path must not call `Add-MpPreference`. |
| KD-11 Logging | `%ProgramData%\NiceHash\Sandbox\logs` with named mutex rotate **or** per-PID files plus a size-capped shared audit log | Multiple miners = multiple wrappers. Uncoordinated `MoveFile` loses data. |
| KD-12 Identity | Authenticode-sign wrapper + installer; Event Log source `NiceHash-Sandbox` | Distinguishes the product from commodity IFEO malware. |
| KD-13 WOW64 IFEO | Installer **always writes both** native and Wow6432Node IFEO views. Single 64-bit `nhwrap.exe`. **No `nhwrap32.exe` in v1.** Lookup is caller bitness (PR-10 four-tuple). | 64-bit NiceHash launching a 32-bit miner still reads the native view (Resolved OQ-6). |
| KD-14 Session 0 | v1: CPU RandomX in session 0 supported (best-effort); **GPU in session 0 unsupported**. No `nhwrap-agent.exe` in v1. | Session 0 device isolation (Resolved OQ-4). |

**Spec correction (KD-3 detail):** The source requirement said to bypass if any ancestor matches the orchestrator name *or* the wrapper. Because IFEO replaces the miner, **the wrapper’s parent on the intended path *is* NiceHash**. Interpreting that literally would disable sandboxing for the only customer that matters. **Bypass when:** (A) `NICEHASH_SANDBOX_BYPASS` is set in *this* process (inherited by helpers unless they rebuild the environment), **or** (B) an ancestor image is `nhwrap.exe` (re-entry), **or** (C) helper spawn: parent is `nhimg_*.exe` / imgcache, **or** an ancestor’s original allowlisted target matches. **Do not bypass** merely because `NiceHash*` appears in the tree.

**KD-4 production intercept (does not reverse KD-4; composes with token drop):**

1. **Preferred:** `CreateProcessAsUserW` + C1 (`DEBUG_ONLY_THIS_PROCESS`) on the **original path** when `SeAssignPrimaryTokenPrivilege` can be enabled (also enables `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
2. **Default when AsUser is unavailable (typical desktop elevated process has `SeImpersonate` but not `SeAssignPrimaryToken`):** C2 **hardlink in the miner’s directory** (`xmrig.exe` → `nhimg_<hash>.exe` next to WinRing0) + `CreateProcessWithTokenW` / `WithLogonW` with **no** `DEBUG_*`.
3. **Last resort:** depth-2 chain (outer token API on the IFEO-hooked name, inner nhwrap Layer A + in-process C1). Pipe/job ownership in §2.7.

---

## Proposed Design

### 3.1 Components and trust boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Interactive session or service session (orchestrator)                  │
│  NiceHash Miner (often High IL if “as admin”)                           │
│    CreateProcess("C:\\Miners\\xmrig.exe", args, redirected stdio)       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ IFEO Debugger (CreateProcessInternalW prepend)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  nhwrap.exe  [High IL only if parent was elevated — inherited token]    │
│  TRUSTED COMPUTING BASE for this feature                                │
│    • parse argv                                                         │
│    • Layer A/B bypass decision                                          │
│    • MSR preflight (elevated, IFEO-safe spawn, WaitForExit)             │
│    • token filter / logon                                               │
│    • job object + pipes                                                 │
│    • stdio proxy threads                                                │
│    • exit(minerExitCode)                                                │
└─────────────┬───────────────────────────────┬───────────────────────────┘
              │ preflight (elevated, short)   │ worker (Medium IL, long)
              ▼                               ▼
     xmrig --msr-only                  xmrig <original args>
     (IFEO-safe spawn)                 (IFEO-safe spawn
                                        + bypass env
                                        + restricted token)
```

**Trust boundary:** Anything after `CreateProcessAsUser`/`WithLogonW` is untrusted. The child must never receive a handle to the wrapper’s primary admin token, an inheritable handle to `\\.\WinRing0`, or a writable handle to HKLM IFEO keys (HKLM is already admin-only — keep ACLs that way).

### 3.2 End-to-end sequence

```mermaid
sequenceDiagram
    autonumber
    participant NH as Orchestrator (NiceHash)
    participant K as KERNELBASE CreateProcessInternalW / IFEO
    participant W as nhwrap.exe
    participant MSR as Preflight miner (elevated)
    participant M as Sandboxed miner (Medium IL)

    NH->>K: CreateProcess(xmrig.exe, args, pipes)
    K->>K: IFEO Debugger = nhwrap.exe
    K->>W: CreateProcess(nhwrap.exe, argv[1]=xmrig path, argv[2..]=args)
    Note over W: Parent PID is NiceHash. This is INTERCEPT, not bypass.
    W->>W: CommandLineToArgvW; isolate target = argv[1]
    W->>W: Layer A: env NICEHASH_SANDBOX_BYPASS?
    W->>W: Layer B: walk ancestors (NT + optional CIM)
    alt bypass (re-entry / sentinel)
        W->>K: IFEO-safe CreateProcess(real image)
        K->>M: miner (inherit std handles)
        W->>W: WaitForSingleObject(miner); ExitProcess(exitCode)
    else intercept (normal)
        opt target on MSR allowlist and token is elevated
            W->>MSR: IFEO-safe spawn --msr-only (elevated)
            W->>W: WaitForSingleObject(preflight, MsrTimeoutMs); timeout TerminateProcess; NO Sleep
            MSR-->>W: exit code
        end
        W->>W: Build restricted/linked token (Medium IL)
        W->>W: Create pipes + JobObject (KILL_ON_JOB_CLOSE)
        W->>M: Spawn matrix: AsUser+C1 or C2+WithTokenW<br/>(never DEBUG_* on seclogon); env BYPASS; HANDLE_LIST or inherit-strip
        par stdout thread
            M-->>W: ReadFile stdout
            W-->>NH: WriteFile wrapper stdout
        and stderr thread
            M-->>W: ReadFile stderr
            W-->>NH: WriteFile wrapper stderr
        and stdin thread
            NH-->>W: ReadFile wrapper stdin
            W-->>M: WriteFile miner stdin
        end
        W->>W: Wait process + drain pipes
        W-->>NH: ExitProcess(miner exit code)
    end
```

### 3.3 Process model and data flow

```mermaid
flowchart TD
    A[nhwrap main] --> B{Layer A: BYPASS env?}
    B -->|yes| P[Passthrough: IFEO-safe spawn + inherit stdio + wait]
    B -->|no| C{Layer B: ancestor is nhwrap?}
    C -->|yes| P
    C -->|no| D[Log intercept + ancestry snapshot]
    D --> E{Image on MSR allowlist AND High IL?}
    E -->|yes| F[Preflight: IFEO-safe elevated --msr-only]
    F --> G[WaitForSingleObject h MsrTimeoutMs then TerminateProcess on timeout]
    G --> H{Preflight exit 0?}
    H -->|no| I[Apply failure policy]
    I --> J[Token drop]
    H -->|yes| J
    E -->|no| J
    J --> K[Pipes + Job + spawn matrix AsUser+C1 or C2+WithTokenW]
    K --> L[Proxy stdio concurrently]
    L --> M[Wait + drain]
    M --> N[Exit with miner code]
    P --> N
```

---

## MODULE 1: Interception & Execution Engine

### 1.1 IFEO mechanism (accurate semantics)

Substitution happens in **user-mode** `KERNELBASE!CreateProcessInternalW` when `DEBUG_PROCESS` / `DEBUG_ONLY_THIS_PROCESS` are **absent**. The API **prepends** the `Debugger` REG_SZ to the **command line**. `lpApplicationName` of the original call is **discarded**. `PROCESS_INFORMATION` / `STARTUPINFO` describe the **debugger** (`nhwrap.exe`) — which is what we want (NiceHash waits on nhwrap). `NtCreateUserProcess` participates via `IFEOSkipDebugger` for the DEBUG case; it does **not** by itself start nhwrap instead of xmrig. Callers of raw `NtCreateUserProcess` **never hit** the wrapper (residual bypass; use `--run`).

**Native 64-bit registry view** (read by a **64-bit caller** of `CreateProcess`, regardless of target image bitness):

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image_name.exe>
  Debugger (REG_SZ) = ArgvQuote(C:\Program Files\NiceHash\Sandbox\nhwrap.exe, forceQuote=true)
```

**WOW64 32-bit registry view** (read by a **32-bit caller** of `CreateProcess`, regardless of target image bitness):

```
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image_name.exe>
  Debugger (REG_SZ) = ArgvQuote(C:\Program Files\NiceHash\Sandbox\nhwrap.exe, forceQuote=true)
```

The installer (64-bit) writes **both** views. Lookup is **caller bitness**, not miner bitness (Miskelly / IFEO docs):

| View | `RegOpenKeyEx` flag | Who reads it |
|------|---------------------|--------------|
| Native 64-bit IFEO | `KEY_WOW64_64KEY` | **64-bit parent** `CreateProcess` (64-bit or 32-bit miner) |
| Wow6432Node IFEO | `KEY_WOW64_32KEY` | **32-bit parent** `CreateProcess` (32-bit or 64-bit miner) |

| Parent | Miner | IFEO view used | Debugger image |
|--------|-------|----------------|----------------|
| 64-bit NiceHash | 64-bit xmrig | native | 64-bit `nhwrap.exe` |
| 64-bit NiceHash | 32-bit miner | **native** (not Wow64) | 64-bit `nhwrap.exe` |
| 32-bit parent | 32-bit miner | Wow6432Node | 64-bit `nhwrap.exe` (32-bit `CreateProcess` may start a 64-bit debugger on x64) |
| 32-bit parent | 64-bit miner | **Wow6432Node** | 64-bit `nhwrap.exe` |

v1 ships **one** 64-bit `nhwrap.exe`. Prove the four tuples in PR-10. Do not register a 32-bit wrapper unless a later PR adds a Wow64 build.

**Image name only.** `C:\a\xmrig.exe` and `D:\b\xmrig.exe` share the key `xmrig.exe`.

**`Debugger` value must contain no extra switches** (not `nhwrap.exe --run`, not `ntsd -g`). Otherwise `CommandLineToArgvW` shifts the target off argv[1]. Always write `ArgvQuote(WrapperPath, forceQuote=true)` so `Program Files` spaces do not split argv.

**Argv layout when Debugger is a single quoted path:**

| Index | Content |
|------:|---------|
| 0 | Interposer (`nhwrap.exe`) |
| 1 | Original command-line **image token** (path or relative name — **not** guaranteed absolute) |
| 2..N | Remainder of the original command line after that token |

If the parent passed `lpApplicationName = C:\Miners\xmrig.exe` and `lpCommandLine = "xmrig --url …"` (legal), nhwrap sees `argv[1] == "xmrig"`, **not** the absolute path. See §1.3 resolution.

Re-executing `xmrig.exe` by that filename, from any directory, **re-enters IFEO** unless C1/C2 applies.

`GlobalFlag`, `VerifierDlls`, `UseFilter`, and IFEO **filters** (`FilterFullPath`) are not installed in v1 (see Alternative A5). The installer must not clobber existing filter subkeys or foreign `Debugger` values (§1.7).

### 1.2 Modes: IFEO vs `--run` vs `--version`

```
nhwrap.exe --version
nhwrap.exe --run -- <target> [args…]
nhwrap.exe --run <target> [args…]          # also accepted; -- is optional if target does not start with -
nhwrap.exe <target> [args…]                # IFEO CreateProcessInternalW-prepended (production)
```

| Mode | Detection | Target index | Notes |
|------|-----------|--------------|-------|
| `--version` | `argv[1]` is `--version` or `-V` | n/a | Print `nhwrap <semver> <git>` to stdout, exit 0. No IFEO, no spawn. |
| `--run` | `argv[1]` is `--run` | First token after optional `--` | Explicit intercept **without** requiring IFEO. Used by tests, opt-in orchestrators, and **`NtCreateUserProcess` launchers** that skip IFEO. Still applies Layer A/B/C, preflight, token drop, proxy. |
| IFEO | otherwise | `argv[1]` | Debugger prepended; argv[1] is the original command-line image token. |

`--run` is **not** a bypass. Bypass is only Layer A/B (and the inner instance of Layer C).

If `Enabled=0` in policy, every mode except `--version` is forced passthrough (IFEO-safe spawn of target with inherited stdio, no token drop, no preflight).

### 1.3 Command-line parsing

**Do not** split on spaces. **Do not** use `std::wistringstream`.

```cpp
int argc = 0;
LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
if (!argv) { /* Event 3001, ExitProcess(ERROR_INVALID_PARAMETER) */ }
// LocalFree(argv) on all exit paths
```

**IFEO mode:** `argc < 2` → Event 3001, exit `ERROR_INVALID_PARAMETER` (87). **Never search `PATH`.** **Never call `PathFindOnPathW`** for allowlisted miners (search-order hijack: a decoy `xmrig.exe` on `PATH` would be preflighted **elevated**).

**Self path:** `GetModuleFileNameW(nullptr, …)` then `GetFinalPathNameByHandleW` if possible. Never trust `argv[0]` for identity.

**Target resolution (argv[1] is not always absolute):**

```
function ResolveTarget(argv1):
  if argv1 is empty: fail 87
  base = PathFindFileNameW(argv1)

  if PathIsRelativeW(argv1) == FALSE:
    return GetFullPathNameW(argv1)          # includes \\?\ ; use as-is

  # Parent used lpApplicationName vs lpCommandLine split; token is a basename.
  # (1) cwd ONLY if the file exists AND basename is allowlisted.
  cwdCandidate = GetFullPathNameW(argv1)    # relative to inherited cwd
  if FileExists(cwdCandidate) AND IsAllowlisted(base):
    return cwdCandidate

  # (2) MinerSearchPath only (installer-recorded miner dirs). NEVER PATH.
  for dir in MinerSearchPath:
    p = dir + "\\" + base
    if FileExists(p) AND IsAllowlisted(base):
      return p

  # (3) Unresolved: keep argv1 as-is and spawn anyway so the orchestrator
  # sees ERROR_FILE_NOT_FOUND (2). Do NOT PathFindOnPathW.
  # Log Event 3003 with unresolved token. Do NOT preflight an unresolved relative name.
  return argv1
```

`--run` callers **must** pass an absolute target path (record it; do not resolve via PATH). Installer/agent should write discovered miner directories into `MinerSearchPath` when miners are installed.

**Fixtures required:** (1) quoted absolute path (Appendix C.1); (2) `lpApplicationName` full path + `lpCommandLine` starting with basename `xmrig`; (3) cwd ≠ miner directory, `PATH` contains a **decoy** `xmrig.exe`, `MinerSearchPath` contains the real miner dir → **real one wins**; decoy must **not** be resolved or preflighted; (4) relative token with empty `MinerSearchPath` and no cwd hit → unresolved, no `PathFindOnPathW`.

### 1.4 Reconstructing `lpCommandLine` (quoting rules)

`CreateProcessW` requires a **writable** `lpCommandLine`. The child sees `CommandLineToArgvW` of that string. `PathQuoteSpacesW` is **insufficient**: it does not escape embedded `"`.

Use this encoder for **each** argument (Windows / CRT rules: `2n` backslashes + `"` → `n` backslashes and a quote delimiter; `2n+1` backslashes + `"` → `n` backslashes and a literal `"`):

```
function ArgvQuote(s, forceQuote):
  if s is empty:
    return "\"\""
  needsQuote = forceQuote OR s contains any of { space, tab, VT, '"' }
                OR s is empty
  if not needsQuote:
    return s
  out = "\""
  bs = 0
  for c in s:
    if c == '\\':
      bs += 1
    else:
      if c == '"':
        out += '\\' * (bs * 2 + 1)
        out += '"'
      else:
        out += '\\' * bs
        out += c
      bs = 0
  out += '\\' * (bs * 2)     # trailing backslashes before the closing quote
  out += '"'
  return out
```

**Child command line:**

```
cmdLine = ArgvQuote(lpApplicationNameOrTarget, forceQuote=true)
for i in minerArgs:           # argv[2..] in IFEO mode
  cmdLine += " "
  cmdLine += ArgvQuote(argv[i], forceQuote=false)
```

`lpApplicationName` is the **unquoted** filesystem path (original or IFEO-safe cache path). `lpCommandLine` is the quoted string above. Passing both avoids `PATH` search and keeps argv[0] aligned with the image when possible.

When launching via C2, `lpApplicationName` is the **alternate filename in the miner directory** (`…\Miners\nhimg_<hash>.exe`). IFEO matches on-disk filename, not argv[0]. **Do not rely on cwd or argv[0] for WinRing0 / OpenCL kernels** — miners use `GetModuleFileNameW` (module directory). C2 in the miner dir keeps that directory unchanged. If a cache **must** live elsewhere (AppLocker blocks miner-dir writes), **copy declared siblings** into that cache dir (see §2.5 C2).

### 1.5 Allowlist matching

Policy `Allowlist` is `REG_MULTI_SZ` of filenames (`xmrig.exe`, `lolminer.exe`, …).

```
function IsAllowlisted(targetPath):
  name = PathFindFileNameW(targetPath)      # "xmrig.exe"
  for entry in Allowlist:
    if CompareStringOrdinal(name, entry, TRUE) == CSTR_EQUAL:
      return true
  return false
```

- Case-insensitive, **filename only** (no directory glob, no `*\xmrig.exe`).
- `.EXE` vs `.exe` matches.
- If not allowlisted: **passthrough immediately** (defense in depth). Event 1001 `reason=not-allowlisted`.

`MsrAllowlist` uses the same matcher. `OrchestratorNames` is `REG_MULTI_SZ` of filenames (`NiceHashMiner.exe`, `NiceHash.exe`, …) plus optional prefix rule: if policy `OrchestratorPrefix` is `NiceHash`, match `CompareStringOrdinal` length-prefix case-insensitive **only for Layer B intercept classification**, never for IFEO hooks.

### 1.6 Policy registry (exact types)

Key: `HKLM\SOFTWARE\NiceHash\Sandbox`  
Open with `KEY_WOW64_64KEY` from the 64-bit wrapper. Installer writes 64-bit view only for policy (wrapper is 64-bit).

| Name | Type | Default | Meaning |
|------|------|---------|---------|
| `Enabled` | `REG_DWORD` | 1 | 0 = force passthrough |
| `WrapperPath` | `REG_SZ` | install path of `nhwrap.exe` | Identity + IFEO expected Debugger data |
| `Allowlist` | `REG_MULTI_SZ` | see installer | IFEO image names |
| `MsrAllowlist` | `REG_MULTI_SZ` | `xmrig.exe` | Preflight images |
| `MsrArgs` | `REG_SZ` | `--msr-only` | Fallback flag if `MsrFlagTable` has no row for the probed version. Still **refused** if `--help` does not contain it. |
| `MsrTimeoutMs` | `REG_DWORD` | 30000 | Preflight `WaitForSingleObject` timeout; then `TerminateProcess`. **Not INFINITE.** Consumer: §4.3 |
| `ForceSkipMsr` | `REG_DWORD` | 0 | 1 = never preflight. Consumer: §4.2 |
| `OrchestratorNames` | `REG_MULTI_SZ` | `NiceHashMiner.exe` | Layer B classification |
| `OrchestratorPrefix` | `REG_SZ` | `NiceHash` | Layer B filename prefix only; **never** an IFEO hook. Empty = prefix match off. Consumer: §1.5 |
| `BypassEnvName` | `REG_SZ` | `NICEHASH_SANDBOX_BYPASS` | Layer A |
| `BypassEnvValue` | `REG_SZ` | `TRUE` | Layer A expected value |
| `LowPrivMode` | `REG_DWORD` | 0 | **v1: must be 0.** 1 (dedicated `NHMiner`) is not a shipped SKU; if set, log Event 2009 and still spawn mode 0. |
| `GpuForceMode0` | `REG_DWORD` | 1 | **v1: locked to 1 in product** — all intercepts use mode 0. Installer writes 1; runtime ignores 0 (treat as 1, Event 2009). No `GpuAllowlist`. `xmrig.exe` is GPU-capable → mode 0. Consumer: §3.7–3.8 |
| `KeepSeImpersonate` | `REG_DWORD` | 0 | 1 = do not strip `SeImpersonatePrivilege` from miner token. Consumer: §3.4 |
| `FailMsr` | `REG_DWORD` | 0 | 0 fail-open; 1 fail-closed |
| `ForceLowIL` | `REG_DWORD` | 0 | 1 = Low IL (experimental) |
| `LogMaxBytes` | `REG_DWORD` | 10485760 | 10 MiB |
| `IfeoSkipMode` | `REG_DWORD` | 0 | 0 = auto (probe); 1 = force C1 DEBUG skip (AsUser/CreateProcessW only); 2 = force C2 miner-dir hardlink |
| `NhMinerUser` | `REG_SZ` | `NHMiner` | **Not used in v1** (mode 1 not shipped). Retained for a future SKU. |
| `MsrFlagTable` | `REG_SZ` (JSON) or built-in | see §4.4 | Version → flag map; runtime still requires the flag to appear in `--help` |
| `LogDir` | `REG_SZ` | `%ProgramData%\NiceHash\Sandbox\logs` | |
| `MinerSearchPath` | `REG_MULTI_SZ` | empty | Extra dirs for relative argv[1] resolution (**not PATH**). Consumer: §1.3 |
| `C2DestList` | `REG_MULTI_SZ` | empty | Absolute paths of every C2 `nhimg_*.exe` created (miner dir and off-dir cache). Wrapper appends under a named mutex after successful hardlink/copy. Consumer: §2.5, uninstall U1b |
| `DeclaredSiblings` | `REG_MULTI_SZ` | `WinRing0x64.sys`, `WinRing0.sys`, `xmrig.sys` | Copied next to off-dir C2 cache if C2 cannot use miner dir. Consumer: §2.5 |
| `DefenderExclusions` | `REG_MULTI_SZ` | empty | Recorded installer exclusions for uninstall. Consumer: §6.4 |

Missing key → default. Corrupt type → Event 3006, default, do not crash. **v1.1 / not implemented:** per-image `MsrArgs`, `GpuPreflight`, AppContainer, `NHMiner` mode 1, `nhwrap-agent`, `nhwrap32.exe`.

### 1.7 IFEO conflict detection (installer)

For each allowlisted `imageName` and each view `{64, 32}`:

```
1. RegCreateKeyEx(IFEO\<imageName>, KEY_READ|KEY_WRITE|viewFlag)  # creates empty key if absent
2. RegQueryValueEx(Debugger)
   a. ERROR_FILE_NOT_FOUND or empty REG_SZ:
        write Debugger = ArgvQuote(WrapperPath, forceQuote=true)   # ALWAYS quoted; Program Files has spaces
        record undo: DELETE_VALUE Debugger (if key was empty) or restore previous
   b. Normalize: strip surrounding quotes from existing Debugger, GetFullPathNameW,
      CompareStringOrdinal(TRUE) against WrapperPath:
        equal → idempotent success (ours). Uninstall uses the same normalize.
   c. else:
        CONFLICT. Do not write. Append to conflict[] {imageName, view, existingDebugger}
        continue other images
3. If UseFilter (REG_DWORD) == 1:
        enumerate subkeys; if any subkey has Debugger != ours → CONFLICT for that image
        v1 does not install filter subkeys
```

Install continues for non-conflicting images. UI lists conflicts. Exit code of installer is 0 if **at least** the core wrapper files were copied; conflicts are warnings (Event 2004) unless `/strict-ifeo` is passed (then rollback IFEO writes from this session).

---

## MODULE 2: Recursion Loop Eradication (Ancestry Verification)

### 2.1 Why a loop exists

```
NiceHash → (IFEO) nhwrap → CreateProcess("xmrig.exe") → (IFEO) nhwrap → ...
```

CPU peg, handle exhaustion, log flood. Both **MSR preflight** and the **sandboxed miner** use the same image name unless Layer C skips IFEO.

**`cmd.exe /c set NICEHASH_SANDBOX_BYPASS=TRUE && xmrig.exe …` does not skip IFEO.** It only injects Layer A for the *next* wrapper instance. If that inner wrapper then `CreateProcess("xmrig.exe")` without Layer C, the loop continues. Production never uses `cmd.exe` as an IFEO skip.

### 2.2 Layer A — Environment sentinel (required)

**Read at wrapper startup** (before spawn):

```
name  = policy.BypassEnvName or L"NICEHASH_SANDBOX_BYPASS"
value = buffer from GetEnvironmentVariableW(name)
truthy = CompareStringOrdinal(value, L"TRUE", TRUE)==CSTR_EQUAL
      OR CompareStringOrdinal(value, L"1", TRUE)==CSTR_EQUAL
      OR CompareStringOrdinal(value, L"YES", TRUE)==CSTR_EQUAL
```

If truthy: Event 1001 `reason=env`; **passthrough** (§2.6). No preflight, no token drop.

**Write on every child create** (intercept miner, preflight, passthrough spawn): build a new Unicode environment block; do not mutate `GetEnvironmentStringsW` in place.

```
function BuildEnvBlock(inheritFromCurrent=true):
  map = parse current env as UTF-16 key=value pairs (if inherit)
  map[BypassEnvName] = BypassEnvValue          # overwrite
  serialize as k=v\0 k=v\0 \0                  # CREATE_UNICODE_ENVIRONMENT
```

### 2.3 Layer B — NT ancestry walk (authoritative)

WMI/CIM is **required as a documented dual-layer path** but is **not** the authority. Authority is NT process information + create-time checks.

#### 2.3.1 Structures

```cpp
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;               // this PID
    ULONG_PTR InheritedFromUniqueProcessId;  // parent PID (reuse-prone)
} PROCESS_BASIC_INFORMATION;

// NtQueryInformationProcess(ProcessBasicInformation = 0)
```

`InheritedFromUniqueProcessId` is a PID, **not** a 64-bit unique start key. Always pair with `GetProcessTimes` `ftCreationTime`.

#### 2.3.2 Handle lifetime and algorithm

```
constant MAX_DEPTH = 64

struct Ancestor {
  DWORD pid
  FILETIME createUtc
  wstring imagePath          # QueryFullProcessImageNameW PROCESS_NAME_NATIVE=0
  bool truncatedEdge         # OpenProcess failed or createTime inversion
}

function GetCreateTime(hProcess) -> FILETIME:
  GetProcessTimes(hProcess, &create, &exit, &kernel, &user)
  return create

function WalkAncestry() -> vector<Ancestor>:
  result = []
  pid = GetCurrentProcessId()
  childCreate = GetCreateTime(GetCurrentProcess())
  depth = 0

  while depth < MAX_DEPTH and pid != 0 and pid != 4:
    h = (pid == GetCurrentProcessId())
        ? GetCurrentProcess()
        : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)

    if h == NULL:
      result.append({pid, {0,0}, L"", truncated:true})
      break    # truncated edge — NOT a wrapper match

    pbi = {}
    status = NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)
    if status != 0:
      if h != GetCurrentProcess(): CloseHandle(h)
      result.append({pid, {0,0}, L"", truncated:true})
      break

    create = GetCreateTime(h)
    if depth > 0 AND CompareFileTime(&create, &childCreate) > 0:
      # alleged parent started AFTER child → PID reuse
      if h != GetCurrentProcess(): CloseHandle(h)
      result.append({pid, create, L"", truncated:true})
      break

    path[32768]
    QueryFullProcessImageNameW(h, 0, path, &len)  # if fail, path empty → no match

    result.append({pid, create, path, truncated:false})

    parentPid = (DWORD)pbi.InheritedFromUniqueProcessId
    if parentPid == pid: break                 # cycle
    if h != GetCurrentProcess(): CloseHandle(h)
    childCreate = create
    pid = parentPid
    depth += 1

  return result
```

**PID-reuse predicate:** accept an edge only if `parent.CreateTime <= child.CreateTime`. Failed `OpenProcess` = truncated, **not** a match.

**Match helpers:**

```
IsWrapperImage(path):
  PathFindFileName equals "nhwrap.exe" (ordinal ignore-case)
  AND (
    CompareStringOrdinal(GetFinalPath(path), GetFinalPath(selfModule), TRUE) == CSTR_EQUAL
    OR Authenticode publisher of path equals publisher of self   # if either unsigned, path match only
  )

IsOrchestrator(path):
  filename in OrchestratorNames OR prefix policy matches
  # classification only — does NOT bypass

IsC2WorkerImage(path):
  filename matches nhimg_*.exe (prefix "nhimg_", suffix ".exe")
  OR path is under %ProgramData%\NiceHash\Sandbox\imgcache\

IsAllowlistedAncestorImage(path):
  PathFindFileName(path) is in Allowlist   # original miner name if C1
  OR IsC2WorkerImage(path)                 # C2 live worker name

IsSameMinerImage(path, target):
  PathFindFileName(path) equals PathFindFileName(target)  # ignore-case
  OR IsC2WorkerImage(path)
```

**Decision (KD-3):**

```
# Layer A is also the helper skip: sandboxed miner inherits BYPASS in its
# environment block. Grandchildren that CreateProcess(NULL env) inherit it.
# Miners that rebuild lpEnvironment without the sentinel still need Layer B.

nodes = WalkAncestry()          # nodes[0] is self (nhwrap)
wrapperCount = count(nodes[1..] where IsWrapperImage)
nhwrapTotal  = 1 + wrapperCount
minerHelper  = any nodes[1..] where IsAllowlistedAncestorImage && !IsWrapperImage
truncated    = any truncatedEdge

if nhwrapTotal > 2:
  Event 3005
  emergency C2 in miner dir (CreateProcessW, inherit stdio, no token drop)
  if spawn fails: ExitProcess(0xE0003005)
  wait; propagate exit

if wrapperCount >= 1:
  BYPASS reason=ancestor

if minerHelper:
  BYPASS reason=miner-helper   # C1 parent xmrig.exe OR C2 parent nhimg_*.exe

if truncated AND not EnvHasBypass:
  INTERCEPT
  log warning 2005 truncated-ancestry

# NiceHash in the tree ⇒ INTERCEPT (not bypass)
INTERCEPT
```

### 2.4 Layer B — CIM/WMI fallback (200 ms)

Used when NT `NtQueryInformationProcess` is unavailable **or** for diagnostic snapshots written to the log. Must not delay launch > 200 ms.

**Query (Win32_Process = CIM_Process):**

```
SELECT ProcessId, ParentProcessId, CreationDate, CommandLine, ExecutablePath
FROM Win32_Process
WHERE ProcessId = <pid>
```

| Field | Use |
|-------|-----|
| `ProcessId` | Current node |
| `ParentProcessId` | Next PID (reuse-prone) |
| `CreationDate` | DMTF datetime → `FILETIME`; same inversion check as NT |
| `ExecutablePath` | Image match |
| `CommandLine` | Log only (redact); detect prior wrapper command line |

**Timeout algorithm:**

```
1. Start a worker thread (or use IWbemContext timeout if available).
2. Worker: CoInitializeEx(COINIT_MULTITHREADED)
   CoCreateInstance(CLSID_WbemLocator)
   ConnectServer(L"ROOT\\CIMV2")
   CoSetProxyBlanket (default)
   ExecQuery(WQL, query)
   parse first object; walk parents with same query up to 64; apply CreateTime check
3. Main: WaitForSingleObject(worker, 200)
   if WAIT_TIMEOUT: abandon (do not TerminateThread); treat CIM as unavailable; NT result stands
   if worker failed: NT result stands
```

CIM `CreationDate` parse: DMTF `yyyymmddHHMMSS.mmmmmmsUUU` via `SystemTimeToFileTime` after `swscanf`. If parse fails, edge is truncated.

Never require WMI service (`winmgmt`) to be healthy for mining to start.

### 2.5 Layer C — IFEO-safe spawn sequences and API matrix

Layer C is **not** a substitute for A/B. A/B decide intercept vs passthrough. C is how **any** spawn of an allowlisted image name avoids an infinite debugger chain.

**Not sufficient:** `\\?\` prefix; full path; `cmd.exe /c` of the same filename.

#### Spawn matrix (mandatory)

`CreateProcessWithTokenW` and `CreateProcessWithLogonW` RPC to **Secondary Logon (`seclogon`)**. If `DEBUG_*` is set, **seclogon** is the debugger, not nhwrap. `DebugActiveProcessStop` in nhwrap then fails or is a no-op; the child sits on the initial debug break (“70 KB frozen image”). Those APIs also take `LPSTARTUPINFOW`, **not** `STARTUPINFOEX` / `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.

| API | IFEO skip | Debugger of child | Allowed? |
|-----|-----------|-------------------|----------|
| `CreateProcessW` | C1 `DEBUG_ONLY_THIS_PROCESS` | **nhwrap** (caller) | **yes** (passthrough, preflight, inner depth-2) |
| `CreateProcessAsUserW` | C1 `DEBUG_ONLY_THIS_PROCESS` | **nhwrap** (in-process `CreateProcessInternalW`) | **yes** — **preferred production intercept** when `SeAssignPrimaryTokenPrivilege` is enabled. Also supports `STARTUPINFOEX` + `HANDLE_LIST`. |
| `CreateProcessWithTokenW` | **must not pass `DEBUG_*`** | seclogon if flags set | C1 **forbidden**. Use **C2** (alternate filename) or depth-2 last resort. |
| `CreateProcessWithLogonW` | **must not pass `DEBUG_*`** | seclogon if flags set | C1 **forbidden**. Same as WithTokenW. |

**Production intercept composition:**

| Priority | When | Spawn | Skip |
|----------|------|-------|------|
| 1 | `SeAssignPrimaryTokenPrivilege` present or enableable (`AdjustTokenPrivileges`) | `CreateProcessAsUserW` + filtered primary token + `HANDLE_LIST` | **C1** on original path (`GetModuleFileNameW` preserved) |
| 2 | Else (typical elevated desktop: `SeImpersonate` only) | `CreateProcessWithTokenW` / `WithLogonW` | **C2** hardlink **in the miner directory**; **no DEBUG_*** |
| 3 | C2 cannot write miner dir (ACL/AppLocker) **and** AsUser unavailable | Depth-2 chain §2.7 | Outer: token API **without DEBUG_*** on hooked name; inner: Layer A + `CreateProcessW` C1 |

`SpawnIfeoSafe` = in-process `CreateProcessW`/`CreateProcessAsUserW` + optional C1/C2.  
`SpawnSandboxed` **composes** the matrix above; it must **not** OR `DEBUG_*` into WithTokenW/WithLogonW.

#### Sequence C1 — `DEBUG_ONLY_THIS_PROCESS` (in-process APIs only)

Preserves `GetModuleFileNameW` = original path (WinRing0 sibling lookup).

```
1. Assert caller is CreateProcessW or CreateProcessAsUserW. If WithTokenW/WithLogonW: FAIL (use C2).
2. dwFlags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
   OR in CREATE_NO_WINDOW if intercept
   OR in CREATE_NEW_PROCESS_GROUP if we will GenerateConsoleCtrlEvent
   OR in EXTENDED_STARTUPINFO_PRESENT if using HANDLE_LIST (AsUser)
3. Strip inherit on all handles except the three miner pipe ends (§5.2), or pass HANDLE_LIST.
4. lpApplicationName = original target path (unquoted)
   lpCommandLine     = ArgvQuote reconstruction (writable buffer)
   lpEnvironment     = BuildEnvBlock() including BYPASS=TRUE
   lpCurrentDirectory = dirname(original target)
5. CreateProcessW / CreateProcessAsUserW(...)
   on failure: do not retry DEBUG on a seclogon API; go to C2
6. DebugActiveProcessStop(pi.dwProcessId) immediately
   if Stop fails:
        for i in 1..32:
          WaitForDebugEvent(&ev, 50)
          ContinueDebugEvent(..., DBG_CONTINUE)
          DebugActiveProcessStop(...)
          if Stop succeeds: break
7. if hJob: AssignProcessToJobObject(hJob, pi.hProcess)   # still SUSPENDED
8. ResumeThread(pi.hThread)
9. CloseHandle(pi.hThread); retain pi.hProcess
```

#### Sequence C2 — Alternate filename **in the miner directory**

IFEO matches basename; `nhimg_<hash>.exe` next to `xmrig.exe` does not match `xmrig.exe`. **`GetModuleFileNameW` is the miner directory**, so WinRing0/`*.json`/OpenCL kernels resolve. **Do not rely on cwd or argv[0].**

Same-directory hardlink is always same-volume (no `ERROR_NOT_SAME_DEVICE` for the EXE itself).

```
1. canonical = GetFullPathNameW(original)
   dir = dirname(canonical)
   GetFileAttributesEx → ftLastWriteTime, nFileSize
   key = SHA256(UTF16(canonical) || FILETIME || DWORD64 size)
   dest = dir + "\\nhimg_" + first16hex + ".exe"
2. if dest exists and size+time match: reuse
   else:
        DeleteFile(dest) if stale
        CreateHardLinkW(dest, canonical)
        if hardlink fails (FAT, AppLocker, ERROR_ACCESS_DENIED):
             CopyFileW(canonical, dest, FALSE)
3. ACL dest: SYSTEM+Administrators FILE_ALL_ACCESS; Users/NHMiner FILE_GENERIC_READ|EXECUTE;
   no Everyone write.
   Record dest: append absolute dest to HKLM C2DestList (RegSetValue MULTI_SZ) under
   mutex Local\NiceHashSandbox.C2DestList; also write a line to
   %ProgramData%\NiceHash\Sandbox\c2-dests.txt (same mutex) as backup manifest.
   Cleanup: uninstall U1b deletes recorded dests; plus 7-day unused scavenge of
   nhimg_*.exe adjacent to allowlisted images (crash-before-uninstall).
4. CreateProcess* with lpApplicationName = dest, **no DEBUG_*** on WithTokenW/WithLogonW
   lpCommandLine may ArgvQuote(canonical) as argv[0] (does not affect IFEO)
   lpCurrentDirectory = dir
   env includes BYPASS=TRUE
   CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW  (never DEBUG_*)
5. Assign job; ResumeThread
```

**Off-directory cache (last resort only):** if miner-dir write is impossible, dest = `%ProgramData%\NiceHash\Sandbox\imgcache\nhimg_<hex>.exe`. Then **copy every `DeclaredSiblings` name** from `dir` into the cache dir (same basename). Append dest to `C2DestList` the same as miner-dir C2. AppLocker/WDAC often **deny** `ProgramData\*.exe` — treat as unsupported unless policy allows; prefer failing spawn with Event 3003 over a miner that cannot load WinRing0.

Installer probe sets `IfeoSkipMode=2` when C1 on AsUser/CreateProcessW still re-enters; it must **not** conclude C1 works based on a WithTokenW test.

#### Sequence C3 — `NtCreateUserProcess` skip (optional, never only path)

Undocumented `PS_CREATE_INFO` / create flags on some builds omit IFEO debugger application. Feature-detect; not required for v1 if C1+C2 exist.

### 2.6 Passthrough implementation

Not `ShellExecute`. Not `cmd.exe`. Inner/Layer A passthrough uses **`CreateProcessW` + C1** (in-process). Never `Start-Process` / WithTokenW of the hooked basename.

| Parameter | Value |
|-----------|--------|
| `lpApplicationName` | Original path if C1; miner-dir `nhimg_*.exe` if C2 |
| `lpCommandLine` | Quoted original target + `argv[2..]` |
| `bInheritHandles` | Prefer `FALSE` + `HANDLE_LIST` of `{inRd,outWr,errWr}` or current std handles. If inherit TRUE: strip all other inherit bits first (§5.2). |
| `lpEnvironment` | Block **with** BYPASS |
| Token | Current (already low-priv if inner wrapper) |
| Wait | `WaitForSingleObject(hProcess, INFINITE)` on the **miner** (passthrough is not preflight) → `GetExitCodeProcess` → `ExitProcess(code)` |

### 2.7 Depth-2 chain (last resort) — pipe and job ownership

Used only when production rows 1–2 of the composition table cannot run.

```
Outer nhwrap (intercept; may still be High IL):
  1. Create pipes (§5.2). Parent-facing: outRd, errRd, inWr.
     Miner-facing (inheritable): outWr, errWr, inRd.
  2. Strip HANDLE_FLAG_INHERIT on EVERY other handle in the process.
  3. CreateJobObject KILL_ON_JOB_CLOSE; do not inherit hJob.
  4. CreateProcessWithTokenW / WithLogonW(
       lpApplicationName = original hooked path,   # IFEO WILL fire
       NO DEBUG_* flags,
       env with BYPASS=TRUE,
       STARTF_USESTDHANDLES = miner-facing ends,
       CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW)
     → pi.hProcess is INNER nhwrap (already filtered token), NOT the miner.
  5. AssignProcessToJobObject(hJob, inner) while SUSPENDED.
  6. CloseHandle(outWr, errWr, inRd) in OUTER.
  7. ResumeThread(inner). Proxy stdio on parent-facing ends until INNER exits.
  8. WaitForSingleObject(inner); ExitProcess(inner exit code).

Inner nhwrap (Layer A hits immediately):
  1. Do not create new pipes. STD_* handles ARE outWr/errWr/inRd.
  2. Do not drop token again. Do not preflight.
  3. CreateProcessW + C1 of ResolveTarget(argv[1]) with:
       bInheritHandles according to §5.2 for current std handles only
       STARTF_USESTDHANDLES copying GetStdHandle(*) to the miner
  4. After miner CreateProcess: SetStdHandle STD_OUTPUT/ERROR to NUL (or Close
     the write ends) so pipe EOF occurs when the MINER exits, not when inner exits.
  5. WaitForSingleObject(miner, INFINITE); ExitProcess(miner code).
     Miner is in the outer job (child of job member, no BREAKAWAY_OK).
```

**Who holds stdout write ends:** after step 6 outer, only inner (then only miner after inner step 4). **Who is in the job:** inner + miner + miner grandchildren. **Who proxies:** outer only.

Maximum live `nhwrap` = 2. Depth > 2 → Event 3005.

---

## MODULE 3: Privilege Drop & Impersonation Handoff

### 3.1 Objective

Miner **primary** token:

- `BUILTIN\Administrators` not enabled (deny-only OK).
- Privileges in §3.4 stripped (or `DISABLE_MAX_PRIVILEGE`).
- Integrity **Medium** `S-1-16-8192` (Low only if `ForceLowIL=1`).
- User: **filtered same user (mode 0) only in v1.** Mode 1 `NHMiner` is not a shipped SKU.

The **wrapper process stays High IL in v1** (inherited from an elevated parent) so it can log to `%ProgramData%` and hold the job object. Only the child drops. Do not `SetTokenInformation` Medium on the wrapper after spawn.

### 3.2 Why `.NET` `UseShellExecute=false` + credentials fails

`ProcessStartInfo` with `RedirectStandard* = true` forces `UseShellExecute = false`, which uses `CreateProcess` / `CreateProcessWithLogonW`, not `ShellExecuteEx`.

When `UserName`/`Password` are also set:

1. Older .NET Framework calls `CreateProcessWithLogonW` **without** `LOGON_WITH_PROFILE` or with a `STARTUPINFO` the secondary logon service rejects → **Win32 5 `ERROR_ACCESS_DENIED`**.
2. Stdio redirection creates anonymous pipes whose DACL is the **caller**. The child runs as another user in another logon session and **cannot** write the pipe → Access Denied or a hung miner.
3. The target user often has **no ACE** on `WinSta0` / `Default` desktop.
4. `UseShellExecute=true` cannot redirect stdio at all — so the “easy” credential path and the parser-compatible path are mutually exclusive in .NET.

**Honored workaround (Appendix A only):** launch `cmd.exe` with `UseShellExecute=false` and credentials, passing `set BYPASS && miner`. That still **does not skip IFEO**, is **argument-injection-prone**, and is not production.

**Native path does not use `UseShellExecute` or `cmd.exe`.** Pipe DACLs must grant the miner user (see §5.2).

### 3.3 API selection

| API | When | Privileges required by **wrapper** |
|-----|------|-------------------------------------|
| `CreateProcessAsUserW` | **Preferred production intercept** when `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege` can be enabled | C1 DEBUG skip legal; `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` legal |
| `CreateProcessWithTokenW` | Mode 0 when AsUser unavailable (`SeImpersonatePrivilege` only) | **No `DEBUG_*`.** C2 miner-dir name or depth-2. No `HANDLE_LIST` (type is `LPSTARTUPINFOW`) — inherit-strip instead |
| `CreateProcessWithLogonW` | **Not used in v1** (mode 1 not shipped) | Future SKU only. Secondary Logon; **no `DEBUG_*`** |

v1 uses AsUser or WithTokenW only. Explicit `lpEnvironment` with bypass; `STARTF_USESTDHANDLES`; no `cmd.exe`.

### 3.4 Passwordless token construction (mode 0)

```
OpenProcessToken(GetCurrentProcess(),
  TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES)

GetTokenInformation(TokenElevationType, ...)

if TokenElevationTypeFull:                          # elevated admin
    GetTokenInformation(TokenLinkedToken, &hLinked, sizeof(HANDLE), ...)
    DuplicateTokenEx(hLinked, TOKEN_ALL_NEEDED, NULL,
                     SecurityImpersonation, TokenPrimary, &hPrimary)
                     # SecurityIdentification is a common CreateProcessWithTokenW failure;
                     # use SecurityImpersonation even though the result is a primary token.
    CloseHandle(hLinked)
    # hPrimary is already UAC-filtered: Medium IL, Administrators deny-only.
    # Do NOT CreateRestrictedToken(LUA_TOKEN|DISABLE_MAX_PRIVILEGE) again on a
    # linked Limited token — often ERROR_INVALID_PARAMETER / a useless token.
    if ForceLowIL: SetTokenInformation TokenIntegrityLevel Low only (no second LUA_TOKEN)
    else: leave linked token as-is (skip StripAndSetIL LUA path)

else:                                               # already limited / default
    DuplicateTokenEx(hCurrent, TOKEN_ALL_NEEDED, NULL,
                     SecurityImpersonation, TokenPrimary, &hPrimary)
    if TokenElevationType != TokenElevationTypeLimited:
        StripAndSetIL(hPrimary)                     # LUA_TOKEN allowed here
    else if ForceLowIL:
        SetTokenInformation IL Low only
    else:
        skip LUA_TOKEN

optional WinSafer (`safer.h`) instead of hand-roll:
    SaferCreateLevel(SAFER_SCOPEID_MACHINE, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &level, NULL)
    SaferComputeTokenFromLevel(level, hPrimary, &hSafer, 0, NULL)
    SaferCloseLevel(level)
    replace hPrimary with hSafer
    Test both Safer and linked-token paths in PR-05.
```

**`StripAndSetIL`:**

```
Administrators  S-1-5-32-544
Power Users     S-1-5-32-547          # disable if present
Backup Operators S-1-5-32-551         # disable if present

SID_AND_ATTRIBUTES disableSids[] = {
  { Administrators, 0 },
  { PowerUsers, 0 },                  # omit if CreateWellKnownSid fails
}

CreateRestrictedToken(
    hPrimary,
    DISABLE_MAX_PRIVILEGE | LUA_TOKEN,   # LUA_TOKEN = 0x4
    disableCount, disableSids,
    0, NULL,                             # extra privilege deletes redundant with DISABLE_MAX_PRIVILEGE
    0, NULL,
    &hRestricted)

# If CreateRestrictedToken fails, fall back to hPrimary if it is already Medium and non-elevated;
# else fail Event 3002.

Integrity:
    CreateWellKnownSid(ForceLowIL ? WinLowLabelSid : WinMediumLabelSid, ...)
    TOKEN_MANDATORY_LABEL tml
    tml.Label.Sid = sid
    tml.Label.Attributes = SE_GROUP_INTEGRITY
    SetTokenInformation(hRestricted, TokenIntegrityLevel, &tml, size)

Privilege strip list if DISABLE_MAX_PRIVILEGE is not used (must delete these):
    SeDebugPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege,
    SeAssignPrimaryTokenPrivilege, SeCreateTokenPrivilege,
    SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege,
    SeSecurityPrivilege, SeSystemEnvironmentPrivilege, SeRelabelPrivilege,
    SeManageVolumePrivilege
    SeImpersonatePrivilege   # unless KeepSeImpersonate=1
    # Keep SeChangeNotifyPrivilege (usually undeletable).
    # DISABLE_MAX_PRIVILEGE also drops SeIncreaseBasePriorityPrivilege, which some
    # GPU schedulers want. If GPU scheduling fails, prefer linked token WITHOUT a
    # second DISABLE_MAX_PRIVILEGE (the UAC filter already removed admin privileges)
    # rather than re-adding random privileges.
```

Never duplicate the **elevated** primary token into the child. Never pass `hCurrent` to `CreateProcessWithTokenW`. Before spawn, strip `HANDLE_FLAG_INHERIT` on **all** handles except the three miner pipe ends (§5.2) so a Medium child cannot receive a duplicated elevated token or `\\.\WinRing0` handle.

### 3.5 `CreateProcess*` parameter tables

Common `STARTUPINFOW`:

| Field | Value |
|-------|--------|
| `cb` | `sizeof(STARTUPINFOW)` |
| `dwFlags` | `STARTF_USESTDHANDLES` |
| `hStdInput` | miner stdin read end |
| `hStdOutput` | miner stdout write end |
| `hStdError` | miner stderr write end |
| `lpDesktop` | `winsta0\\default` if target session is interactive; `NULL` if session 0 CPU-only |
| `lpTitle` | NULL |

Common `dwCreationFlags`: `CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`  
(`CREATE_NO_WINDOW` on intercept; omit on passthrough inherit.)  
**Never** OR `DEBUG_PROCESS` / `DEBUG_ONLY_THIS_PROCESS` into `CreateProcessWithTokenW` / `CreateProcessWithLogonW`. C1 flags only on `CreateProcessW` / `CreateProcessAsUserW`.

#### `CreateProcessWithTokenW`

| Arg | Value |
|-----|--------|
| `hToken` | restricted/linked **primary** |
| `dwLogonFlags` | 0 (or `LOGON_WITH_PROFILE` if profile must load — usually 0 for linked token of already-logged-on user) |
| `lpApplicationName` | C2 `nhimg_*.exe` in miner dir (not the IFEO-hooked basename, unless depth-2 last resort) |
| `lpCommandLine` | writable quoted command |
| `dwCreationFlags` | common flags **without** `DEBUG_*` |
| `lpEnvironment` | Unicode block with bypass |
| `lpCurrentDirectory` | original miner directory |
| `lpStartupInfo` | table above |
| `lpProcessInformation` | out |

#### `CreateProcessAsUserW`

| Arg | Value |
|-----|--------|
| `hToken` | primary (must be primary, not impersonation) |
| `lpStartupInfo` | `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` = `{inRd, outWr, errWr}` when intercepting; `EXTENDED_STARTUPINFO_PRESENT` |
| `dwCreationFlags` | common flags **plus** `DEBUG_ONLY_THIS_PROCESS` for C1 |
| Wrapper must enable `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` in **its** token (`AdjustTokenPrivileges`) before the call. |

#### `CreateProcessWithLogonW` (mode 1 — **future SKU only, not v1**)

| Arg | Value |
|-----|--------|
| `lpUsername` | `NHMiner` |
| `lpDomain` | `.` |
| `lpPassword` | retrieved from LSA secret; **SecureZeroMemory** after call |
| `dwLogonFlags` | `LOGON_WITH_PROFILE` |
| remaining | same as WithTokenW; **do not** pass `cmd.exe`; **do not** pass `DEBUG_*`; C2 `lpApplicationName` |

After success: `AssignProcessToJobObject` then `ResumeThread`.

### 3.6 Dedicated `NHMiner` account (mode 1) — **not a v1 SKU**

Do **not** implement installer `NetUserAdd` / LSA secret / `CreateProcessWithLogonW` in v1. Text below is a future SKU only.

Installer-only, elevated (future):

```
USER_INFO_1 ui = {}
ui.usri1_name     = L"NHMiner"
ui.usri1_password = cryptographically random 16 bytes → printable (or 128-bit hex)
ui.usri1_priv     = USER_PRIV_USER
ui.usri1_home_dir = NULL
ui.usri1_comment  = L"NiceHash sandbox worker"
ui.usri1_flags    = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE | UF_NORMAL_ACCOUNT
ui.usri1_script_path = NULL
NetUserAdd(NULL, 1, (LPBYTE)&ui, &err)
```

If `NERR_UserExists`, do not reset the password unless `/reset-nhminer-password`.

**Rights (LSA `LsaAddAccountRights` / `LsaRemoveAccountRights`):**

| Right | Action |
|-------|--------|
| `SeBatchLogonRight` | **Grant** (needed for some non-interactive creates) |
| `SeInteractiveLogonRight` | Grant **only if** `CreateProcessWithLogonW` probe returns 1385 `ERROR_LOGON_TYPE_NOT_GRANTED` |
| `SeDenyNetworkLogonRight` | Grant (optional harden) |
| `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTcbPrivilege` | **Remove** if present |

`NetLocalGroupAdd` `NHSandboxUsers`; `NetLocalGroupAddMembers` `NHMiner`. ACL miner dirs RX for that group.

**LSA secret layout:**

| Item | Value |
|------|--------|
| Secret name | `NHWRAP_NHMINER_PWD` (LSA private data; not a service `_SC_` secret unless we add a service) |
| API | `LsaOpenPolicy` (`POLICY_CREATE_SECRET \| POLICY_GET_PRIVATE_INFORMATION`) → `LsaStorePrivateData` / `LsaRetrievePrivateData` |
| Payload | UTF-16 password bytes; length in `LSA_UNICODE_STRING` |
| ACL | default LSA (SYSTEM + Administrators) |
| Wrapper | retrieves at intercept spawn when `LowPrivMode=1`; never writes the secret at launch; `SecureZeroMemory` |

Do not store the password in `HKLM`, a file, or the log.

### 3.7 Window station / desktop ACLs

Linked-token mode (same user): child keeps access to the parent’s `WinSta0\Default`. No ACL change.

**v1 ships mode 0 only** (`GpuForceMode0=1` locked). **All intercepts** use the linked/restricted token of the wrapper user. `LowPrivMode=1` / `NHMiner` / WinSta ACL surgery is **unsupported future** — runtime must not create or logon `NHMiner`. `xmrig.exe` is GPU-capable → mode 0.

Dedicated account into an **interactive** session (**not v1**; kept for a future SKU):

```
1. OpenWindowStationW(L"winsta0", FALSE, READ_CONTROL | WRITE_DAC)
2. GetUserObjectSecurity → add ACE for NHMiner SID — MINIMUM, not WINSTA_ALL_ACCESS:
     WINSTA_READATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | WINSTA_ENUMDESKTOPS |
     WINSTA_ENUMERATE | WINSTA_READSCREEN | WINSTA_WRITEATTRIBUTES
     (add WINSTA_CREATEDESKTOP only if 0xC0000142 persists in soak)
3. OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL | WRITE_DAC)
4. Add ACE: DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW |
     DESKTOP_CREATEMENU | STANDARD_RIGHTS_REQUIRED
     — NOT DESKTOP_ALL / GENERIC_ALL (screenshot + input injection).
```

Without some desktop access, `CreateProcessWithLogonW` may succeed then the child dies with `0xC0000142`. This ACL still re-exposes the interactive session to a compromised `NHMiner` (threat table). Prefer mode 0 for GPU.

Do **not** grant these ACLs to Everyone. Do not weaken the IFEO key ACL.

### 3.8 Session 0 vs interactive matrix

| Parent | Session | Token mode | CPU RandomX | GPU CUDA/OpenCL | v1 policy |
|--------|---------|------------|-------------|-----------------|-----------|
| NiceHash desktop, as admin | Interactive N | Mode 0 linked | Works | Usually works at Medium IL | **Supported** |
| NiceHash desktop, as admin | Interactive N | Mode 1 NHMiner | n/a | n/a | **Not a v1 SKU** |
| NiceHash desktop, not admin | Interactive N | Mode 0 (already Medium) | Works; MSR preflight **skipped** (not High IL) | Works | Supported; Event 2001 if MSR allowlisted but not elevated |
| NiceHash **service** | Session 0 | Any | Works | **Often fails** (no GPU in session 0) | CPU OK; GPU best-effort Event 2003 |
| Wrapper as SYSTEM | Session 0 | Must not pass SYSTEM token | N/A | N/A | `WTSQueryUserToken` of a logged-on user (v1.1 agent); v1 refuse GPU |

**v1 GPU / spawn:** Medium IL, interactive session, **mode 0 for every intercept** (includes `xmrig.exe`). Do not strip the user from vendor device ACLs. **Session 0: CPU supported; GPU unsupported.** No `nhwrap-agent` in v1 (Resolved OQ-4).

### 3.9 GPU from a non-admin user

Fails commonly for Low IL, session 0, users missing from device object ACL, or never-run vendor UI. v1 installer does **not** create `NHMiner` or modify GPU device ACLs.

---

## MODULE 4: Synchronous Hardware State Injection

### 4.1 MSR persistence (accurate)

MSRs written from Ring 0 stay in the physical core until overwritten, firmware/OS reset on some C-state/package events (model-dependent), CPU offline/online, or reboot. They are **not** immortal. They **do** outlive the elevated process if nothing else writes them. An unprivileged miner **cannot** reload WinRing0/`xmrig.sys` without `SeLoadDriverPrivilege` + admin.

### 4.2 When preflight runs

```
if policy.Enabled
AND not Layer A/B bypass
AND IsAllowlisted(target) for MsrAllowlist
AND current process TokenElevation == TokenElevationTypeFull (or IL High)
AND ForceSkipMsr == 0
AND ResolveTarget produced an **absolute existing** path (never preflight a relative/unresolved token or a PATH-discovered image)
AND SelectMsrArgs(target) succeeded (version table + `--help` contains the flag)
AND not WinRing0OnlyAdjacent(target)   # skip if WinRing0x64.sys / WinRing0.sys is the only adjacent MSR driver
  then RunMsrPreflight()
else if MsrAllowlist matched AND not elevated:
  Event 2001 reason=not-elevated; continue (fail-open) or 3004 if FailMsr=1
else if WinRing0OnlyAdjacent:
  Event 2001 reason=winring0-only; continue (fail-open) or 3004 if FailMsr=1
```

### 4.3 Exact preflight spawn

```
LaunchRequest req
req.targetPath = original miner path
req.commandLine = ArgvQuote(original) + " " + SelectMsrArgs(original)   # version table, not a hardcoded flag
req.workDir = dirname(original)
# Do NOT pass pool URL, user, or original miner args.

env = BuildEnvBlock()   # BYPASS=TRUE

stdio:
  hNul = CreateFileW(L"\\\\.\\NUL", GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE, NULL, OPEN_EXISTING, 0, NULL)
  OR dedicated pipes whose reader thread writes only to the wrapper log (never parent stdout/stderr)
  STARTF_USESTDHANDLES with stdin=NUL, stdout=log-or-NUL, stderr=log-or-NUL

token = NULL   # inherit wrapper elevated token; NOT the filtered miner token

SpawnIfeoSafe(req, token=NULL, env, preflightStdio, hJob, &pi)
# Preflight is elevated in-process CreateProcessW: C1 legal. CREATE_NO_WINDOW.
# Never use WithTokenW for preflight.

timeout = policy.MsrTimeoutMs default 30000
wr = WaitForSingleObject(pi.hProcess, timeout)   # FORBIDDEN as success: Sleep; FORBIDDEN as default: INFINITE
if wr == WAIT_TIMEOUT:
  TerminateProcess(pi.hProcess, 0xE0002001)
  WaitForSingleObject(pi.hProcess, 5000)
  Event 2001 (fail-open) or 3004 (fail-closed) reason=timeout
  msrExit = timeout-failure
else:
  GetExitCodeProcess(pi.hProcess, &msrExit)
CloseHandle(pi.hProcess)

# Parent orchestrator std handles must be untouched: no WriteFile to them during preflight.
```

Preflight **is** IFEO-visible if spawned by original filename; Layer A+C are mandatory. Recursion-safe: same C1/C2 as the sandboxed miner.

If `WaitForSingleObject` returns `WAIT_FAILED`, treat as preflight failure (`GetLastError`).

### 4.4 Version-specific MSR flags (resolved OQ-1)

```
function SelectMsrArgs(imagePath) -> flag or SKIP:
  # Probe via SpawnIfeoSafe (C1, BYPASS env, stdio to buffer, timeout 5000 ms).
  # Do not use parent stdout. Do not pass pool args.
  ver  = stdout of image --version   # parse first semver / "XMRig 6.x.y"
  help = stdout of image --help
  flag = MsrFlagTable[ver] or policy.MsrArgs default "--msr-only"
         # Built-in table shipped with nhwrap; installer may overlay REG_SZ JSON.
         # Example rows (maintain against bundled miners):
         #   6.21+  -> --msr-only
         #   older  -> --randomx-wrmsr   (only if that string appears in --help)
  if flag is empty OR flag not a substring of help:
    Event 2001 reason=no-flag; return SKIP   # never start a full elevated miner
  return flag

function WinRing0OnlyAdjacent(imagePath) -> bool:
  dir = dirname(imagePath)
  msrSys = files in dir matching {WinRing0x64.sys, WinRing0.sys, xmrig.sys,
           and other names in DeclaredSiblings that are .sys}
  winring = {WinRing0x64.sys, WinRing0.sys} present in dir
  other   = msrSys minus winring
  return winring is non-empty AND other is empty
```

| Image | Flag source | Notes |
|-------|-------------|--------|
| `xmrig.exe` | `SelectMsrArgs` | Refuse preflight if `--help` lacks the table/policy flag |
| Other RandomX forks on `MsrAllowlist` | same | |

**GPU extension (not v1 — do not implement in PR-06):**

| Hook | Example | Wait |
|------|---------|------|
| NVIDIA persistence | `nvidia-smi.exe -pm 1` | `WaitForSingleObject` with `MsrTimeoutMs` (or a GPU-specific timeout DWORD) |
| NVIDIA compute | vendor-specific; do not set clocks unless product policy says so | blocking |
| AMD compute mode | vendor tool | blocking |

GPU hooks still must not write parent stdout. Register later as `GpuPreflight` `REG_MULTI_SZ` of command lines.

### 4.5 Failure policy

| `FailMsr` | Preflight non-zero, crash, missing image, wait fail | Wrapper |
|-----------|------------------------------------------------------|---------|
| 0 (default) | Event **2001**, continue sandbox launch | Hashrate may drop; mining continues |
| 1 | Event **3004**, **do not** start miner, `ExitProcess(msrExit or 0xE0003004)` | Orchestrator sees failure |

Do not `sc stop` third-party drivers on failure unless the service name is allowlisted (none in v1).

### 4.6 WinRing0 (resolved OQ-5)

Historically unsigned/vulnerable. Out of scope to replace. **Skip preflight** (Event 2001 `reason=winring0-only`) if `WinRing0x64.sys` or `WinRing0.sys` is the **only** adjacent MSR driver (`WinRing0OnlyAdjacent`). If `xmrig.sys` (or another non-WinRing0 name in `DeclaredSiblings`) is also present, preflight may run and may load that signed driver. Do not `sc stop` WinRing0 on skip.

---

## MODULE 5: Multi-Threaded Asynchronous Pipeline Stream Proxy

### 5.1 Intercept vs passthrough

| Path | Stdio |
|------|--------|
| Intercept | Create pipes; miner `STARTF_USESTDHANDLES`; three threads copy to **wrapper** std handles (which are NiceHash’s pipes) |
| Passthrough | Inherit current std handles; no proxy threads |

### 5.2 Pipe creation and inherit bits

```
SECURITY_ATTRIBUTES sa
sa.nLength = sizeof(sa)
sa.lpSecurityDescriptor = SD for wrapper user + miner SID (GENERIC_READ|GENERIC_WRITE)
                          If mode 0 same user, NULL DACL is still forbidden; NULL SD (default) is OK
sa.bInheritHandle = TRUE

CreatePipe(&outRd, &outWr, &sa, 65536)
CreatePipe(&errRd, &errWr, &sa, 65536)
CreatePipe(&inRd,  &inWr,  &sa, 65536)

# Parent-facing ends must NOT be inherited by the miner:
SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0)
SetHandleInformation(errRd, HANDLE_FLAG_INHERIT, 0)
SetHandleInformation(inWr,  HANDLE_FLAG_INHERIT, 0)

# Miner-facing ends stay inheritable:
#   outWr, errWr, inRd

# bInheritHandles=TRUE copies EVERY inheritable handle. IFEO children inherit
# NiceHash's inheritable table (tokens, jobs, devices) — those were NOT created
# by nhwrap. "Handles we created" is **insufficient** and forbidden as the v1
# algorithm.
#
# v1 MANDATORY before ANY CreateProcess/AsUser/WithTokenW:
#   1. NtQuerySystemInformation(SystemExtendedHandleInformation) for current PID
#      (or duplicate every handle via GetCurrentProcess + iterative
#      DuplicateHandle/NtQueryObject — Toolhelp does not expose inherit flags).
#   2. For EVERY handle in this process except {inRd, outWr, errWr}:
#        SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0)
#      This includes inherited std handles from NiceHash, hJob, tokens, log,
#      preflight NUL, LSA, threads, and any unknown inherited handle.
#   3. Snapshot previous inherit bits only if a later Restore is required
#      (v1 does not restore; process is exiting after the miner).
#
# Prefer CreateProcessAsUserW + STARTUPINFOEX +
#   PROC_THREAD_ATTRIBUTE_HANDLE_LIST = {inRd, outWr, errWr}
#   with bInheritHandles=FALSE — then only those three inherit.
# WithTokenW cannot take HANDLE_LIST: the full-process inherit-strip is
# mandatory on that path (not a set of handles we created).

si.dwFlags    = STARTF_USESTDHANDLES
si.hStdOutput = outWr
si.hStdError  = errWr
si.hStdInput  = inRd

CreateProcess...   # see spawn matrix; no DEBUG_* on seclogon
CloseHandle(outWr); CloseHandle(errWr); CloseHandle(inRd)   # copies in child
# wrapper holds outRd, errRd, inWr
```

If a future mode-1 SKU is enabled, build an explicit SD with `ConvertStringSecurityDescriptorToSecurityDescriptorW` (v1 uses default same-user SD):

```
D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;<NHMinerSID>)
```

### 5.3 Thread model

Buffer size: **65536** bytes. Forward **raw bytes** (`WriteFile` of `ReadFile`’s `dwRead`). **Never** `WriteLine` / add `\n`. Line splitting is log-only.

```
StdoutThread:
  loop:
    ok = ReadFile(outRd, buf, 65536, &n, NULL)
    if !ok || n==0: break          # ERROR_BROKEN_PIPE / EOF
    WriteAll(GetStdHandle(STD_OUTPUT_HANDLE), buf, n)

StderrThread: identical → STD_ERROR_HANDLE

StdinThread:
  hIn = GetStdHandle(STD_INPUT_HANDLE)
  if hIn == NULL or hIn == INVALID_HANDLE_VALUE: return
  loop:
    ok = ReadFile(hIn, buf, 65536, &n, NULL)
    if !ok || n==0:
      CloseHandle(inWr); inWr = NULL     # child sees EOF
      break
    if inWr: WriteAll(inWr, buf, n)
```

**Headless:** never `[Console]::KeyAvailable`, `ReadConsoleInput`, or `GetConsoleMode` as a required path. If `ReadFile` on stdin fails with `ERROR_INVALID_HANDLE` / `ERROR_INVALID_FUNCTION`, **skip** the stdin pump.

**Forbidden deadlock (worked example):**

Default pipe buffer ~4 KiB. Fake miner writes **1 MiB to stderr**, then one stdout line.

```
Broken wrapper:
  line = ReadLine(stdout)     # blocks forever
  miner WriteFile(stderr) fills 4 KiB → miner blocks
  stdout line never written
  NiceHash waits on wrapper → hang

Correct wrapper:
  StderrThread reads the 1 MiB as it arrives (many 64 KiB reads)
  miner unblocks, writes stdout
  StdoutThread forwards the line
  both complete
```

Always start **both** reader threads **before** `ResumeThread` on the miner (spawn was `CREATE_SUSPENDED`).

### 5.4 Wait + drain order

```
1. ResumeThread(miner)
2. WaitForSingleObject(hMiner, INFINITE)
3. CloseHandle(inWr) if still open          # unblock child if it was in ReadFile; also helps our stdin thread
4. CancelSynchronousIo(hStdinThread) if still blocked on parent stdin
5. WaitForSingleObject(hStdoutThread, 5000)
6. WaitForSingleObject(hStderrThread, 5000)
7. WaitForSingleObject(hStdinThread, 1000)  # then TerminateThread only if absolutely stuck (document as last resort)
8. FlushFileBuffers(parent stdout/stderr) if they are files; ignore failure on pipes
9. GetExitCodeProcess(hMiner, &code)
10. if code == STILL_ACTIVE (259): TerminateProcess(hMiner, 259); code = 259
11. Close remaining pipe handles
12. ExitProcess(code)                       # orchestrator thinks the wrapper IS the miner
```

Do not `ExitProcess` while reader threads may still `WriteFile` to parent stdout (race tearing the last hashrate line). Drain first.

### 5.5 Job object

```
hJob = CreateJobObjectW(NULL, NULL)          # anonymous
JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = {}
lim.BasicLimitInformation.LimitFlags =
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    # v1: KILL_ON_JOB_CLOSE only.
    # Do NOT set DIE_ON_UNHANDLED_EXCEPTION (kills miners that use WER/minidump).
    # Do NOT set BREAKAWAY_OK or SILENT_BREAKAWAY_OK (helpers must die with the job).
    # Soak GPU vendor helpers; if a required helper is breakaway-by-driver,
    # document as residual — do not silently enable SILENT_BREAKAWAY_OK.
SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &lim, sizeof lim)
SetHandleInformation(hJob, HANDLE_FLAG_INHERIT, 0)
AssignProcessToJobObject(hJob, miner)        # while SUSPENDED
# keep hJob open until wrapper ExitProcess → miner tree dies
```

If `AssignProcessToJobObject` → `ERROR_ACCESS_DENIED` (nested job / breakaway disallowed): Event **2002**; continue; on wrapper exit `TerminateProcess(miner)` as fallback (does not kill grandchildren unless we enumerated them). Residual risk documented.

Preflight may share this job **only because** it is waited **before** the wrapper exits. Do not close the job between preflight and miner.

### 5.6 Ctrl+C / parent kill

```
SetConsoleCtrlHandler(Handler, TRUE)

Handler(CTRL_C_EVENT / CTRL_BREAK_EVENT / CTRL_CLOSE_EVENT):
  if minerPid:
    GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, minerPid)  # requires CREATE_NEW_PROCESS_GROUP
    CloseHandle(inWr) if open
  return TRUE     # wrapper does not ExitProcess here; wait path collects miner code

# If parent kills nhwrap (TerminateProcess / job of NiceHash):
#   KILL_ON_JOB_CLOSE destroys miner tree. This is the reliable headless path.
```

`GenerateConsoleCtrlEvent` is flaky with `CREATE_NO_WINDOW` and no console; job kill is canonical.

---

## MODULE 6: Host System Preservation & Security Exceptions

### 6.1 Log paths and content

| File | Path |
|------|------|
| Shared | `%ProgramData%\NiceHash\Sandbox\logs\nhwrap.log` |
| Archive | `nhwrap.<YYYYMMDDTHHMMSSZ>.<wrapperPid>.log` in the same directory |
| Optional per-PID | `nhwrap.<pid>.log` if shared rotate fails |

Ceiling: **10 MiB** (`LogMaxBytes`). Encoding: UTF-8, one JSON object per line (or TSV); newline `\n`.

Fields: `ts` UTC, `pid`, `ppid`, `parentImage`, `target`, `argsRedacted`, `decision` (intercept\|bypass), `bypassReason`, `preflightExit`, `minerPid`, `minerExit`, `il`, `user`, `ifeoSkip`.

The wrapper is High IL when NiceHash is elevated, but **non-admin NiceHash is a supported matrix row** (§3.8): that wrapper is Medium IL and **cannot** create `Global\` objects (`SeCreateGlobalPrivilege`) or write an RX-only ProgramData log. Inner depth-2 nhwrap is also Medium. Logging ACLs and mutex must allow the wrapper user.

### 6.2 Mutex rotation algorithm

```
MUTEX_NAME = L"Local\\NiceHashSandbox.LogRotate"
# Use Local\ so Medium-IL wrappers without SeCreateGlobalPrivilege can create it.
# If a future session-0 + interactive multi-session writer is required, switch to
# Global\ WITH a DACL granting SYSTEM, Administrators, AND the wrapper user /
# NHSandboxUsers SYNCHRONIZE|MUTANT_QUERY|MUTANT_MODIFY (not Admins+SYSTEM only).
MAX      = LogMaxBytes (default 10485760)

# Mutex DACL even for Local\: SYSTEM, Administrators, wrapper user, NHSandboxUsers.
# CreateMutexW at process start; hold the handle for process lifetime.

function LogLine(msg):
  WaitForSingleObject(hMutex, 5000)
  if WAIT_TIMEOUT: write to nhwrap.<pid>.log instead; return

  h = CreateFileW(sharedLog,
        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)

  GetFileSizeEx(h, &size)
  if size >= MAX:
    CloseHandle(h)
    archive = dir + "nhwrap." + utcNowBasic() + "." + pid + ".log"
    # utcNowBasic = YYYYMMDDTHHMMSSZ
    ok = MoveFileExW(sharedLog, archive, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
    if !ok:
      # file locked: skip rotate this write (small overrun OK)
      h = CreateFileW(..., OPEN_ALWAYS)
    else:
      h = CreateFileW(..., CREATE_ALWAYS)

  WriteFile(h, utf8, len, ...)     # include trailing \n
  CloseHandle(h)
  ReleaseMutex(hMutex)
```

Pre-write size check is inside the mutex so two processes cannot both observe 9.9 MiB and both write 1 MiB.

Scavenge (installer scheduled task or on install/uninstall): delete `nhwrap.*.log` older than 14 days; if `logs` dir > 100 MiB, delete oldest archives.

### 6.3 Redaction list

Apply to `CommandLine` / args before log or Event Log:

| Pattern | Replacement |
|---------|-------------|
| `--pass`, `--password`, `--passwd`, `--userpass` and following token or `=value` | `***` |
| `--user`, `--username` and following token or `=value` | `***` |
| `--api-token`, `--api-key`, `--access-token` and following token | `***` |
| URI userinfo `scheme://user:pass@host` | `scheme://***:***@host` |
| Base58-like 26–95 chars (BTC/XMR style) | `***` |
| `0x` + 40 hex (ETH address) | `***` |
| LSA / `NHMiner` password | never logged |

Redaction false positives are acceptable; leaks are not.

### 6.4 Defender exclusion (installer only)

**Never** call this from `nhwrap.exe` launch.

```powershell
# Elevated installer, after consent checkbox.
Add-MpPreference -ExclusionPath "C:\Program Files\NiceHash\Sandbox\nhwrap.exe"
# Optional still-narrow:
Add-MpPreference -ExclusionPath "C:\Program Files\NiceHash\Sandbox"
```

Equivalent API: `MSFT_MpPreference` / Defender CIM. Record what we added in `HKLM\SOFTWARE\NiceHash\Sandbox\DefenderExclusions` `REG_MULTI_SZ` for uninstall reversal.

**Forbidden:** volume roots, user profile, miner download directories, `ExclusionProcess=*`.

Uninstall:

```powershell
Remove-MpPreference -ExclusionPath "C:\Program Files\NiceHash\Sandbox\nhwrap.exe"
Remove-MpPreference -ExclusionPath "C:\Program Files\NiceHash\Sandbox"
```

Best-effort if Defender is absent (Event 2006).

### 6.5 T1546.012 hygiene

- IFEO `Debugger` is a known persistence technique. UI lists hooked names.
- Never silently IFEO-hook on first launch.
- Never hook `System32`, `cmd.exe`, `powershell.exe`, `explorer.exe`.
- Uninstaller deletes `Debugger` **only if** data equals `WrapperPath` (normalized).
- HKLM IFEO ACL remains admin-only; low-priv miner cannot unhook.
- Wrapper dir ACL: `SYSTEM` + `Administrators` full; `Users` / `NHMiner` RX; no write.
- Authenticode-sign wrapper and installer (KD-12).

---

## API / Interface Changes

Greenfield. Public surfaces:

### CLI

| Mode | Invocation | Role |
|------|------------|------|
| IFEO intercept | `nhwrap.exe <target> [args…]` | Production |
| Explicit | `nhwrap.exe --run [--] <target> [args…]` | Tests / opt-in |
| Passthrough force | env `NICEHASH_SANDBOX_BYPASS=TRUE` | Inner instance |
| Version | `nhwrap.exe --version` | |

Exit codes: miner’s code on success path; wrapper failures in Appendix D.

### Registry policy

§1.6. WOW64 IFEO: §1.1.

---

## Data Model Changes

No application database.

```
%ProgramFiles%\NiceHash\Sandbox\
  nhwrap.exe
%ProgramData%\NiceHash\Sandbox\
  imgcache\                 (off-dir C2 last resort)
  logs\
  c2-dests.txt              (backup list of miner-dir nhimg_*.exe)
```

v1 has no prior schema. Uninstall: §Installer.

---

## Job Objects, Integrity, and Session Notes

Covered in §5.5 (jobs), §3.4 / KD-6 (integrity), §3.8 (session 0). Summary:

- Wrapper IL: **stays High** when the parent was elevated (Resolved OQ-3). Miner IL: Medium. `ForceLowIL` experimental. Non-admin wrapper is Medium — log mutex is `Local\` (§6.2).
- Job flags: `KILL_ON_JOB_CLOSE` only (no `DIE_ON_UNHANDLED_EXCEPTION`, no breakaway). Nested jobs: if assign fails, Event 2002 + `TerminateProcess` fallback.
- Session 0: CPU supported; **GPU unsupported**; **no** `nhwrap-agent` in v1 (Resolved OQ-4).
- Mode 0 only for all intercepts, including xmrig (Resolved OQ-2).

---

## Installer and Uninstaller

Elevated, Authenticode-signed, explicit UI. Never IFEO from the wrapper hot path.

### Install operations (numbered; push undo as each succeeds)

| Step | Operation | Undo (rollback stack, LIFO) |
|------|-----------|------------------------------|
| I0 | Require admin; verify Authenticode of payload | none |
| I1 | Create `%ProgramFiles%\NiceHash\Sandbox`; copy `nhwrap.exe` | Delete copied files; remove dir if empty |
| I2 | ACL directory: SY/BA full; Users RX | Restore previous SD if we saved it; else leave |
| I3 | Create `%ProgramData%\NiceHash\Sandbox\{logs,imgcache}` + ACLs: SY/BA full; **Users / NHSandboxUsers `FILE_ADD_FILE \| FILE_ADD_SUBDIRECTORY \| FILE_APPEND_DATA \| FILE_GENERIC_READ`** (not RX-only — non-admin wrapper must append) | Delete if we created and empty |
| I4 | `EventCreate` / `RegisterEventSource` source `NiceHash-Sandbox` in Application log | `DeregisterEventSource` / remove registry Eventlog key we added |
| I5 | Write `HKLM\SOFTWARE\NiceHash\Sandbox` values (§1.6) | Delete values/key if we created the key |
| I6 | For each allowlist name × {64-bit, 32-bit IFEO}: conflict algorithm §1.7; write `Debugger` | Restore previous `Debugger` or delete value if we created it |
| I7 | **v1: skip.** Do not `NetUserAdd` NHMiner, do not store an LSA secret. (`/account` is a future SKU.) | none |
| I8 | Optional consent: Defender `ExclusionPath` + record in policy | `Remove-MpPreference` for recorded paths |
| I9 | Call the **PR-06 probe** (`nhifeo_probe.exe`): temporary IFEO key; test AsUser/CreateProcessW C1; if still re-enters, set `IfeoSkipMode=2`. Must **not** pass `DEBUG_*` through WithTokenW as “success.” | Delete probe IFEO key always (even on success) |
| I10 | Write Uninstall registry (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NiceHashSandbox`) | Delete uninstall key |

On failure at step *k*: execute undo for I(*k*-1) … I1. Do not leave a `Debugger` pointing at a missing EXE.

`/strict-ifeo`: any IFEO conflict fails the install after rollback of I6 writes from this session.

### Uninstall operations

| Step | Operation |
|------|-----------|
| U0 | Stop running miners/wrappers if possible (`taskkill` only `nhwrap.exe` with our path; warn if in use) |
| U1 | For each IFEO image we recorded: delete `Debugger` iff data equals `WrapperPath` |
| U1b | Delete each path in `C2DestList` / `c2-dests.txt` iff the file exists, filename matches `nhimg_*.exe`, and Authenticode publisher **or** SHA256 of the file equals the linked miner (compare to sibling allowlisted EXE in the same directory when present; else hash recorded at create time). Then scavenge leftover `nhimg_*.exe` next to allowlisted miner dirs (`MinerSearchPath` + last-known paths). Keep 7-day unused scavenge for crash-before-uninstall. Do **not** delete `xmrig.exe` or other allowlisted names. |
| U2 | Delete probe IFEO key if present |
| U3 | Reverse Defender exclusions we recorded |
| U4 | Delete Event Log source |
| U5 | Delete `HKLM\SOFTWARE\NiceHash\Sandbox` (after U1b consumed `C2DestList`) |
| U6 | Delete uninstall key |
| U7 | Delete ProgramData logs/imgcache (optional checkbox; default keep logs) |
| U8 | Delete Program Files payload |
| U9 | v1: no-op (NHMiner was not created). Future SKU: `NetUserDel` only if we created it |
| U10 | v1: no-op (no LSA secret). Future: delete LSA secret |

Uninstall must not delete `Debugger` values we do not own (Application Verifier).

---

## Alternatives Considered

### A1. Detours / IAT hook of `CreateProcess` inside NiceHash

- **Pros:** No IFEO (no T1546.012); no global hook.
- **Cons:** Breaks on .NET `Process.Start`, `cmd` wrappers, miner self-updates; requires patching a third-party orchestrator.
- **Verdict:** Rejected as primary; `--run` remains opt-in for tests.

### A2. PowerShell IFEO debugger (`nhwrap.ps1`)

- **Pros:** Fast to prototype.
- **Cons:** 200–800 ms startup; AV; quoting hell; `UseShellExecute` credential trap; poor job-object control.
- **Verdict:** Appendix A only.

### A3. Always-on AppContainer / LowBox for miners

- **Pros:** Stronger isolation.
- **Cons:** GPU/driver incompatibility.
- **Verdict:** Research spike, not v1 default.

### A4. Launch miner by copying to a random name without IFEO (orchestrator change)

- **Pros:** Simple skip.
- **Cons:** Requires NiceHash code change; sibling resource lookup.
- **Verdict:** Cache hardlink is Layer C2 only; DEBUG skip on original path is C1.

Installer self-test: spawn `nhifeo_probe.exe` with a test IFEO key; measure whether **in-process** DEBUG skip (CreateProcessW/AsUser) avoids a second wrapper. A WithTokenW+DEBUG freeze is a **fail**, not a skip.

### A5. Path-filtered IFEO (`UseFilter` + `FilterFullPath`) vs global basename

- **Pros:** Since Win7, `UseFilter=1` + filter subkey `FilterFullPath` can hook only `C:\NiceHash\miners\xmrig.exe`, not every `xmrig.exe` on the machine (user downloads, AV scanners, other products). Smaller T1546.012 blast radius.
- **Cons:** NiceHash miner directories **move** (self-update, per-algo folders, user-configured paths). Filters would require the installer/agent to rewrite subkeys on every miner path change — a race the basename hook avoids. Multiple copies of the same miner would need multiple filters.
- **Verdict:** **Rejected for v1.** Global allowlisted basename remains. Installer already enumerates filter subkeys **only** to avoid clobbering Application Verifier. Revisit if EDR noise from global `xmrig.exe` hooks is unacceptable.

---

## Security & Privacy Considerations

### Threat model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Compromised miner re-elevates via stolen wrapper admin token | **Critical** | Child never receives wrapper token handles; `DuplicateToken` only filtered; **strip inherit on all handles except three pipe ends**; prefer `HANDLE_LIST` on AsUser; PR-05 snapshot fails on elevated `TOKEN_*` or writable WinRing0 in the child |
| Compromised miner writes IFEO for `explorer.exe` | **High** | HKLM requires admin; miner is non-admin |
| Compromised miner kills wrapper and orphans a privileged helper | **High** | Job `KILL_ON_JOB_CLOSE`; preflight waited to completion before drop |
| `cmd.exe` argument injection | **High** | Not used in native path; Appendix A must refuse metacharacters |
| Password of `NHMiner` stolen from disk | **High** | **N/A in v1** — mode 1 not shipped |
| IFEO used as persistence by an attacker impersonating us | **High** | Authenticode; installer UI; uninstaller; allowlist only |
| Defender exclusion of entire disk | **High** | File/dir of wrapper only; installer-only |
| Stdio named pipe squatting | **Medium** | Anonymous pipes or random names + DACL |
| Log leaks wallets / pool passwords | **Medium** | Redaction |
| PID reuse tricks wrapper into passthrough | **Medium** | CreateTime checks; truncated → intercept; env + Layer C |
| MSR driver (WinRing0) is itself malware-grade | **High** | **Skip preflight** if WinRing0 is the only adjacent MSR driver (Resolved OQ-5) |
| Wrapper stays High IL (attack surface) | **Medium** | Accepted in v1 (Resolved OQ-3); no network, no script engine |
| Mode 1 WinSta/desktop ACL widen (`NHMiner` on `WinSta0\Default`) | **High** | **Not in v1** (mode 1 not shipped) |
| `DEBUG_*` on WithTokenW/WithLogonW | **Critical** | Forbidden in spawn matrix; child freeze / seclogon debugger |

**Invariant:** a compromised miner must not obtain a SYSTEM/admin **primary** token.

**Privacy:** command lines may contain pool credentials. Logs are local-only; no telemetry in v1.

---

## Risks

| ID | Risk | Severity | Likelihood | Mitigation |
|----|------|----------|------------|------------|
| R1 | IFEO re-entry infinite loop | Critical | Medium without Layer C | A+B+C; depth>2 Event 3005; installer skip self-test |
| R2 | PID reuse false bypass | High | Low | CreateTime; truncated ⇒ intercept |
| R3 | GPU broken at Medium/session 0 | High | High for service mode | Mode 0 interactive; Event 2003; GPU in session 0 unsupported (Resolved OQ-4) |
| R4 | MSR not applied; silent hashrate loss | Medium | Medium | Fail-open + Event 2001; optional fail-closed |
| R5 | Stdio deadlock on stderr-only writers | High | High if single-thread drain | Concurrent readers; 1 MiB test |
| R6 | .NET-style credential launch copied into native | High | Medium | Ban `cmd.exe` on production path; pipe DACLs |
| R7 | T1546.012 AV/EDR quarantine of `nhwrap` | High | High if unsigned | Authenticode; narrow exclusion; allowlist IFEO |
| R8 | Installer conflict destroys Application Verifier Debugger | High | Low | Conflict algorithm; never overwrite foreign Debugger |
| R9 | Log disk fill | Medium | Medium on multi-week runs | 10 MiB mutex rotate; 14-day scavenge |
| R10 | Job assign fails; orphan miner after wrapper kill | Medium | Low–medium | Event 2002; TerminateProcess fallback |
| R11 | C2 off-dir cache breaks `GetModuleFileNameW` sibling lookup (WinRing0) | High | High if ProgramData cache | C2 **in miner directory**; sibling copy only if cache elsewhere; C1/AsUser preserves real module path |
| R12 | LSA secret / second password leak | High | Low if mode 0 | Prefer mode 0 |
| R13 | WinRing0 loaded by preflight | High | Medium on XMRig | Skip preflight when WinRing0 is the only adjacent MSR driver (Resolved OQ-5) |
| R14 | Rollback leaves IFEO → missing EXE (every miner launch fails) | Critical | Medium on failed install | Undo stack I6; never write Debugger before file copy |

---

## Observability

### File logs

§6.1–6.3.

### Windows Event Log

Source: `NiceHash-Sandbox` (Application). Full catalog: **Appendix D**.

### Metrics (optional ETW provider `NiceHash.Sandbox`)

`launch_ms`, `preflight_ms`, `stdio_bytes_stdout`, `stdio_bytes_stderr`, `stdio_bytes_stdin`, `rotate_count`, `reentry_count`.

### Alerting

- Event 3005 immediately (loop).
- Event 3002 rate > 3/min (logon broken).
- Log directory size > 100 MiB (scavenge failed).

---

## Rollout Plan

1. **Feature flag:** `Enabled` DWORD. 0 = passthrough.
2. **Stage 0:** `--run` without IFEO; fake miner tests.
3. **Stage 1:** IFEO for `xmrig.exe` only; fail-open MSR; mode 0; volunteer machines.
4. **Stage 2:** GPU miner allowlist; session-0 soak.
5. **Stage 3:** NiceHash installer consent for IFEO + optional Defender exclusion.
6. **Rollback:** Uninstaller or `Enabled=0` + delete our `Debugger` values. No reboot required if miners stopped first. MSR bits may remain until reboot — acceptable.

---

## Testing Strategy

| Test | Proof |
|------|-------|
| Unit: argv fixtures | Spaces, embedded quotes, empty args, `argc==1`, `--run --`, relative argv[1] vs `lpApplicationName` |
| Unit: ResolveTarget PATH hijack | cwd ≠ miner dir; `PATH` decoy `xmrig.exe`; `MinerSearchPath` has real dir → real wins; decoy never preflighted; no `PathFindOnPathW` |
| Unit: `ArgvQuote` round-trip | `CommandLineToArgvW(ArgvQuote(s)) == s` for `\`, `"`, trailing `\\` |
| Unit: env block | Bypass present; Unicode; extra NUL terminator |
| Unit: redaction | `--pass=secret` and `user:pass@host` absent |
| Integration: fake miner | stdout/stderr/stdin/env |
| Loop test | IFEO on fake miner; ≤1 extra wrapper; fail if >2 `nhwrap` in 1 s |
| Privilege test | Child `TokenElevation` false; IL Medium; Administrators not enabled |
| Job test | Kill wrapper; fake miner + grandchild die |
| Stdio deadlock | 1 MiB stderr then one stdout line; no hang |
| Headless | `CREATE_NO_WINDOW`; no console APIs; no crash |
| MSR path | Mock preflight; parent stdout has no preflight banner; wait is `WaitForSingleObject(h, MsrTimeoutMs)`; hung mock is `TerminateProcess`’d by 30 s + slack |
| Log rotate | 8 concurrent writers; cap; no torn lines |
| Installer conflict | Pre-existing Debugger → abort that image |
| Uninstall | Our IFEO gone; foreign Debugger intact; exclusion removed |
| WOW64 | Four tuples `(parent32\|parent64)×(miner32\|miner64)`; lookup by **caller** bitness |

---

## Resolved decisions (formerly Open Questions)

User decisions 2026-09-01 are **final**. Do not re-open in implementation.

### OQ-1 XMRig flag string — **Resolved**

- **Choice:** Version-specific table from `xmrig --help` / `--version` (`SelectMsrArgs`, §4.4). Refuse preflight if the bundled binary’s `--help` does not contain the configured flag. Wait remains `MsrTimeoutMs=30000` then `TerminateProcess`.
- **Rationale:** Wrong flags can start a full elevated miner; probing `--help` is the prevention, the timeout is the safety net.

### OQ-2 GPU identity — **Resolved**

- **Choice:** Ship **mode 0 only**. `GpuForceMode0=1` for all intercepts. Do not ship dedicated `NHMiner` / mode 1 as a v1 SKU (may remain documented as unsupported/future).
- **Rationale:** Avoid a second password, LSA secret, and WinSta ACL widen; xmrig is GPU-capable so it uses the logged-on user’s filtered token.

### OQ-3 Wrapper IL — **Resolved**

- **Choice:** Wrapper stays High IL in v1.
- **Rationale:** Keeps `%ProgramData%` logging and job-object ownership simple; shrink the wrapper instead of dropping IL after spawn.

### OQ-4 Session 0 GPU — **Resolved**

- **Choice:** v1 document-only: CPU in session 0 supported; GPU in session 0 unsupported. No v1 `nhwrap-agent`.
- **Rationale:** Session 0 device isolation; NiceHash GPU mining is a desktop-session problem in v1.

### OQ-5 WinRing0 — **Resolved**

- **Choice:** Skip preflight if `WinRing0x64.sys` is the only adjacent MSR driver (`WinRing0OnlyAdjacent`).
- **Rationale:** Do not load a known-vulnerable unsigned driver from an elevated wrapper; hashrate loss is acceptable vs that risk.

### OQ-6 32-bit miners / SysWOW64 IFEO — **Resolved**

- **Choice:** Installer always writes both native and Wow6432Node IFEO views. Single 64-bit `nhwrap`. No `nhwrap32.exe` in v1. PR-10 tests the caller×image bitness matrix.
- **Rationale:** Lookup is caller bitness; one signed 64-bit debugger covers the four tuples on x64.

---

## References

- Microsoft Docs / Miskelly: Image File Execution Options (caller-bitness WOW64 views; `CreateProcessInternalW` Debugger prepend), `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, `CreateProcessWithTokenW`, `CreateRestrictedToken`, `SaferComputeTokenFromLevel` (`safer.h` / WinSafer), `CommandLineToArgvW`, Job Objects, `WaitForSingleObject`, `NetUserAdd`, `LsaStorePrivateData`.
- MITRE ATT&CK T1546.012 — Image File Execution Options Abuse.
- Windows Internals (IFEO debugger substitution; UAC `TokenLinkedToken`).
- XMRig RandomX MSR / driver notes (verify version).
- Defender `Add-MpPreference` / `Remove-MpPreference`.
- NT: `NtQueryInformationProcess` (`ProcessBasicInformation.InheritedFromUniqueProcessId`), `GetProcessTimes`.

---

## Appendix A — PowerShell / .NET Reference Algorithm (non-production)

Matches the spec’s `cmd.exe` and `UseShellExecute=false` constraints. **Not** the IFEO debugger in production. **Injection risk:** miner args containing `& | < > ^ % "` are `cmd.exe` metacharacters. This reference **refuses** those characters rather than pretending to escape them. Production native code must not call `cmd.exe`.

```powershell
# NON-PRODUCTION. Do not register this script as IFEO Debugger.
param(
  [Parameter(Mandatory)] [string]$Target,
  [string[]]$MinerArgs = @(),
  [string]$User,
  [securestring]$Password,
  [string]$Domain = '.'
)

$ErrorActionPreference = 'Stop'
$BypassName = 'NICEHASH_SANDBOX_BYPASS'

function Test-Metacharacters([string[]]$Parts) {
  foreach ($p in $Parts) {
    if ($p -match '[&|<>^%"]') {
      throw "Refusing cmd.exe passthrough: metacharacter in argument (use native nhwrap). Part=$p"
    }
  }
}

function Get-CimProcess([uint32]$ProcId) {
  Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction SilentlyContinue |
    Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine, ExecutablePath
}

function Test-CreateTimeEdge([datetime]$ParentCreated, [datetime]$ChildCreated) {
  return ($ParentCreated -le $ChildCreated)
}

function Get-AncestryDecision {
  # Layer B CIM walk with CreateTime check. Production uses NtQueryInformationProcess.
  $nodes = @()
  $pid = $PID
  $childCreated = (Get-Process -Id $pid).StartTime
  $depth = 0
  $wrapperAncestors = 0
  $minerHelper = $false
  $selfPath = [Environment]::GetCommandLineArgs()[0]
  $targetName = [IO.Path]::GetFileName($Target)

  while ($depth -lt 64 -and $pid -and $pid -ne 0) {
    $wmi = Get-CimProcess $pid
    if (-not $wmi) { break } # truncated — do not treat as wrapper match
    if ($depth -gt 0 -and -not (Test-CreateTimeEdge $wmi.CreationDate $childCreated)) { break }
    $nodes += $wmi
    $exeName = if ($wmi.ExecutablePath) { [IO.Path]::GetFileName($wmi.ExecutablePath) } else { '' }
    if ($depth -gt 0) {
      if ($exeName -ieq 'nhwrap.exe' -or $exeName -ieq [IO.Path]::GetFileName($selfPath)) {
        $wrapperAncestors++
      }
      if ($exeName -ieq $targetName) { $minerHelper = $true }
    }
    $childCreated = $wmi.CreationDate
    $pid = [uint32]$wmi.ParentProcessId
    $depth++
  }

  $nhwrapTotal = 1 + $wrapperAncestors
  if ($nhwrapTotal -gt 2) { return 'emergency' }
  if ($wrapperAncestors -ge 1) { return 'bypass-ancestor' }
  if ($minerHelper) { return 'bypass-helper' }
  # NiceHash in the tree is INTERCEPT, not bypass (KD-3)
  return 'intercept'
}

function Copy-StreamAsync {
  param($Reader, $Writer)
  return [System.Threading.Tasks.Task]::Run({
    $buf = New-Object byte[] 65536
    while (($n = $Reader.BaseStream.Read($buf, 0, $buf.Length)) -gt 0) {
      $Writer.BaseStream.Write($buf, 0, $n)
      $Writer.Flush()
    }
  }.GetNewClosure())
}

function Test-IfeoHooked([string]$Path) {
  $name = [IO.Path]::GetFileName($Path)
  $keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$name",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$name"
  )
  foreach ($k in $keys) {
    if (Test-Path $k) {
      $dbg = (Get-ItemProperty $k -ErrorAction SilentlyContinue).Debugger
      if ($dbg) { return $true }
    }
  }
  return $false
}

function Invoke-NativePassthroughOrThrow([string]$Path, [string[]]$Args) {
  # PowerShell Start-Process of an IFEO-hooked basename re-enters the debugger (Module 2).
  # This reference cannot implement C1/C2. Do not loop.
  if (Test-IfeoHooked $Path) {
    throw @"
Cannot passthrough under IFEO from PowerShell.
Start-Process '$Path' would prepend Debugger again (infinite nhwrap/script loop).
Use native nhwrap.exe C1 (CreateProcessW DEBUG_ONLY_THIS_PROCESS) or C2 (nhimg_*.exe in miner dir).
"@
  }
  $p = Start-Process -FilePath $Path -ArgumentList $Args -NoNewWindow -Wait -PassThru
  exit $p.ExitCode
}

# --- Layer A ---
if ($env:NICEHASH_SANDBOX_BYPASS -in @('TRUE','1','YES')) {
  Invoke-NativePassthroughOrThrow $Target $MinerArgs
}

$decision = Get-AncestryDecision
if ($decision -like 'bypass*' -or $decision -eq 'emergency') {
  Invoke-NativePassthroughOrThrow $Target $MinerArgs
}

# MSR preflight: blocking wait, no Sleep; do not touch parent stdout
if ([IO.Path]::GetFileName($Target) -ieq 'xmrig.exe') {
  if (Test-IfeoHooked $Target) {
    throw "Cannot run --msr-only via Start-Process on an IFEO-hooked image from PowerShell."
  }
  $msr = Start-Process -FilePath $Target -ArgumentList '--msr-only' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\nhwrap-msr.out" -RedirectStandardError "$env:TEMP\nhwrap-msr.err"
  if ($msr.ExitCode -ne 0) { Write-Error "msr preflight $($msr.ExitCode)" }
}

if (Test-IfeoHooked $Target) {
  throw "This script must not run against an IFEO-hooked image and must not be registered as Debugger. Use native nhwrap.exe (C1/C2)."
}

Test-Metacharacters (@($Target) + $MinerArgs)
$arg = ($MinerArgs | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } }) -join ' '
# Still injection-adjacent if Test-Metacharacters is removed. Native path must not do this.
$cmd = '/s /c "set ' + $BypassName + '=TRUE&& "' + $Target + '" ' + $arg + '"'

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "$env:SystemRoot\System32\cmd.exe"
$psi.Arguments = $cmd
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.RedirectStandardInput  = $true
$psi.CreateNoWindow = $true
if ($User) {
  $psi.UserName = $User
  $psi.Password = $Password
  $psi.Domain = $Domain
  $psi.LoadUserProfile = $true
}

$proc = [Diagnostics.Process]::Start($psi)
# Incremental concurrent copy — not ReadToEndAsync (deadlocks if child waits on stdin)
$stdoutTask = Copy-StreamAsync $proc.StandardOutput [Console]::Out
$stderrTask = Copy-StreamAsync $proc.StandardError  [Console]::Error
$stdinTask = [System.Threading.Tasks.Task]::Run({
  $buf = New-Object byte[] 65536
  $sin = [Console]::OpenStandardInput()
  try {
    while (($n = $sin.Read($buf, 0, $buf.Length)) -gt 0) {
      $proc.StandardInput.BaseStream.Write($buf, 0, $n)
      $proc.StandardInput.BaseStream.Flush()
    }
  } catch { }
  try { $proc.StandardInput.Close() } catch { }
})

$proc.WaitForExit()
[void][System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))
exit $proc.ExitCode
```

---

## Appendix B — Native function contracts (design-level C++)

Not a complete translation unit. Error model: functions return `bool` or `DWORD` Win32 codes; log Event IDs from Appendix D. Do not throw across the `CreateProcess` boundary.

```cpp
// --- Types ---

struct LaunchRequest {
  std::wstring targetPath;     // unquoted filesystem path of original miner
  std::wstring commandLine;    // writable-ready quoted command (ArgvQuote)
  std::wstring workDir;        // dirname(original); never empty if target has a dir
};

struct StdPipes {
  HANDLE outRd = INVALID_HANDLE_VALUE;  // wrapper reads miner stdout
  HANDLE outWr = INVALID_HANDLE_VALUE;  // miner writes; closed after CreateProcess
  HANDLE errRd = INVALID_HANDLE_VALUE;
  HANDLE errWr = INVALID_HANDLE_VALUE;
  HANDLE inRd  = INVALID_HANDLE_VALUE;  // miner reads; closed after CreateProcess
  HANDLE inWr  = INVALID_HANDLE_VALUE;  // wrapper writes miner stdin
};

enum class Decision {
  Intercept,
  BypassEnv,
  BypassAncestor,
  BypassHelper,
  BypassDisabled,     // Enabled=0 or not allowlisted
  EmergencyReentry    // nhwrap depth > 2
};

struct AncestryResult {
  Decision decision;
  int nhwrapTotal;            // including self
  bool truncated;
  struct Node { DWORD pid; FILETIME create; std::wstring path; bool truncated; };
  std::vector<Node> nodes;
};

// --- argv.cpp ---

// CommandLineToArgvW + mode detection.
// Returns ERROR_SUCCESS, ERROR_INVALID_PARAMETER (87), ERROR_NOT_ENOUGH_MEMORY.
DWORD ParseLaunchArgv(int argc, LPCWSTR* argv, bool* explicitRun, LaunchRequest* out);

// Windows CRT-compatible encoder (§1.4). forceQuote=true for argv[0]/paths with spaces.
std::wstring ArgvQuote(std::wstring_view s, bool forceQuote);

// Join ArgvQuote(target) + args into a single command line (space-separated).
std::wstring BuildCommandLine(std::wstring_view imagePath,
                              const std::vector<std::wstring>& args);

// --- env.cpp ---

// Truthy BypassEnvName in current process. Empty/missing => false.
bool EnvHasBypass();

// Allocates with HeapAlloc; caller HeapFree. Always inserts BypassEnvName=BypassEnvValue.
// Returns nullptr on OOM (ERROR_NOT_ENOUGH_MEMORY).
LPWSTR BuildEnvBlockWithBypass();  // double-NUL UTF-16

// --- ancestry.cpp ---

// NT walk §2.3.2. On NT failure, optionally CIM §2.4 with 200 ms cap.
// NiceHash ancestor => Intercept, not Bypass.
AncestryResult WalkAncestry(const std::wstring& targetPath);

bool IsWrapperImage(std::wstring_view path);
bool IsAllowlistedFilename(std::wstring_view path, const std::vector<std::wstring>& list);

// --- token.cpp ---

// Mode 0. Returns primary Medium (or Low if ForceLowIL) token, or NULL + GetLastError
// (ERROR_PRIVILEGE_NOT_HELD, ERROR_ACCESS_DENIED, ERROR_NOT_FOUND if no linked token and restrict fails).
HANDLE CreateFilteredPrimaryToken(bool forceLowIL);

// Mode 1 helper: LsaRetrievePrivateData → password buffer; caller SecureZeroMemory + LsaFreeMemory.
DWORD RetrieveNhMinerPassword(std::wstring* password);

// --- job.cpp ---

// Anonymous job, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. NULL on failure.
HANDLE CreateKillOnCloseJob();

// Assign while child still CREATE_SUSPENDED. false → Event 2002.
bool AssignToJob(HANDLE hJob, HANDLE hProcess);

// --- stdio_proxy.cpp ---

// Creates three pipes; inherit bits §5.2. false → GetLastError (ERROR_NO_SYSTEM_RESOURCES, etc.).
bool CreateStdPipes(StdPipes* p, PSID minerSid /*optional*/);

void CloseMinerEnds(StdPipes* p);     // after CreateProcess
void CloseAllPipes(StdPipes* p);

// Starts 3 threads; waits per §5.4; returns miner exit code (or 259).
DWORD ProxyUntilExit(HANDLE hProcess, StdPipes* p);

// --- spawn.cpp ---

enum class IfeoSkip { Auto, DebugOnly, HardlinkCache };

// IN-PROCESS only: CreateProcessW or CreateProcessAsUserW.
// tokenOrNull == NULL → CreateProcessW inherit current (preflight / passthrough).
// tokenOrNull != NULL → CreateProcessAsUserW (C1 DEBUG_* legal).
// NEVER implemented with CreateProcessWithTokenW.
// pipesOrNull == NULL → inherit current std handles (passthrough) after inherit-strip.
// hJob may be NULL.
// Returns Win32 error (0 success). Fills pi; caller closes handles.
DWORD SpawnIfeoSafe(const LaunchRequest& req,
                    HANDLE tokenOrNull,
                    LPVOID envBlock,
                    const StdPipes* pipesOrNull,
                    HANDLE hJob,
                    IfeoSkip skip,
                    PROCESS_INFORMATION* pi);

// Production intercept composition (§2.5 matrix):
//   1) If SeAssignPrimaryToken enabled: SpawnIfeoSafe(..., filteredToken, ..., C1)
//   2) Else: C2 miner-dir name + CreateProcessWithTokenW/WithLogonW with NO DEBUG_*
//   3) Else: depth-2 (§2.7). This function must not OR DEBUG_* into seclogon APIs.
// Always CREATE_SUSPENDED. Inherit-strip or HANDLE_LIST before create.
DWORD SpawnSandboxed(const LaunchRequest& req,
                     HANDLE filteredToken,          // mode 0 (v1 only path)
                     const wchar_t* user, const wchar_t* domain, const wchar_t* password, // mode 1 unused in v1
                     LPVOID envBlock,
                     const StdPipes* pipes,
                     HANDLE hJob,
                     PROCESS_INFORMATION* pi);

// --- preflight.cpp ---

// Elevated, IFEO-safe (CreateProcessW+C1), stdio to NUL/log.
// SelectMsrArgs (version table + --help); skip if WinRing0OnlyAdjacent.
// WaitForSingleObject(h, MsrTimeoutMs); timeout → TerminateProcess.
// Returns preflight exit code; *ran=false if skipped.
DWORD RunMsrPreflight(const LaunchRequest& original, HANDLE hJob, bool* ran);
bool WinRing0OnlyAdjacent(const std::wstring& imagePath);
std::wstring SelectMsrArgs(const std::wstring& imagePath); // empty => skip

// --- log.cpp ---

void LogInit();   // create mutex + directory
void LogLine(int eventId, /*kv fields*/);
void LogRedactedCommandLine(std::wstring_view cmd);
```

**Ctrl+C:** `SetConsoleCtrlHandler` in `main` after spawn; see §5.6.

---

## Appendix C — Worked examples

### C.1 IFEO argv

Parent:

```
CreateProcessW(
  L"C:\\Program Files\\Miners\\xmrig.exe",
  L"\"C:\\Program Files\\Miners\\xmrig.exe\" --url pool.example:3333 --user wallet",
  ...)
```

`CreateProcessInternalW` prepends the **quoted** Debugger string (installer always `ArgvQuote`s `WrapperPath`). Typical command line when the parent also quoted the full path:

```
"C:\Program Files\NiceHash\Sandbox\nhwrap.exe" "C:\Program Files\Miners\xmrig.exe" --url pool.example:3333 --user wallet
```

**Split ApplicationName/CommandLine (common, not “atypical”):**

```
lpApplicationName = C:\Program Files\Miners\xmrig.exe
lpCommandLine     = xmrig --url pool.example:3333 --user wallet
```

nhwrap sees `argv[1] == "xmrig"` (relative). `ResolveTarget` (§1.3) uses cwd (if allowlisted file exists) then `MinerSearchPath` — **never `PATH` / `PathFindOnPathW`**. If NiceHash’s cwd is not the miner dir, `MinerSearchPath` must contain `C:\Program Files\Miners`. A decoy `xmrig.exe` on `PATH` must not be preflighted.

`CommandLineToArgvW` →

| Index | Token |
|------:|-------|
| 0 | `C:\Program Files\NiceHash\Sandbox\nhwrap.exe` |
| 1 | `C:\Program Files\Miners\xmrig.exe` |
| 2 | `--url` |
| 3 | `pool.example:3333` |
| 4 | `--user` |
| 5 | `wallet` |

Reconstructed child `lpCommandLine`:

```
"C:\Program Files\Miners\xmrig.exe" --url pool.example:3333 --user wallet
```

### C.2 Intercept vs bypass decision table

| # | Layer A env | Ancestors (child→root, filenames) | Allowlisted | Decision | Reason |
|---|-------------|-----------------------------------|-------------|----------|--------|
| 1 | unset | nhwrap → NiceHashMiner → explorer | yes | **Intercept** | KD-3: NiceHash is intended parent |
| 2 | `TRUE` | nhwrap → nhwrap → NiceHashMiner | yes | **BypassEnv** | Inner IFEO instance |
| 3 | unset | nhwrap → nhwrap → NiceHashMiner | yes | **BypassAncestor** | Wrapper parent |
| 4 | unset | nhwrap → xmrig → nhwrap → NiceHashMiner | yes | **BypassHelper** and/or ancestor | C1: parent filename `xmrig.exe` |
| 4b | unset | nhwrap → nhimg_abcd.exe → nhwrap → NiceHashMiner | yes | **BypassHelper** | C2: parent is `nhimg_*.exe` (not `xmrig.exe`); Layer A env also inherited |
| 5 | unset | nhwrap → services → wininit | yes | **Intercept** | Service-launched allowlisted miner |
| 6 | unset | nhwrap → NiceHashMiner | **no** | **BypassDisabled** | Defense in depth |
| 7 | unset | nhwrap → nhwrap → nhwrap → … | yes | **EmergencyReentry** | Event 3005, depth>2 |
| 8 | unset | nhwrap → (OpenProcess parent fails) | yes | **Intercept** | Truncated edge, fail-safe sandbox |
| 9 | unset | nhwrap → PID reuse (parent CreateTime > child) | yes | **Intercept** | Inversion = truncated |
| 10 | unset | `--run` from test harness (no IFEO) | yes | **Intercept** | `--run` is not bypass |
| 11 | unset | nhwrap → NiceHashMiner; `Enabled=0` | yes | **BypassDisabled** | Feature flag |

### C.3 Example log lines (UTF-8, redacted)

```
{"ts":"2026-09-01T12:00:00Z","pid":4120,"ppid":3880,"parentImage":"C:\\Program Files\\NiceHash\\NiceHashMiner.exe","target":"C:\\Program Files\\Miners\\xmrig.exe","argsRedacted":"--url pool.example:3333 --user ***","decision":"intercept","bypassReason":null,"preflightExit":0,"minerPid":null,"il":"high","ifeoSkip":"debug"}
{"ts":"2026-09-01T12:00:01Z","pid":4120,"minerPid":4504,"il":"medium","user":"CORP\\alice","decision":"miner-started"}
{"ts":"2026-09-01T14:12:09Z","pid":4120,"minerPid":4504,"minerExit":0,"decision":"miner-exited"}
```

Rotate archive name example: `nhwrap.20260901T141210Z.4120.log`.

---

## Appendix D — Error code and Event ID catalog

Source: `NiceHash-Sandbox`. Facility for synthetic wrapper exits: `0xE0000000 | eventId` when a miner exit code is not available.

### Events

| ID | Level | When | Payload |
|----|-------|------|---------|
| 1000 | Info | Intercept decision | target, parent, skip mode |
| 1001 | Info | Bypass | reason=`env`\|`ancestor`\|`helper`\|`not-allowlisted`\|`disabled` |
| 1002 | Info | Miner started | minerPid, IL, user |
| 1003 | Info | Miner exited | exit code |
| 1004 | Info | Passthrough spawn | skip=debug\|hardlink |
| 1005 | Info | Preflight started | args=`--msr-only` |
| 1006 | Info | Preflight succeeded | exit 0 |
| 1007 | Info | Install IFEO written | image, view=32\|64 |
| 1008 | Info | Uninstall IFEO removed | image |
| 2001 | Warning | MSR preflight failed (fail-open) | exit, lastError |
| 2002 | Warning | Job assign failed | lastError=5 |
| 2003 | Warning | Session 0 / GPU caveat | sessionId |
| 2004 | Warning | IFEO conflict skipped | image, existing Debugger |
| 2005 | Warning | Ancestry truncated | pid |
| 2006 | Warning | Defender API unavailable | |
| 2007 | Warning | Log rotate failed | lastError |
| 2008 | Warning | Pipe stdin skipped (no handle) | |
| 2009 | Warning | Mode 1 / `LowPrivMode=1` / `GpuForceMode0=0` ignored (v1 ships mode 0 only) | |
| 3001 | Error | Parse error | argc, command line redacted |
| 3002 | Error | Token/logon failed | lastError (5, 1314, 1385, …) |
| 3003 | Error | CreateProcess failed | lastError (2, 5, 267, …) |
| 3004 | Error | MSR fail-closed | preflight exit |
| 3005 | Error | Infinite re-entry depth>2 | nhwrapTotal |
| 3006 | Error | Policy registry corrupt | value name |
| 3007 | Error | LSA secret retrieve failed | NTSTATUS |
| 3008 | Error | Emergency hardlink spawn failed | lastError |

### Wrapper `ExitProcess` codes

| Code | Meaning |
|------|---------|
| miner exit (0–255 typical, any DWORD) | Success path: miner’s `GetExitCodeProcess` |
| 2 `ERROR_FILE_NOT_FOUND` | Target missing |
| 5 `ERROR_ACCESS_DENIED` | Token, pipe DACL, or WinSta |
| 87 `ERROR_INVALID_PARAMETER` | `argc<2`, bad `--run` |
| 1314 `ERROR_PRIVILEGE_NOT_HELD` | `SeAssignPrimaryTokenPrivilege` missing |
| 1385 `ERROR_LOGON_TYPE_NOT_GRANTED` | NHMiner rights |
| 259 `STILL_ACTIVE` | Forced terminate of hung miner |
| `0xE0003004` | MSR fail-closed and preflight code unavailable |
| `0xE0003005` | Re-entry emergency spawn failed |

Do not map miner exit 87 to parse error; only use 87 **before** spawn.

---

## PR Plan

Incremental, independently reviewable. **No product IFEO keys on developer machines until PR-09** (installer). **C2 + combined IFEO+token path (PR-06) lands before the installer writes real miner IFEO keys.** Logging (PR-08) is before the lab so PR-10 has files.

### PR-01 — Scaffold, CLI parse, unit tests

- **Title:** `nhwrap: process entry, CommandLineToArgvW slicing, and parse fixtures`
- **Files/components:** `src/main.cpp`, `src/argv.cpp`, `src/argv.h`, `tests/argv_test.cpp`, CMake/Cargo
- **Dependencies:** none
- **Description:** Console subsystem EXE; fail closed on `argc < 2`; quote-aware reconstruction; `--run` / `--version`; `ResolveTarget` for relative argv[1].
- **Acceptance criteria:**
  - `ArgvQuote` round-trips through `CommandLineToArgvW` for: spaces, empty string, embedded `"`, trailing `\`, `C:\Program Files\Miners\xmrig.exe`.
  - IFEO-shaped argv uses index 1 as target; Debugger value has no extra switches.
  - Fixture: `lpApplicationName` full path + `lpCommandLine` basename `xmrig --url x` ⇒ resolved target is not cwd-only when cwd ≠ miner dir (`MinerSearchPath`).
  - PATH-hijack fixture: cwd ≠ miner dir; `PATH` prepends a decoy `xmrig.exe`; `MinerSearchPath` has the real dir → real path wins; decoy is never returned; source must not call `PathFindOnPathW`.
  - `--run -- <path with spaces> --url x` yields the same `LaunchRequest` as IFEO mode (`--run` requires an absolute path).
  - `argc==1` exits 87.

### PR-02 — Layer A environment sentinel and in-process C1 passthrough

- **Title:** `nhwrap: NICEHASH_SANDBOX_BYPASS passthrough with CreateProcessW + DEBUG_ONLY_THIS_PROCESS`
- **Files/components:** `src/env.cpp`, `src/spawn.cpp`, `tests/fake_miner.cpp`, `tests/loop_test.cpp`
- **Dependencies:** PR-01
- **Description:** Unicode env block; sentinel ⇒ `CreateProcessW` C1 inherit-stdio, wait, propagate exit. **No seclogon, no `DEBUG_*` on WithTokenW.**
- **Acceptance criteria:**
  - Child env contains `NICEHASH_SANDBOX_BYPASS=TRUE`.
  - With sentinel set, fake miner runs once; watchdog: >2 `nhwrap` in 1 s fails.
  - Exit code 42 from fake miner is wrapper exit 42.
  - Source does not pass `DEBUG_PROCESS` / `DEBUG_ONLY_THIS_PROCESS` to `CreateProcessWithTokenW` / `WithLogonW` (grep AC).
  - `cmd.exe /c set BYPASS` is **not** used.

### PR-03 — Layer B ancestry walk (NT + CIM fallback)

- **Title:** `nhwrap: PID-reuse-safe ancestor walk`
- **Files/components:** `src/ancestry.cpp`, `tests/ancestry_test.cpp`
- **Dependencies:** PR-01
- **Description:** NT walk + CreateTime; CIM 200 ms timeout; KD-3 NiceHash = intercept; C2 `nhimg_*` helper match.
- **Acceptance criteria:**
  - Fixture: parent NiceHash filename ⇒ `Intercept`.
  - Fixture: parent `nhwrap.exe` ⇒ `BypassAncestor`.
  - Fixture: parent `nhimg_abcd.exe` ⇒ `BypassHelper`.
  - Fixture: parent CreateTime > child ⇒ truncated ⇒ `Intercept`.
  - CIM timeout: mock hang ≥200 ms ⇒ NT-only decision, no crash.
  - Depth>2 sets `EmergencyReentry`.

### PR-04 — Job object and stdio proxy

- **Title:** `nhwrap: kill-on-close job and concurrent stdio splice`
- **Files/components:** `src/job.cpp`, `src/stdio_proxy.cpp`, `tests/stdio_deadlock_test.cpp`, `tests/headless_test.cpp`
- **Dependencies:** PR-02
- **Description:** Anonymous pipes, inherit-strip of all handles except three miner ends, three threads, drain-after-exit.
- **Acceptance criteria:**
  - Fake miner writes 1 MiB stderr then one stdout line; test finishes < 2 s; stdout line reaches parent.
  - `CREATE_NO_WINDOW` launch does not throw / does not call console key APIs.
  - Kill wrapper ⇒ fake miner and its child are gone (`KILL_ON_JOB_CLOSE` only; no `DIE_ON_UNHANDLED_EXCEPTION`).
  - Parent stdin EOF closes miner stdin; miner that exits on EOF does exit.
  - Raw `\r` progress is forwarded without extra `\n`.

### PR-05 — Token drop (linked / restricted / AsUser / WithTokenW)

- **Title:** `nhwrap: Medium-IL filtered token; AsUser+HANDLE_LIST; WithTokenW without DEBUG_*`
- **Files/components:** `src/token.cpp`, `src/spawn.cpp`, `tests/privilege_test.cpp`
- **Dependencies:** PR-04
- **Description:** `TokenLinkedToken` + `SecurityImpersonation` primary; skip second `LUA_TOKEN` on Limited; `CreateProcessAsUserW` + `HANDLE_LIST` when `SeAssignPrimaryToken` available; WithTokenW otherwise **without** `DEBUG_*`. No `cmd.exe`.
- **Acceptance criteria:**
  - Fake miner reports `TokenElevationType != Full`, IL Medium, Administrators not enabled.
  - Handle snapshot: child holds **no** `TOKEN_*` handle to an elevated token and no writable WinRing0 device.
  - Inherit-strip: only `{inRd,outWr,errWr}` inheritable at spawn (or HANDLE_LIST equivalent).
  - Linked-token path does not fail on `CreateRestrictedToken(LUA_TOKEN)` of an already-Limited token.
  - Pipe SD: same-user mode 0 default DACL is sufficient; no NHMiner SID required in v1.

### PR-06 — C2 miner-dir skip + combined IFEO+token path + skip probe

- **Title:** `nhwrap: miner-dir nhimg hardlink, spawn matrix, IFEO+WithTokenW combined test`
- **Files/components:** `src/imgcache.cpp`, `src/spawn.cpp`, `tests/nhifeo_probe.exe`, `tests/ifeo_token_test.cpp`
- **Dependencies:** PR-02, PR-05
- **Description:** Implements C2 **in the miner directory**; spawn matrix; depth-2 ownership tests. **This PR must pass before installer IFEO (PR-09).** Isolated test IFEO key on `nhifeo_probe.exe` only — not product miner names on dev machines.
- **Acceptance criteria:**
  - `CreateProcessWithTokenW` of an IFEO-hooked allowlisted **test** name: **no freeze**, ≤2 `nhwrap`, child Medium IL, **no `DEBUG_*` passed to seclogon**.
  - AsUser+C1 path (if privilege present): `GetModuleFileNameW` of child is original path; one miner, one outer nhwrap.
  - C2: `nhimg_*.exe` created **next to** the fake miner; child’s `GetModuleFileNameW` directory equals miner dir; sibling `WinRing0x64.sys` fixture is `CreateFile`-able from the child.
  - Probe: in-process C1 re-entry ⇒ `IfeoSkipMode=2`. WithTokenW+DEBUG must not be treated as success.
  - Off-dir cache copies `DeclaredSiblings`; AppLocker deny of ProgramData EXE is documented skip.

### PR-07 — MSR preflight allowlist and bounded wait

- **Title:** `nhwrap: version-table MSR preflight, WinRing0 skip, MsrTimeoutMs`
- **Files/components:** `src/preflight.cpp`, policy reader, `tests/preflight_test.cpp`
- **Dependencies:** PR-02, PR-05
- **Description:** `SelectMsrArgs` from `--version`/`--help` table; skip if flag missing or `WinRing0OnlyAdjacent`; `WaitForSingleObject(h, MsrTimeoutMs)` then `TerminateProcess`; stdio to NUL/log; fail-open/closed.
- **Acceptance criteria:**
  - Mock preflight writes `PREFLIGHT_BANNER` to stdout: parent stdout must **not** contain it.
  - Mock that never exits: wrapper continues by 30 s + slack; process is terminated; Event 2001/3004.
  - Mock that exits after 300 ms: wrapper continues only after that — no fixed `Sleep` as success.
  - Image without the table/policy flag in `--help`: preflight skipped (no full elevated miner).
  - Adjacent `WinRing0x64.sys` only (no `xmrig.sys`): preflight skipped, Event 2001 `winring0-only`; miner still starts if `FailMsr=0`.
  - Adjacent `xmrig.sys` + WinRing0: preflight **not** skipped solely because WinRing0 is present.
  - `FailMsr=0` + exit 1 ⇒ miner still starts; `FailMsr=1` ⇒ miner not started.

### PR-08 — Logging with mutex rotation and redaction

- **Title:** `nhwrap: 10 MiB concurrency-safe log rotation`
- **Files/components:** `src/log.cpp`, `tests/log_rotate_test.cpp`
- **Dependencies:** PR-01
- **Description:** `Local\` mutex (Medium-capable DACL); log dir append for Users; redaction.
- **Acceptance criteria:**
  - 8 processes appending 2 MiB each: archives created; no torn JSON lines; live file ≤ 10 MiB + one write overrun.
  - `--pass=secret` and `stratum+tcp://user:pass@host` not present in log bytes.
  - Mutex name `Local\NiceHashSandbox.LogRotate`.
  - **Non-elevated (Medium IL) wrapper writes a line without `SeCreateGlobalPrivilege`.**

### PR-09 — Installer, IFEO allowlist, Event Log, Defender exclusion, uninstall

- **Title:** `nhwrap-setup: IFEO allowlist, ACLs, Event Log, optional MpPreference`
- **Files/components:** `setup/`, `src/eventlog.cpp`
- **Dependencies:** PR-06 (combined path + probe), PR-07 optional, PR-08
- **Description:** IFEO allowlist only; `Debugger` always `ArgvQuote(WrapperPath)`; both WOW64 views; I9 **calls PR-06 probe** (does not re-specify it); conflicts refused; file-scoped Defender exclusion; uninstall.
- **Acceptance criteria:**
  - Clean VM: native **and** Wow6432Node `Debugger` values equal quoted `WrapperPath` for allowlisted names only; `cmd.exe` not hooked.
  - Pre-set foreign Debugger on `xmrig.exe` ⇒ that image skipped; foreign value unchanged.
  - Failed copy of `nhwrap.exe` ⇒ no IFEO `Debugger` left pointing at missing file (rollback).
  - Uninstall removes our Debugger (quote-normalized compare), leaves foreign Debugger, removes recorded Defender paths (or logs 2006).
  - I3 log dir allows Users append.
  - Hot path of `nhwrap.exe` does not import Defender APIs.
  - **v1 installer does not create `NHMiner`, an LSA secret, or `/account`.**
  - Writes **both** native and Wow6432Node IFEO `Debugger` values; ships only 64-bit `nhwrap.exe` (no `nhwrap32.exe`).

### PR-10 — Integration IFEO lab (caller×image bitness) and session matrix

- **Title:** `nhwrap: IFEO lab tests, caller-bitness WOW64 matrix, session matrix`
- **Files/components:** `tests/ifeo_lab/`, isolated VM CI
- **Dependencies:** PR-09
- **Description:** Set/clear IFEO; NiceHash-like parent; four tuples `(parent32|parent64)×(miner32|miner64)`; GPU/session notes.
- **Acceptance criteria:**
  - All four tuples launch 64-bit `nhwrap` and one miner (or documented skip if 32-bit parent cannot start 64-bit debugger — fail the build unless that skip is OS-proven).
  - 64-bit parent + 32-bit miner reads **native** IFEO, not Wow6432Node.
  - 32-bit parent + 64-bit miner reads **Wow6432Node**.
  - Combined token path: no freeze, ≤2 `nhwrap`, Medium child.
  - Loop watchdog fails the job if >2 `nhwrap` for one launch.
  - Session 0: CPU fake exits 0; GPU fake records Event 2003 and is **not** required to produce hashrate (GPU unsupported in session 0).
  - No `nhwrap-agent.exe` in the payload.
  - Four-tuple matrix uses a **single** 64-bit `nhwrap` (no `nhwrap32.exe`).
