# Phase 2 final report: PSP-1000 baseline and memory audit

## 1. Restoration summary

The default build is restored to the last hardware-functional architecture:
the embedded helper is attribute `0x0007`, it is loaded with
`sceKernelLoadModuleBuffer`, and its original `module_start` installs
`OnModuleStart`. The temporary no-op start, `0x0807`, and VSH buffer-loader
experiments are no longer compiled or selected. The verified generated-array
alignment correction and final ELF modulo-64 check remain permanent.

The 0x0807 experiments remain findings, not baseline code:

- `0x0807` plus the ordinary buffer loader returned `0x800200D1`
  (`SCE_KERNEL_ERROR_ILLEGAL_PERM`).
- `0x0807` plus the resolved VSH buffer loader returned `0x80020149`
  (`SCE_KERNEL_ERROR_ILLEGAL_PERM_CALL`). The VSH loader resolved successfully
  using the known 6.60/6.61 mapping.
- Neither experiment reached `sceKernelStartModule`; neither establishes how a
  successfully loaded VSH-classified helper would affect memory.

## 2. Static binary footprint

File size and resident memory are deliberately separated. A fresh PSPDEV build
is required for exact final kernel ELF section/symbol numbers; this environment
has no PSPDEV. Run `psp-size`, `psp-nm -S --size-sort`, and
`psp-readelf -S -l` on both build ELFs before `build_linux.sh` removes them.

| Module | Text | Data | BSS | Embedded binary | Notable static objects |
|---|---:|---:|---:|---:|---|
| `user/zerovsh_upatcher` | Hardware metadata: about 2.2–2.4 KiB (one run: 2,360 B) | 0 B | 20 B | none | two integers and three callback pointers; one reported segment was 2,756 B |
| `kernel/zerovsh_patcher` | **Pending PSPDEV ELF measurement** | **Pending** | **Pending** | generated helper PRX, historically about 4.8 KiB on disk, aligned to 64 B | four 128-byte config arrays (512 B); resolver NID table (224 B on PSP); resolver library table (48 B); module/extension pointer tables (48 B); driver/callback pointers and diagnostic strings |

The helper PRX bytes are static data embedded in the kernel file and consume
kernel-module static memory. Once ModuleMgr loads the helper, its small USER
text/BSS is a separate resident copy. Reports must identify both but must not
mistake the embedded file bytes for helper USER text or count either as Sony
SlidePlugin runtime memory. Alignment can add at most 63 bytes of placement
padding before the embedded array; exact padding is linker-layout dependent.

## 3. Thread and stack inventory

| Thread | Entry | Priority | Stack | PSP-1000? | Class/lifetime | Termination and cleanup | Sizing assessment |
|---|---|---:|---:|---|---|---|---|
| `zeroctrl_umod` | `zeroCtrlLoadStartModule` | `0x10` | `0x10000` = 65,536 B | yes | **TEMPORARY** loader/helper-start worker | calls `sceKernelExitDeleteThread`; failed thread start deletes the thread; failed module start unloads the helper | likely oversized for current locals (two 232-byte snapshots plus ordinary frames), but measure high-water use before changing |
| `zeroctrl_btn` | `zeroCtrlReadButtons` | `0x10` | `0x10000` = 65,536 B | no under current guard | **CONDITIONAL/PERSISTENT** on supported non-Go/non-1000 models when ClockAndCalendar is enabled | infinite loop; released only with VSH/plugin teardown; failed start deletes thread | likely oversized, but callback/power paths need hardware stack measurement |

PSP-1000 currently reserves at most one explicitly created ZeroVSH stack at a
time: 64 KiB for `zeroctrl_umod`. Across supported configurations, both thread
objects can briefly coexist, so the conservative maximum configured stack
reservation is 128 KiB. Module framework start-thread stacks are system/module
owned and are not explicitly configured by this source audit.

## 4. Dynamic allocation inventory

| Call site/operation | Partition / size / mode | Lifetime and owner | Release/error path | Class |
|---|---|---|---|---|
| `zeroCtrlSwapFile` through `zeroCtrlAllocUserBuffer` | USER, 256 B, `PSP_SMEM_High` | one local UID per intercepted open/getstat operation | allocation failure returns null; missing filename and blacklisted font free immediately; open/getstat paths free after fallback/custom operation | temporary |
| `zeroCtrlGetSlideConfig` | USER, 256 B, `PSP_SMEM_High` | local `cfg_id` for one INI read | allocation failure returns; success always frees after copy; `ini_gets` receives the real 256-byte capacity | temporary |
| `sceKernelLoadModuleBuffer` for embedded helper | ModuleMgr chooses USER text/data (hardware showed PID 2); helper segment about 2.6–2.8 KiB | ModuleMgr UID; remains resident after successful start | failed start unloads; successful path intentionally retains it | persistent/system-managed |
| module-probe replacement read | destination is the loader-provided `data` buffer; file length varies | no ZeroVSH allocation; reads redirected module file into caller buffer | file is closed on success | externally owned buffer |
| INI/minIni operations and diagnostic file I/O | no `malloc`/partition allocation in ZeroVSH source | stack buffers and I/O-manager-owned internals | descriptors are closed | temporary/system-owned internals |

No `malloc`, `calloc`, or `realloc` call exists in `user/`, kernel hooks,
resolver, blacklist, logger, or main code. Phase 1 ownership remains correct:
callers initialize UIDs to `-1`; allocation reports the actual UID through an
output pointer; a failed head-address lookup frees and resets it; each successful
owner frees once; early returns free; and `zeroCtrlFreeUserBuffer` ignores
negative UIDs. No double-free path was found.

## 5. Configuration, path, and redirection memory

| Object | Storage | Size | Lifetime / observation |
|---|---|---:|---|
| `redir_path`, `useSlide`, `slideContrast`, `ledDisable` | kernel static | 128 B each, 512 B total | full kernel lifetime; bounded `ini_gets` writes |
| redirected path | USER partition block | 256 B per active redirected operation | transient; formatted as `redir_path + basename`; concurrent operations own separate UIDs |
| module-probe `filename` | kernel thread stack | 256 B | transient during probe; formatted device/path/module name |
| config scratch `usermem` | USER partition block | 256 B | transient per exported config read |
| registry `RegParam` | stack | SDK structure size | transient while setting welcome state |
| diagnostic formatting line | stack | 128, 160, 192, 224, or 256 B depending helper | transient per serialized record |

There is minor duplicated storage and generous 128/256-byte capacity, but the
realistic saving is hundreds of bytes, not MiB. It is **LOW VALUE / NOISE**
unless bounds-safe formatting is separately pursued for correctness. Existing
`sprintf`/`strcpy` sites deserve a future safety review, not a memory-first
rewrite in Phase 2.

## 6. Embedded helper lifetime and architecture

The kernel's temporary `zeroctrl_umod` thread loads the aligned embedded bytes,
starts the helper, and deletes itself. There is no successful-path unload, so
the helper remains resident for the VSH lifetime. Its persistent globals are
`model`, `devkit`, `previous`, `AddSysconfItem`, and `origFuncInit` plus its
small code/data. `OnModuleStart` is compiled into the helper text and its
address is passed to `sctrlHENSetStartModuleHandler`; the returned previous
handler is retained for chaining.

| Option | Feasibility | Expected saving | Risk | Complexity | Decision |
|---|---|---:|---|---|---|
| A. Keep helper resident | proven current architecture | none; persistent helper is only a few KiB | low | low | baseline/recommended |
| B. Move callback functionality into kernel PRX | technically conceivable, but user-mode VSH patch calls/import assumptions and callback execution privilege/addressability require validation | only the helper's few-KiB USER resident image; embedded bytes might also be removed | high compatibility and privilege risk | high | investigate only if later evidence makes a few KiB material |
| C. Install callback then unload helper | unsafe while handler points to helper `OnModuleStart`; slide hooks and helper globals also live there | few KiB | critical dangling callback/use-after-unload | superficially low, actually unsafe | reject unless callback is first moved/unregistered and all patches are proven independent |

## 7. Diagnostics memory and release cost

`ZeroCtrlPartitionEntry` is 28 bytes and a snapshot is 232 bytes on the 32-bit
PSP ABI. The loader worker holds two snapshots (464 bytes) while isolating load
and start. Logger formatting uses one stack buffer at a time, maximum 256 bytes;
module serialization uses 224 bytes and partition serialization 192 bytes.
Capture uses one SDK partition-info structure. Persistent diagnostic data is a
single enable integer plus code and strings in kernel static sections. ZeroVSH
diagnostics allocate no heap or partition blocks; I/O-manager buffering is
unknown/system-owned, and each sparse open is closed.

Phase 3 still needs these measurements. For release, introduce a single
`ZEROCTRL_PSP1000_DIAGNOSTICS` build flag that compiles declarations, strings,
capture structures, logger object code, and call sites to no-ops/out—not merely
a runtime false branch. Measure the kernel ELF before/after with PSPDEV before
claiming savings.

## 8. Sony SlidePlugin asset analysis

| Family | PRX file size | RCO file size | Static ELF observation |
|---|---:|---:|---|
| 6.20 | 1,820,476 B | 9,932 B | ELF32 MIPS PSP PRX; module string `slide_plugin_module` |
| 6.3x | 1,820,476 B | 9,932 B | same program-header layout, different PRX hash |
| 6.60/6.61 | 1,820,476 B | 9,932 B | same program-header layout, different PRX hash |

Host `readelf` sees no section table and three program headers. Two LOAD
segments report `FileSiz/MemSiz` 0x1b8730/0x1b8730 and 0x50/0x11bc,
respectively: 1,808,620 bytes of aggregate LOAD `MemSiz` before loader
alignment/metadata or runtime allocations. This is useful static evidence, not
a runtime RAM measurement. Stripped section/symbol metadata limits largest-
symbol/import/attribute analysis with host tools; PSP-aware tooling and actual
ModuleMgr metadata are required. The identical RCO files are UI resources and
must not be counted as resident PRX text merely because they are redirected.

## 9. Existing SlidePlugin path, separated by responsibility

**Load mechanism.** Firmware/VSH decides to request `slide_plugin.prx`.
ZeroVSH's flash open/getstat hooks recognize `.prx`/`.rco`, derive the basename,
and try the same filename below `RedirPath` on Memory Stick (internal storage on
Go), falling back to flash on failure. `zeroCtrlModuleProbe` replaces only
`vshmain.prx`, `paf.prx`, and `common_gui.prx`; it does not explicitly load the
SlidePlugin.

**Trigger/start mechanism.** On currently supported non-1000/non-Go models with
firmware >= 6.00 and `ClockAndCalendar=Enabled`, the kernel installs its module
start handler and persistent button thread. User-side VSH patches alter the
firmware slide check so VSH can request the plugin. The exact Sony ModuleMgr
load/start remains VSH-owned.

**UI behavior.** The button thread moves ZeroVSH's state between STARTING,
STARTED, STOPPING, and STOPPED, supplies the impose parameter behavior, keeps
power awake, and restores brightness/LED/clock state when stopping. The RCO
supplies related UI resources through ordinary redirection.

**Clock/calendar patches.** When `slide_plugin_module` starts, kernel-side
`OnModuleStart` hooks its `sceBSMan` and `sceVshBridge` imports. User-side
`OnModuleStart` patches local-time handling and the plugin initialization entry
to apply LED, brightness, and CPU-speed behavior. These are behavior patches,
not the mechanism that loads the PRX.

## 10. Phase 3 first controlled hardware experiment

The first question is only whether the Sony PRX can load/start on PSP-1000 and
what each step costs. Do not enable the full clock/calendar behavior.

1. Add `[Experimental] PSP1000SlidePlugin = Disabled` to the configuration
   schema, defaulting to disabled. Require both `model == 0` and exact `Enabled`
   before bypassing a narrowly identified guard; retain every normal-model path.
2. Require ClockAndCalendar to remain disabled, Memory Stick-only deployment,
   and a tested recovery method (disable/remove plugin from recovery mode).
3. Select only the firmware-matching Sony PRX/RCO and verify their hashes/files
   before boot. Never write `flash0`.
4. In memory only, capture USER free/largest and raw partitions immediately
   before Sony module load. Invoke the existing VSH-owned load path with no
   diagnostic write in the interval.
5. Immediately capture post-load state and, on success, `SceModule2` metadata:
   result, attribute, `mpid_text`, `mpid_data`, text/data/BSS, segment addresses
   and sizes. Keep UI/contrast/brightness/clock/LED/button patches disabled or
   bypassed unless evidence shows Sony initialization strictly requires one.
6. In a separate one-variable run, start the loaded plugin, immediately capture
   USER/partition state and return code, then serialize all retained snapshots.
7. Optionally take one sparse delayed/idle snapshot after XMB stabilization to
   distinguish synchronous load/start cost from later VSH activity.
8. A failure is data: log the exact negative code and snapshots; do not add an
   alternate loader, thread attribute, or firmware patch in the same run.

Instrumentation may require a narrow ModuleMgr hook or existing start-handler
observation to expose the VSH-owned load boundary. That mechanism is a Phase 3
implementation decision and must be reviewed for recursion and firmware
specificity before deployment.

## 11. Optimization priorities (no changes implemented)

| Component | Current known cost | Persistent? | Opportunity / estimated saving | Difficulty | Regression risk | Priority |
|---|---:|---|---|---|---|---|
| Loader thread stack | 64 KiB configured | temporary | measure then reduce; potentially tens of KiB while active | medium | medium | **HIGH VALUE** |
| Button thread stack | 64 KiB configured | conditional persistent | measure then reduce; potentially tens of KiB | medium | high (UI/power paths) | **HIGH VALUE** before full feature |
| Diagnostics | 464 B snapshot locals + <=256 B line stack + kernel code/strings | Phase 3 only | compile out production code/strings; exact static saving pending ELF | low-medium | low if gated | **MEDIUM VALUE** |
| User helper residency | one ~2.6–2.8 KiB segment plus loader metadata | persistent | kernel move could save only a few KiB | high | high | **LOW VALUE** |
| Embedded helper bytes | historically ~4.8 KiB kernel static | persistent | external load removes bytes but adds I/O/deployment complexity | medium | medium-high | **LOW VALUE** |
| 256 B redirect/config blocks | 256 B per active operation | temporary | shorten/cache; at most hundreds of bytes normally | low | concurrency/correctness risk | **LOW VALUE / NOISE** |
| Four config arrays | 512 B total | persistent | tighter typed settings; likely <400 B | medium | low-medium | **LOW VALUE / NOISE** |
| Duplicate strings/tables | hundreds of bytes, exact ELF pending | persistent | deduplicate/strip diagnostics in release | low-medium | low | **LOW VALUE / NOISE** |
| Old firmware branches/NID table | ~272 B tables plus code | persistent | firmware-specific build could remove some | medium | high compatibility risk | **LOW VALUE / NOISE** |

## 12. Unknown/system-owned memory

- The exact final kernel text/data/BSS, largest symbols, and diagnostic static
  delta are blocked on a fresh PSPDEV ELF retained before cleanup.
- The `0x01220000` transition occurs during the wall-clock interval in which
  `sceKernelStartModule` executes, identically for original and no-op helper
  starts. This excludes ZeroVSH's original start body, but does **not** prove
  ModuleMgr allocated all 18.125 MiB for ZeroVSH; other VSH activity may run
  while the call blocks or schedules. It is not a Phase 2 optimization target.
- Sony SlidePlugin runtime allocations, exact imports, and ModuleMgr-selected
  partitions remain hardware/PSP-tooling unknowns despite the static LOAD sizes.

## 13. Phase 2 exit criteria

### Functional baseline

- 0x0007 helper restored? **YES**
- ordinary buffer loader restored? **YES**
- original `module_start` restored? **YES**
- aligned(64) preserved? **YES**
- build passes? **PENDING PSPDEV** (source/static checks pass here; rerun
  `./build_linux.sh` and confirm both alignment messages and output artifact)

### Memory audit

- kernel static footprint known? **BLOCKED/PARTIAL** — source objects and stale
  artifact file size are known; exact restored ELF sections/symbols need PSPDEV.
- user static footprint known? **YES/PARTIAL** — real module metadata supplies
  resident sizes; refreshed restored ELF symbol ranking needs PSPDEV.
- all ZeroVSH threads inventoried? **YES**
- all dynamic allocations inventoried? **YES**
- persistent helper lifetime understood? **YES**
- diagnostics cost understood? **YES**, except exact linked static byte delta
- realistic optimization candidates ranked? **YES**

### SlidePlugin readiness

- SlidePlugin load path understood? **YES**, with the exact VSH-owned load
  boundary instrumentation mechanism deferred to Phase 3 design review
- Sony asset metadata inspected? **YES/PARTIAL** — file and LOAD metadata known;
  section/symbol detail is unavailable because the PRXs have no section table
- controlled load/start memory test designed? **YES**
- explicit PSP-1000 opt-in design specified? **YES**
- Phase 3 first hardware experiment defined? **YES**

Phase 2 can close after the restored build and PSP-1000 smoke test confirm the
functional baseline. Exact kernel ELF accounting remains an explicitly blocked
toolchain measurement, not a reason to change runtime behavior in this phase.
