# ZeroVSH PSP-1000 Engineering Guide

## Project goal

Reproduce as much of the PSP Go SlidePlugin experience as practical on real
PSP-1000 hardware, prioritizing the clock, calendar, open/close behavior,
transitions, animations, and related XMB resources. General ZeroVSH file
redirection already supports PSP-1000; SlidePlugin is the unsupported target.

## Architecture

ZeroVSH builds `user/zerovsh_upatcher.prx`, converts it to
`kernel/zerovsh_upatcher.h` with `bin2c`, embeds it in
`kernel/zerovsh_patcher.prx`, and copies the final plugin to
`bin/zerovsh_patcher.prx`. Kernel hooks redirect selected VSH files to Memory
Stick (or internal storage on PSP Go), while the embedded user module applies
user-mode VSH and SlidePlugin hooks.

## PSP-1000 constraints

- Model `0` is PSP-1000 and model `4` is PSP Go.
- PSP-1000 has much less RAM than later systems. Track total and largest
  contiguous free blocks, fragmentation, allocation lifetimes, and module
  load/start results instead of inferring runtime use from PRX file size.
- Keep hardware-dependent conclusions distinct from code inspection. A build
  cannot prove that SlidePlugin runs on a PSP-1000.

## Build

Use the current PSPDEV toolchain and run:

```sh
./build_linux.sh
```

Do not revert the modern PSPSDK compatibility work. The expected artifact is
`bin/zerovsh_patcher.prx`.

The Linux pipeline post-processes modern PSPSDK `bin2c` output to require at
least 64-byte alignment for `zerovsh_user_module`, then validates the final ELF
symbol address with `psp-nm` before copying the PRX. Both checks fail the build
loudly. The historical Windows pipeline uses the repository `_bin2c`, whose
embedded format string already requests `aligned(64)`; it does not use the
modern Linux `bin2c` path and has not been otherwise changed.

## Branch strategy

Keep major phases independently reviewable. Suggested branches are
`psp1000-memory-fix`, `psp1000-diagnostics`,
`psp1000-slide-experimental`, `psp1000-memory-optimization`,
`pspgo-xmb-fidelity`, `psp1000-custom-slide`, and
`psp1000-slide-stable`. Do not combine model unlocking with memory-correctness
work.

## Safety rules

- Never write to or modify `flash0`; use runtime hooks and Memory Stick assets.
- PSP-1000 SlidePlugin experiments must be explicitly opt-in and easy to
  disable to provide a boot-loop recovery path.
- Preserve existing PSP-2000/3000/Go behavior and model restrictions unless a
  dedicated phase intentionally changes them.
- Avoid logging in hot I/O hooks and any location where logging recursively
  invokes the hook.
- Preserve `readme.txt` as historical documentation until hardware-verified,
  user-facing behavior warrants an update.

## Known findings

- Before the `psp1000-memory-fix` phase, `zeroCtrlAllocUserBuffer` accepted its
  block UID by value. Allocations returned a usable address but discarded the
  actual UID, while callers tried to free zero-initialized shared `path_id` or
  `cfg_id` values. Every successful call therefore leaked its user-partition
  block and could attempt an invalid free.
- File-path allocation also leaked on the no-filename and blacklisted-font
  early-return paths.
- Shared allocation IDs were unsafe for nested or concurrent I/O hooks. Each
  operation now owns a local block UID, and allocation reports that UID through
  an explicit output parameter.
- The former global K1 save slot was unsafe across nested and concurrent calls;
  K1 restoration state is now function-local.
- User-module loading and both helper-thread creation paths now release their
  created resource when start-up fails.
- No heap or partition-memory allocation was found in `user/`, `kernel/hook.c`,
  `kernel/resolver.c`, `kernel/blacklist.c`, or `kernel/logger.c` during the
  phase-one source audit.
- Phase 1 was smoke-tested on a real PSP-1000: it booted normally, the XMB
  remained usable, and no obvious freeze, crash, or boot loop was observed.
  ClockAndCalendar was disabled, so this does not establish SlidePlugin
  compatibility.
- `zeroCtrlGetSlideConfig` formerly passed `sizeof(usermem)` to `ini_gets`.
  Because `usermem` is a pointer, this limited the 256-byte allocation to the
  pointer size (four bytes on PSP), truncating values to at most three
  characters. Phase 2 now passes the allocation's actual 256-byte capacity.

## Phase 2 diagnostics

- On PSP-1000 only, each VSH session truncates and writes
  `ms0:/zerovsh_psp1000.log`. Other models perform no diagnostic file I/O.
- The kernel captures memory in `PSP_MEMORY_PARTITION_USER` explicitly with
  `sceKernelPartitionTotalFreeMemSize()` and
  `sceKernelPartitionMaxFreeMemSize()`. Thus `total_free` and `largest_block`
  describe the user partition relevant to VSH and module loading, rather than
  an ambiguous context-dependent partition. Records cover kernel entry,
  NID/config setup, hook installation, embedded-user-module load/start, and
  completion, along with important operation return codes.
- The logger opens the Memory Stick file only from sparse initialization and
  loader-thread call sites. It may pass through the installed Memory Stick
  driver hook, which forwards to the saved original driver method. Never call
  the logger from `zeroCtrlMsIoOpen`, `zeroCtrlMsIoGetstat`, redirection hooks,
  module-probe file replacement, or other hot/recursively reachable I/O paths.
- The expected compact format begins with the diagnostic version, numeric and
  human-readable model, devkit, ClockAndCalendar value, redirection path, and
  locked SlidePlugin state. It then uses `[mem] <stage> total_free=<bytes>
  largest_block=<bytes>` and `[event] <operation> result=0x<code>` records.
- Loader-adjacent code deliberately performs no diagnostic calls after
  `sceKernelLibrary` is detected and before `sceKernelLoadModuleBuffer()`.
  After a successful load, the start-control path captures the post-load state,
  immediately starts the module, and captures post-start state before writing
  either snapshot. Valid partitions in the PSP system-memory ID range are
  identified by a successful
  `sceKernelQueryMemoryPartitionInfo()` call and later written with start
  address, partition size, attributes, total free memory, and largest block.
- After a successful load, the existing LoadCore `SceModule2` definition and
  `sceKernelFindModuleByName()` are used to log the verified module fields:
  module ID/name, attributes, text/data partition IDs, text/data/BSS sizes, and
  up to the four address/size segment entries represented by that structure.

## Phase 2 hardware evidence

- Multiple earlier real PSP-1000 logs recorded 23,177,984 bytes at the
  pre-load-labelled stage and 4,136,960 bytes at the post-load-labelled stage,
  a reproducible 19,041,024-byte difference (about 18.16 MiB). Those stages
  enclosed diagnostic calls and VSH scheduling, so they did not isolate the
  loader call and must not be interpreted as direct loader consumption.
- Disabling other VSH plugins and disabling Inferno Cache did not remove the
  reduction. The PSP-1000 remained stable in these tests.
- Clean runs consistently had `total_free == largest_block` both before and
  after loading. Severe fragmentation is therefore not supported by current
  evidence; investigation should focus on partition sizing/ownership and
  ModuleMgr loader semantics unless later measurements contradict this.
- The separately inspected `zerovsh_upatcher` has about 2.5 KiB of runtime ELF
  segments (`text=2472`, `data=0`, `bss=20`; load segment memory sizes 0x9b0
  and 0x14). Its text/data/BSS cannot explain the roughly 18 MiB reduction.
- USER-partition resizing, partition reassignment, a large ModuleMgr
  reservation, VSH-loader differences, and VSH-module-attribute differences
  remain unverified hypotheses pending the new partition/module metadata log.
- The embedded module historically used `0x0007`, comprising the no-stop,
  single-load, and single-start low bits. The current attribute-only A/B test
  adds the historical VSH classification bit and uses `0x0807`; its effect is
  not known until real-hardware results are collected.
- The project's ModuleMgr header documents VSH API type `0x20` and a path-based
  `sceKernelLoadModuleVSH()`, but does not expose the historical buffer-loader
  NID `0xF0CAC59E`. Its signature, 6.60/6.61 NID behavior, partition semantics,
  and suitability for this resolver remain research questions. Do not change
  the loader or perform an A/B test until the new hardware evidence is reviewed.
- Phase 2.5 successfully enumerated the real PSP-1000 partition map before a
  load: PID 2 reported the 25,165,824-byte (24 MiB) USER region at 0x08800000,
  PID 6 mirrored that region, PIDs 1 and 3 mirrored the 3 MiB kernel region,
  and PID 5 was a separate 4 MiB region at 0x08400000.
- An earlier broad measurement interval paired a failed `0x80020148` load
  (`SCE_KERNEL_ERROR_UNSUPPORTED_PRX_TYPE`) with a `0x01228000` USER-memory
  reduction, versus `0x01228B00` on earlier successful runs. That reduction can
  no longer be attributed directly to the loader because the interval included
  diagnostic work and VSH scheduling before the loader call.
- Deferred-write hardware diagnostics subsequently measured USER/PID 2 as
  25,165,824 bytes total and 23,128,832 bytes free immediately before the load.
  The load returned `0x80020148`; immediately afterward USER remained exactly
  25,165,824 bytes total and 23,128,832 bytes free. The loader-call delta was
  therefore zero bytes, and all successfully queried metadata for PIDs 1-6 was
  unchanged.
- Direct roughly 18 MiB consumption by `sceKernelLoadModuleBuffer()` was ruled
  out: the isolated failed call changed USER free memory by zero bytes, and the
  later aligned successful call consumed only `0xB00` bytes.
- A controlled real-hardware A/B test established the cause of `0x80020148`:
  modern PSPSDK `bin2c` emitted `aligned(16)`, placing
  `zerovsh_user_module` at 0x4EB0 (48 modulo 64). Changing only the generated
  alignment to 64 placed it at 0x4EC0 and the unchanged loader succeeded with
  module ID 0x045A4437. The loader's documented 64-byte buffer alignment is
  therefore a verified build requirement, now enforced by the Linux build.
- The aligned successful load reduced USER free memory from 23,128,832 to
  23,126,016 bytes: `0xB00` (2,816 bytes). Module metadata reported attribute
  0x0007, `mpid_text=2`, `mpid_data=2`, text=2,360, data=0, BSS=20, one segment
  of 2,756 bytes. The resident load cost closely matches the segment plus small
  alignment/loader overhead; `sceKernelLoadModuleBuffer()` does not consume
  roughly 18 MiB.
- The same run later measured 3,693,824 USER bytes free after module start, a
  `0x01288300` (19,432,192-byte, about 18.53 MiB) transition from the post-load
  capture. USER/PID 2 remained 25,165,824 bytes total and PID 5 remained a free
  4 MiB region, so no USER resize was visible. The older interval contained
  diagnostic serialization and module lookup, so it does not prove that
  `sceKernelStartModule()` caused the transition.
- The isolated start-control captures `after_load`, immediately calls
  `sceKernelStartModule()`, and captures `after_start` before performing any
  diagnostic write or module lookup. Only then are control markers, results,
  snapshots, and module metadata serialized.
- Real PSP-1000 start-control evidence localized the transition to the isolated
  synchronous start interval: USER free memory fell from 23,124,992 bytes
  after load to 4,119,552 bytes after start, exactly `0x01220000` (19,005,440
  bytes, 18.125 MiB). No diagnostic serialization or module lookup occurred
  between those captures, so asynchronous diagnostic I/O is no longer a
  supported explanation for this interval.
- PID 2 remained the 25,165,824-byte USER partition and PID 5 remained a fully
  free 4 MiB partition. PIDs 1/3/4/5 showed no large transition. Within PID 2,
  `total_free == largest_block == 4,119,552` after start, so the evidence shows
  occupation/reservation inside USER without a visible resize and does not
  support severe fragmentation.
- The aligned helper again reported attribute 0x0007, text/data partition 2,
  text=2,360, data=0, BSS=20, and one 2,756-byte segment. This footprint cannot
  explain the 18.125 MiB start-interval reservation.
- `ZEROCTRL_PSP1000_NOOP_USER_START_CONTROL` is temporarily enabled in both
  module builds. Under this compile-time control, the embedded user's
  `module_start()` performs no model/devkit query, handler installation,
  logging, memory query, or delay; it only returns success. The original body
  remains under `#else`. Kernel diagnostics emit
  `[experiment] user_start_control=noop` only after both start snapshots exist.
- Real PSP-1000 no-op testing produced the same byte-for-byte transition as the
  normal body: normal `module_start` delta = `0x01220000`; no-op
  `module_start` delta = `0x01220000`. The no-op run fell from 23,125,760 to
  4,120,320 USER bytes free. This excludes `zeroCtrlGetModel()`,
  `sceKernelDevkitVersion()`, `sctrlHENSetStartModuleHandler()`, handler
  registration, and all other work in the original body as causes.
- ModuleMgr/CFW start or classification semantics are now the leading area of
  investigation. Historical PSP/M33 and modern implementation documentation
  associate 0x0000 with USER, 0x0800 with VSH, and 0x1000 with KERNEL module
  classification. The current single-variable experiment changes only the
  helper's attribute from 0x0007 to 0x0807, retains the no-op start, and emits
  `[experiment] module_attr_control=vsh_0x0807` after applicable snapshots.
  Loader, API type, start call, and main-thread attributes remain unchanged.
- If 0x0807 loads and starts without `0x01220000`, classification is strongly
  implicated and the result must be reproduced before SlidePlugin work. A
  loader rejection instead supports a separately reviewed API-type experiment;
  a successful start with the same delta shows the VSH bit alone is
  insufficient. No alternative loader is part of this control.
- As supporting context only, modern ARK-style implementations of
  `sctrlHENSetStartModuleHandler()` replace a stored handler pointer and return
  the previous pointer, making a direct 18 MiB allocation there appear
  unlikely. This is not proof for the tested CFW; hardware A/B results remain
  authoritative.

## Current experimental state

Phase 2 adds diagnostics, retains the temporary compile-time no-op user-start
control, and currently performs an attribute-only 0x0007-to-0x0807 A/B test,
plus one bounded configuration-buffer fix.
PSP-1000 remains excluded by the existing kernel and user model checks; its
SlidePlugin is intentionally locked. No PSP-1000 SlidePlugin support or
firmware patch is enabled, and diagnostic usefulness/stability still requires
real-hardware verification.

## Hardware testing workflow

1. Confirm `ClockAndCalendar = Disabled` in
   `ms0:/seplugins/zerovsh.ini` and retain a recovery method that can disable
   the plugin.
2. Run `./build_linux.sh` with PSPDEV and copy
   `bin/zerovsh_patcher.prx` to the existing Memory Stick plugin location;
   do not touch `flash0`.
3. Restart the PSP/VSH, use the XMB normally for several minutes, and note any
   instability. Do not attempt to start SlidePlugin.
4. Copy the complete `ms0:/zerovsh_psp1000.log` back to the PC. Confirm it
   contains the header, all memory stages, and module/thread result records.
5. Return the unedited log and observations for analysis before any
   experimental PSP-1000 enablement.

Every phase report must state files changed, technical findings, assumptions,
build status, required hardware tests, hardware results if available,
unresolved questions, and the recommended next phase.
