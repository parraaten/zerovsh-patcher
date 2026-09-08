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
- Full partition snapshots are captured in memory immediately before and after
  the embedded user-module load regardless of its result, and after a start
  attempt following a successful load. Pre-load details are not written until
  the post-load snapshot is safe in memory, minimizing file-I/O and timing
  interference around the loader call. Valid partitions in the PSP
  system-memory ID range are identified by a successful
  `sceKernelQueryMemoryPartitionInfo()` call and later written with start
  address, partition size, attributes, total free memory, and largest block.
- After a successful load, the existing LoadCore `SceModule2` definition and
  `sceKernelFindModuleByName()` are used to log the verified module fields:
  module ID/name, attributes, text/data partition IDs, text/data/BSS sizes, and
  up to the four address/size segment entries represented by that structure.

## Phase 2 hardware evidence

- Multiple clean real PSP-1000 tests measured 23,177,984 bytes free immediately
  before `sceKernelLoadModuleBuffer()` and 4,136,960 bytes immediately after.
  The exact, reproducible reduction is 19,041,024 bytes (about 18.16 MiB).
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
- The embedded module's `0x0007` attribute comprises the no-stop, single-load,
  and single-start low bits; it has not been changed. Historical association
  of `0x0800` with VSH modules is not yet sufficient evidence to use `0x0807`.
- The project's ModuleMgr header documents VSH API type `0x20` and a path-based
  `sceKernelLoadModuleVSH()`, but does not expose the historical buffer-loader
  NID `0xF0CAC59E`. Its signature, 6.60/6.61 NID behavior, partition semantics,
  and suitability for this resolver remain research questions. Do not change
  the loader or perform an A/B test until the new hardware evidence is reviewed.
- Phase 2.5 successfully enumerated the real PSP-1000 partition map before a
  load: PID 2 reported the 25,165,824-byte (24 MiB) USER region at 0x08800000,
  PID 6 mirrored that region, PIDs 1 and 3 mirrored the 3 MiB kernel region,
  and PID 5 was a separate 4 MiB region at 0x08400000.
- That test's module load failed with `0x80020148`
  (`SCE_KERNEL_ERROR_UNSUPPORTED_PRX_TYPE`) yet still reduced USER free memory
  from 23,177,728 to 4,139,520 bytes: exactly `0x01228000` (19,038,208 bytes).
  Earlier successful loads reduced it by `0x01228B00` (19,041,024 bytes), a
  difference of `0xB00` (2,816 bytes), close to the tiny module's loadable
  footprint and plausible alignment/metadata overhead. This is a strong
  hypothesis, not proof of the allocation mechanism.
- The cause of `0x80020148` is unknown. Diagnostic file I/O is not established
  as its cause. The old success-gated instrumentation left the post-failure
  partition map unknown; the capture-before-write design now collects that map
  even when loading fails.

## Current experimental state

Phase 2 adds baseline diagnostics and one bounded configuration-buffer fix.
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
