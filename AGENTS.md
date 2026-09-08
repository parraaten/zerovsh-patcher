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

## Current experimental state

Phase 1 fixes ownership and lifetime errors only. PSP-1000 remains excluded by
the existing model checks. No PSP-1000 SlidePlugin support, diagnostics, or
firmware patch is enabled, and no hardware behavior is claimed.

## Hardware testing workflow

1. Build `bin/zerovsh_patcher.prx` on the PC.
2. Copy it and redirected resources to Memory Stick without touching
   `flash0`.
3. Test on a real PSP-1000 with a documented recovery/disable procedure.
4. Write sparse diagnostics to `ms0:/zerovsh_psp1000.log`, concentrating on
   state transitions, memory measurements, and module load/start errors.
5. Return the log and observed behavior for analysis before the next change.

Every phase report must state files changed, technical findings, assumptions,
build status, required hardware tests, hardware results if available,
unresolved questions, and the recommended next phase.
