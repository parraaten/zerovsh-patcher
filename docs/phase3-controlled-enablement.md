# Phase 3 report: controlled PSP-1000 Sony SlidePlugin enablement

## Scope and implementation

This phase adds one default-disabled setting, `[Experimental]
PSP1000SlidePlugin`. The kernel reads it into a fixed 16-byte buffer during
normal initialization. The experiment is armed only when the hardware model is
0, that value is exactly `Enabled`, and `ClockAndCalendar` is exactly
`Disabled`. The exported predicate reports only this already-validated armed
state to the embedded user helper; no USER allocation is added.

The one condition bypassed is the user helper's existing
`(model != 0) && (model != 4)` guard around the VSH slide-check patch. On 6.61,
the experiment redirects the two instructions at `vsh_module + 0x6F84` to
`zeroCtrlDummyFunc`, exactly as the established path does on supported non-Go
models. The PSP-1000 exception applies only to the `vsh_module` case. It does
not patch `sysconf_plugin_module` and does not apply the helper's
`slide_plugin_module` RTC or initialization hooks.

The 6.61 trigger path established by source inspection is:

1. the helper observes `vsh_module` through
   `sctrlHENSetStartModuleHandler()`;
2. the patch at `vsh_module + 0x6F84` replaces the firmware slide-check result;
3. VSH's existing code requests `slide_plugin.prx` (ZeroVSH never directly
   calls a loader for the Sony module);
4. the flash driver open/getstat hooks try the same basename under
   `ms0:/PSP/VSH` and fall back to flash if absent;
5. firmware ModuleMgr/LoadCore probes, relocates, and starts the PRX; and
6. the chained start-module handlers observe `slide_plugin_module`.

The existing firmware-family asset selection is therefore retained. For
devkit `0x06060110`, deploy unmodified `slide_plugin_660.prx` and
`slide_plugin_660.rco` as `slide_plugin.prx` and `slide_plugin.rco` below the
configured redirection directory. This commit does not alter any Sony asset.

## Instrumentation choice and limitations

The implementation combines two already-present, narrow observations rather
than adding a broad ModuleMgr loader hook:

- `zeroCtrlModuleProbe()` recognizes `slide_plugin_module` without changing
  its buffer and captures the fixed kernel snapshot labelled
  `at_slide_plugin_probe`. This proves that the Sony image reached LoadCore, but
  it is a probe-time measurement—not a snapshot before VSH's loader request.
- the existing start-module callback captures `slide_plugin_pre_start`, plus a
  private copy of `SceModule2`. At this point relocation has completed and the
  callback runs immediately before the Sony entrypoint. This distinguishes a
  loaded/relocated module from the earlier probe without claiming an
  after-start measurement.
- the one-shot diagnostic writer thread and its unchanged 0x2000-byte stack are
  created during kernel initialization, before the embedded helper can enable
  the VSH request patch. It sleeps until the probe, then waits up to two seconds
  for the start callback. If observed, it waits 750 ms from that callback,
  captures `slide_plugin_delayed`, and serializes retained state. On timeout it
  records `slide_module_start_not_seen` and `slide_plugin_start_timeout`.
  Before either normal exit it clears `deferred_thread_started`.
- no file I/O occurs in flash hooks, the executable probe, or the start
  callback. Flash opens inspect the incoming filename with K1 locally cleared
  and restored, and set only fixed in-memory PRX/RCO request flags.

This is the least invasive useful option because the project already hooks the
probe and already chains the start callback. It introduces no undocumented
6.61 ModuleMgr NID and does not intercept or change loader arguments/results.
Because the writer thread has constant memory presence across both snapshots,
its stack and thread overhead do not contaminate the probe-to-pre-start delta.
Consequently, this first scaffold **cannot** obtain the VSH-owned loader return
code, the Sony `module_start` return code, or an immediate post-start snapshot.
It must not label the delayed sample as direct start cost. If the callback is
seen, module ID/name, attributes, text/data partitions, text/data/BSS sizes,
and up to four segments are available. If probe is seen but callback is not,
the evidence localizes failure only to the probe-to-start-callback interval.

## Capability and safety separation

Only capability A (the minimum VSH request patch) and capability B
(observation) are enabled. On PSP-1000 the kernel handler returns after capture
and before Sony import hooks; the user handler likewise skips RTC and
initialization hooks. The sysconf patch, persistent 64 KiB button thread,
clock/calendar behavior, impose-state behavior, LED control, brightness, CPU
clock changes, and initialization injection remain disabled. Existing behavior
on every historically supported model is unchanged.

The ordinary `0x0007` embedded helper, `sceKernelLoadModuleBuffer`,
`sceKernelStartModule`, original helper `module_start`, existing 64 KiB stacks,
and generated/linked 64-byte alignment checks remain unchanged. No path writes
to `flash0`; recovery remains disabling `zerovsh_patcher.prx` in `vsh.txt` or
through recovery mode.

## Hardware test configuration and procedure

Use exactly:

```ini
[General]
RedirPath = /PSP/VSH

[SlidePlugin]
ClockAndCalendar = Disabled
Contrast = Disabled
StartBtn = 0x010000
StopBtn = 0x010000

[PowerSave]
LED = Disabled
Brightness = -1

[Experimental]
PSP1000SlidePlugin = Enabled
```

1. Build with current PSPDEV/GCC 15.2 using `./build_linux.sh`.
2. Confirm both generated-array and linked-symbol 64-byte alignment messages,
   and confirm `bin/zerovsh_patcher.prx` exists.
3. Copy the existing 6.60 assets to `/PSP/VSH/slide_plugin.prx` and
   `/PSP/VSH/slide_plugin.rco` on Memory Stick; do not modify them or flash0.
4. Install the built plugin using the existing Memory Stick setup and retain a
   recovery-mode method to disable its `vsh.txt` entry.
5. Verify the configuration above, restart VSH, and do not press slide buttons.
6. Observe XMB usability for several minutes and record any freeze/restart.
7. Retrieve the complete `ms0:/zerovsh_psp1000.log` without editing it.
8. Set `PSP1000SlidePlugin = Disabled` before any unrelated test.

Expected header markers are `[phase] psp1000_slide_phase3`, opt-in enabled,
clock/calendar disabled, minimal hooks, and button thread disabled. Depending
on progress, deferred records include `slide_request_seen`,
`slide_rco_request_seen`, `slide_probe_seen`, `slide_module_start_seen`,
`slide_module_modid`, `at_slide_plugin_probe`, `slide_plugin_pre_start`,
module/segment metadata, and either `slide_plugin_delayed` or
`slide_plugin_start_timeout`. Absence of a marker is meaningful; an immediate
freeze can also prevent the deferred serializer from writing captured state.

## Interpretation and next one-variable experiment

| Result | Interpretation | Next experiment |
|---|---|---|
| A: no request/probe | Minimum VSH trigger is still blocked. | Instrument only the 6.61 VSH request condition/call site; do not alter Sony files. |
| B: probe/request, no start callback | ModuleMgr/LoadCore rejected or stopped the image before start observation. | Add only the narrowest verified loader-result observation needed to obtain the exact error. |
| C: loaded module evident, start callback absent | The image is structurally loadable but the transition to start is blocked. | Instrument only that ModuleMgr start boundary and return code. |
| D: start callback, then freeze | Sony code reached startup; initialization/resource/UI work is now the boundary. | Add only an immediate post-start/result observation; keep behavior patches off. |
| E: callback and stable XMB | The original Sony module can reach startup on this tested PSP-1000. | Repeat unchanged once; then enable one Sony behavior capability on a separate branch/run. |

## Findings, assumptions, and unresolved questions

### First PSP-1000 hardware result

The first controlled run requested both Sony assets, reached the executable
probe, loaded and relocated `slide_plugin_module`, and reached the pre-start
handler. Its module ID was `0x04A15317`, attribute `0x0000`, text/data
partitions 2/2, text 1,804,080 bytes, data 80 bytes, BSS 4,460 bytes, and two
segments of 1,804,080 and 4,540 bytes (1,808,620 bytes aggregate). This proves
that the original Sony PRX itself fits and loads on the tested PSP-1000; it
disproves simple PRX-load RAM insufficiency.

USER free memory was 1,693,440 bytes at probe and 1,701,376 bytes at the
pre-start callback. The 750 ms sample contained 1,745,920 free bytes. PID 5
remained separately fully free at 4,194,304 bytes and must not be assumed
available to ordinary Sony USER allocations. Runtime-memory insufficiency
during Sony initialization therefore remains plausible but unproven. The XMB
froze before its icons appeared, localizing the current boundary to at or after
the Sony start transition rather than Sony loading/relocation.

### Sony entrypoint no-op control

The next run changes one semantic variable. Commit `542b16f` was superseded
before hardware validation because it targeted the ELF entry address at
`SceModule2` offset `0x64`, not the ModuleMgr module-start function pointer at
offset `0x50`. These are different concepts: ModuleMgr executes
`module_start_func`, while `entry_addr` remains diagnostic evidence only.

After capturing pre-start state, the kernel chains the prior SystemControl
handler exactly once and retains its result. It then re-reads both live fields,
using `module_start_func` as the control target and preserving `entry_addr`
without modifying it. The target must be nonzero, not `0xFFFFFFFF`, word
aligned, and have room for both replacement words in both the module text range
and one reported segment. Subtraction-based bounds checks avoid address
overflow. Failure leaves Sony code untouched and records a negative validation
reason.

On validation success, the original two words are retained in fixed kernel
state and replaced in RAM—not on disk—with `0x03E00008` (`jr $ra`) and
`0x24020000` (`addiu $v0, $zero, 0`). In standard MIPS encoding the first word
has SPECIAL opcode 0, function 8, and source register 31; the second has ADDIU
opcode 9 with source/destination registers 0/2 and immediate 0. The delay-slot
instruction therefore returns integer success before control returns to the
caller. Existing full D-cache writeback and I-cache invalidation run after the
two stores. Only then is the in-memory start-seen flag published to the writer.

Deferred output adds `[experiment] sony_module_start_control=noop`, distinct
`slide_module_start_func_addr` and `slide_elf_entry_addr` values,
module-start in-segment validation, both original words, and either
`slide_module_start_patch_applied=1` plus
`sony_module_start_control=noop_applied`, or the negative
`slide_module_start_patch_skipped` reason. There is still no Sony start
return-code observation. The local header has build-time assertions for
`module_start_func == 0x50`, `entry_addr == 0x64`, and `text_addr == 0x6C`, so
renaming the known fields cannot silently alter their ABI layout.
All trigger, opt-in, diagnostic-thread, asset, helper-loader, stack, and Sony
behavior-hook semantics otherwise remain identical to the first run.

Interpretation is deliberately narrow: normal XMB startup with the no-op shows
that loading/relocation alone did not freeze it and makes original Sony startup
the next dependency boundary. A continued freeze places the failure before or
independently of the original entry body, so the next single-variable work is
the VSH slide-state/registration semantics. Failed validation requires returning
the logged address and ranges without guessing another patch location.

### Phase 3.1 freeze-boundary breadcrumb build

The first corrected-module-start hardware attempt is **INCONCLUSIVE**. The VSH
boot sound, background/wave, and slightly more translucent clock/battery
appeared, but icons did not and VSH froze. Its log ended after the ordinary
ZeroVSH helper metadata. No persisted evidence proves that the Sony request,
probe, pre-start callback, or no-op patch occurred, so this is not Result B and
must not be described as “no-op applied and still froze.”

The writer now begins a three-second absolute pre-probe window when its thread
starts and polls fixed volatile state every 10 ms. It writes its alive marker
immediately and writes each newly observed checkpoint at most once. If probe is
not seen by three seconds, it serializes the request/RCO/probe/start flag values,
writes `slide_probe_not_seen timeout_us=3000000`, and exits normally. After
probe, the existing two-second start timeout and 750 ms post-callback delay are
unchanged, as are the existing probe, pre-start, delayed, and timeout snapshot
semantics.

Fixed state now distinguishes writer alive; request and RCO observation; probe
callback entry and return; start callback entry; prior-handler return;
module-start target read; validation completion/success; original-word save;
two-word write; cache synchronization; and start-callback return. Probe now
retains the exact `sceKernelProbeExecutableObject()` result, publishes the
returning milestone, and returns that result unchanged. Start milestones follow
the documented control order, and `saw_start` remains the final compatibility
publication before returning the chained handler result.

All file writes still originate only in `zeroctrl_slide_diag`; the IoOpen,
probe, and start callbacks mutate fixed memory only. This is intentionally a
breadcrumb build: asynchronous one-line Memory Stick writes every newly
observed transition can perturb VSH timing. Do not use this run for precise
memory-cost conclusions. Once the freeze boundary is known, return to deferred
logging for quantitative measurements.

Expected checkpoint order is writer alive, request, optional RCO, probe entered,
probe returning with result, start entered, previous handler returned with
result, target read with address, validation with result, original saved, words
written, cache sync complete, and start callback returning. The last persisted
line localizes the boundary. In particular, cache-sync and callback-returning
markers prove the corrected no-op was installed; only then can a later freeze
support the host VSH-state hypothesis.

Files changed are the kernel/user handlers and export bridge, diagnostic writer,
sample INI, this report, and `AGENTS.md`. `readme.txt`, Sony PRX/RCO files,
loader attributes/APIs, stack sizes, and firmware data are untouched.

The original Phase 3 run proves request, RCO access, load/relocation, and the
pre-start boundary. The first corrected no-op attempt adds no conclusive stage
evidence because its SlidePlugin markers were not persisted. The VSH-owned
start result and normal USER allocation access to PID 5 also remain unknown.
Return the breadcrumb sequence, both logged addresses, validation/patch
markers, available snapshots, and stability result before choosing the next
single-variable experiment.
