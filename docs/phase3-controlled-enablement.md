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

### Phase 3.1a host-VSH trigger-disabled control

The breadcrumb hardware run reached the writer and completed the ordinary
ZeroVSH helper load/start, but its three-second terminal state was
`request=0 rco_request=0 probe=0 start=0`. The XMB nevertheless froze before
icons appeared. This proves that the freeze can occur before the Sony pipeline;
the corrected Sony no-op was not involved and must not be classified from this
run.

The next build keeps the PSP-1000 experiment armed and changes only the host
VSH behavior variable. When the experimental helper observes `vsh_module`, it
does **not** call `zeroCtrlRedir2Stub()` for `text_addr + 0x6F84`. Historical
non-1000/non-Go branches and offsets are unchanged. The explicit markers are
`psp1000_vsh_slide_trigger=disabled_control` and
`vsh_slide_patch=disabled`; `slide_hooks=minimal` is intentionally omitted.
The Sony `module_start_func` no-op remains dormant in source if an unexpected
request occurs.

For PSP-1000 devkit `0x06060110`, the helper bounds-checks a read-only window
from target minus 8 through target plus 15 against `vsh_module` text. It never
writes VSH code. A new fixed-scalar handoff (NID `0x1337357A`) copies module ID,
text address/size, module-start and ELF-entry addresses, target, validation,
and six surrounding words into fixed kernel state, publishing
`vsh_module_seen` last. The writer alone persists the checkpoint and
`vsh_modid`, `vsh_text_addr`, `vsh_text_size`,
`vsh_module_start_func_addr`, `vsh_elf_entry_addr`, `vsh_slide_target`,
`vsh_slide_target_in_text`, and word `m8` through `p12` events. An invalid
window records metadata and validation but performs no reads.

If the XMB completes boot with icons and working controls, this is strong
evidence that applying the forced PSP-1000 `+0x6F84` modification is necessary
for the freeze; it does not yet prove the offset itself is wrong. The next step
is to identify that real PSP-1000 instruction window and find a safe host
trigger. If the XMB still freezes, isolate the writer and experiment callback
scaffolding before returning to VSH offsets or Sony startup.

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

### Phase 3.1b read-only VSH code capture

The trigger-disabled control booted normally on real PSP-1000 hardware while
the corresponding trigger-enabled build froze before icons. The next build
therefore retains the disabled `vsh_module + 0x6F84` patch and expands only the
read-only evidence capture. For firmware 6.61, fixed kernel state holds the
clamped, word-aligned range from candidate minus `0x80` through candidate plus
`0xFF` (up to `0x180` bytes). No USER memory is allocated, and only the writer
thread emits the capture range events and addressed `[vshcode]` records.

The current six-word evidence does not establish a function entry or semantic
equivalence. In particular, the signed `lw` displacement resolves to
`0x09C682E0`, not `0x09C782E0`. Full analysis, explicit unknowns, and the one
next controlled hardware procedure are maintained in
`docs/phase3-vsh-trigger-analysis.md`.

### Phase 3.1c read-only predicate-reference scan

Real hardware returned the complete 96-word window and remained fully usable.
With that run's relocated base, `+0x6F84` is the exact start of a leaf predicate
that reads `0x09C7DAE0`, returns strict 0/1, and is true for `{4,5,7,9}`.
Adjacent leaf predicates classify the same apparent enumeration. This disproves
the earlier “unknown boundary” assessment but does not identify slide semantics
or establish whether historical `-1` is unsafe.

The next build still leaves every VSH instruction and global untouched. It
scans loaded VSH text in memory for correctly resolved direct J/JAL references
to all eight captured predicates and for compatible LUI/load/store references
to `0x09C7DAE0`. Fixed arrays retain at most 32 caller and 32 global-reference
windows, prioritize JAL over J and stores over loads, and report totals and
overflow. Only the existing writer thread serializes the compact matches and
their bounds-clamped `-0x30/+0x50` windows. See
`docs/phase3-vsh-trigger-analysis.md` for formats and the hardware procedure.

### Phase 3.1d relocation-aware shared-global scan

Hardware found three direct JAL callers of `+0x6F84`: `+0x058D4` and
`+0x13F6C` branch on zero/nonzero, while `+0x14020` uses a nonzero `movn` path
to contribute capability bit `0x40`. None of these direct callers distinguishes
1 from -1. Indirect references remain unknown, so this weakens rather than
absolutely disproves the strict-boolean hypothesis.

The same run exposed that the original global scan compared raw immediates.
VSH relocated from `0x09C26E00` to `0x09C26D00`, changing the predicate load
displacement from `0xDAE0` to `0xD9E0` while preserving global text-relative
offset `0x56CE0`; the scanner therefore incorrectly reported zero references.
The corrected build derives the global from the loaded predicate's validated
LUI/load pair, sign-extends its displacement, and compares fully reconstructed
effective addresses. It does not fall back to the observed offset. Stores are
still retained before loads, and obvious intervening definitions of the base
register terminate the bounded backward search. Detailed direct windows are
limited to the three already-known `+0x6F84` references to reduce log noise;
all predicate matrix counts remain enabled. VSH code and shared state remain
strictly read-only.

### Phase 3.1e read-only state-generator trace

The corrected hardware run found 15 relocation-aware references with no
overflow and one store to `vsh_shared_state` at `+0x671C`. Its delay-slot store
writes the return from a direct call to `+0x3F970`. The setter is conditional:
the available prefix reduces its inputs to `(incoming_a0 == 0) && ((incoming_a1 & 1) != 0)`,
but the exact earlier boundary is not yet captured.

The next build captures only initializer context `+0x6680..+0x673F`, generator
context `+0x3F8F0..+0x3FAEF`, and direct J/JAL caller windows for candidate
`+0x66EC` and generator `+0x3F970`. It validates the derived global's complete
four-byte range against trusted kernel `SceModule2` segment metadata and reads
its delayed current value only after successful revalidation. Predicate matrix
counts remain, but repeated detailed global output is limited to stores. All
VSH code/state remains untouched and the Sony path remains disabled.
