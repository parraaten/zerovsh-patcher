# Phase 3 report: controlled PSP-1000 Sony SlidePlugin enablement

## Current controlled behavioral experiment: selective `+0x58D4` trigger

Completed read-only reverse engineering proves that
`sceVshBridge:0x21C243FE` is `vshKernelGetModel`, the PSP-1000 shared VSH model
state is 0, and `+0x66E0` is called from `+0x70E0` with `a0=1` and
`a1=0xFFFF`. It also proves that `+0x6F84` is a model/capability predicate,
that globally forcing it freezes PSP-1000, and that its only direct callers are
`+0x058D4`, `+0x13F6C`, and `+0x14020`.

The next experiment is the first behavioral control. With both experimental
options explicitly enabled, and only on PSP-1000 firmware 6.61 with
`ClockAndCalendar=Disabled`, it semantically validates and rewrites the single
JAL word at `+0x58D4` to call a strict-true function. It does not write the
delay slot, predicate `+0x6F84`, shared state, either other caller, initializer,
or model import. The Sony module-start no-op is dormant; request and start are
left to the native VSH/Sony pipeline. Whether this caller specifically causes
the SlidePlugin request remains unknown and requires hardware testing.

### Phase report

- **Files changed:** `user/main.c`, `kernel/main.c`, `bin/zerovsh.ini`, this
  report, and `docs/phase3-vsh-trigger-analysis.md`.
- **Technical findings:** the model source and three predicate callers are
  hardware-proven; `+0x58D4` is the strongest gate-like caller, but its effect
  is not yet proven.
- **Assumptions:** loaded-module text bounds identify executable VSH text, and
  the established module-start handler observes `vsh_module` before this gate
  is needed.
- **Build status:** the Linux build is required; a successful build does not
  establish PSP-1000 runtime compatibility.
- **Hardware test required:** boot once with both opt-ins enabled and return the
  complete log plus XMB stability observations, using a recovery method.
- **Hardware results available:** the prior read-only build booted normally;
  the selective write has not yet been tested on hardware.
- **Unresolved questions:** whether this one caller requests the PRX/RCO and
  whether natural Sony initialization remains live.
- **Recommended next phase:** classify the result as A-E before restoring this
  word or considering a different single caller; do not enable clock/calendar.

## Historical initial scope and implementation (superseded)

The initial Phase 3 experiment added one default-disabled setting, `[Experimental]
PSP1000SlidePlugin`. The kernel reads it into a fixed 16-byte buffer during
normal initialization. The experiment is armed only when the hardware model is
0, that value is exactly `Enabled`, and `ClockAndCalendar` is exactly
`Disabled`. The exported predicate reports only this already-validated armed
state to the embedded user helper; no USER allocation was added. The global
predicate patch and the later Sony start no-op described in the historical
sections below are both dormant in the current selective build.

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

### Phase 3.1f read-only state-source import resolution

Hardware validated `vsh_shared_state` inside a VSH segment and read value 0 on
PSP-1000. It also proved `+0x3F970` is a two-word `jr ra; syscall 0x2617` import
stub, not an internal generator. The widened initializer sequence proves the
assignment condition is original `a0 == 1 && a1 == 0xFFFF`; `+0x66E0`, after an
unconditional jump/delay slot, is now the entry candidate.

The next build removes the large import-stub-table window and its 29 caller
windows. It traverses only validated `SceLibraryStubTable` descriptors within
trusted VSH segments, validates NID and function-stub arrays, and structurally
matches runtime stub `+0x3F970` to its library and NID. It scans callers of
`+0x66E0` with the existing relocation-safe algorithm so their `a0/a1` setup can
be analyzed. No import is called and VSH code/state remains untouched.

## Natural Sony module_start boundary trace

Extended real PSP-1000 T4 evidence now proves the ordered native pipeline:
`+0x58D4` forced true, PRX request, LoadCore probe, pre-start handler, RCO
request, then a later crash. The `saw_start` breadcrumb is only **PROVEN**
evidence that the pre-start handler observed `slide_plugin_module`; it does not
prove Sony's natural body entered or returned.

The exact opt-in `PSP1000SonyStartTrace=Enabled` installs only when diagnostics,
the PSP-1000 SlidePlugin experiment, ClockAndCalendar-disabled state, 6.61, and
`DangerousCaller58D4` all match. Hardware proved the earlier metadata-pointer
installation but did not persist an entry marker, so the current control uses a
return-address interposition trace. Hardware already proved the prior direct
return scan failed closed (`validation=0`, `install=0`) after recognizing the
entry pair, so that crash is not attributed to the tracer. The replacement
validates three prologue instructions but patches only the first two with
`J`/NOP. The entry stub saves the incoming ModuleMgr `ra`, substitutes the exit
stub address, reproduces `addiu sp,sp,-16` and `sw s0,0(sp)`, then jumps to the
natural body at `+8`. Sony's untouched `sw ra,4(sp)` saves the interposed return.
If Sony naturally restores and uses it, the exit stub records unchanged `v0`
and jumps to the saved ModuleMgr caller address. No Sony return site is located
or patched. Entry, return, and result are fixed BSS evidence. Only the
deferred writer persists them. No memory query is made in either stub. When
that writer first observes a return,
it captures the nearest safe USER-partition snapshot; this is not an exact
in-wrapper interval measurement.

### Saved-RA registration failure localization

The first saved-RA hardware run retained the native `+0x58D4` pipeline but
persisted no `[sony-start-ra]` record even though its exact config marker was
present. This proves neither entry nor non-entry: the installer sets
`attempted=1` only after its initial guards, and `registered=0` is the leading
hypothesis. Registration now records each supplied helper address, helper module
metadata and four bounded segment ranges, and one stable failure reason without
changing any acceptance condition. The installer similarly records the exact
initial guard that precedes `attempted=1`. All persistence remains in the
existing deferred writer.

Hardware subsequently **PROVED** `RESULT_SLOT_OUT_OF_RANGE(14)`: the first
eight scalar arguments were coherent, while the ninth arrived as `0x00008613`
instead of an address in the helper segment. The private registration ABI now
passes one pointer to a fixed 36-byte, nine-`u32` descriptor. The kernel first
validates that the complete descriptor lies in a loaded helper segment, copies
it once under the existing K1 convention, and only then applies every existing
stub/slot range and alignment check to the copy. The deferred log begins with
`[sony-start-register-descriptor] address=... size=36 validation=...`.

This is an ABI transport correction only. The saved-RA assembly, its two-word
Sony entry patch, trigger semantics, and production defaults are unchanged.

## Phase 3 Strategy B: BSMan-only CLOSED experiment

### Evidence boundary

**PROVEN (PSP-1000 6.61 hardware):** selective VSH caller `+0x58D4` alone
opens the native pipeline; the Sony PRX is requested; LoadCore probes it and
returns zero; the pre-start handler observes it; natural Sony `module_start`
enters, executes, returns, and returns success (`0`); and the RCO request occurs
after that return. The current failure boundary is therefore
**post-`module_start` runtime / RCO / activation / PAF**, not `+0xF98`, the
external call near `+0xFA4`, or the routine near `+0xFE8`.

**PROVEN:** USER memory is substantially lower at the deferred observation of
Sony's successful return (1,802,496 bytes free and largest) than at an earlier
safe snapshot (4,168,704 bytes free). Ownership of that delta is **UNKNOWN**;
attributing all of it to `module_start` would be unsupported. PAF,
`SceSlideHeaparea`, page creation, and resource/animation pressure remain
**HYPOTHESES** and this experiment changes no allocation.

The BSMan CLOSED shim is an **EXPERIMENT — NOT YET HARDWARE VERIFIED**. It does
not establish that BSMan causes the crash and does not emulate physical slider
hardware.

### Structural import and CLOSED semantics

The pre-start kernel handler walks the runtime-loaded `SceLibraryStubTable`
range from `slide_plugin_module.stub_top/stub_size`. Every descriptor length,
library string, NID array, and eight-byte function-stub array must remain in a
loaded module segment. It accepts exactly one library/NID pair:
`sceBSMan` / `0x23E3A9B6`, records its original two words, and rejects an
ambiguous or malformed table without writing code. There is no static runtime
stub address.

The repository's legally pre-existing 6.60 research image was inspected only
to establish semantics; no Sony binary/resource is added or modified. At static
`+0x93AC`, the four-word evidence is `0x3C130000, 0x0C00A856,
0x3C130000, 0x1040000A`: the `jal` targets the static BSMan stub at `+0x2A158`,
its delay slot is followed by `beq v0,zero`. The zero branch skips the nonzero path which sets the observed
boolean state to one. The live installer independently requires one runtime
JAL to the structurally resolved stub and the same `beq v0,zero` consumption,
and logs the four-word caller evidence. Thus `CLOSED=0` is classified
**STRONG INFERENCE**, not a hardware fact: consumption is proven statically to
be boolean, while the UI meaning of the zero path remains an inference from the
non-open path.

Only after all gates and validations succeed, the transaction replaces the
exact import stub with `J zeroCtrlBSManClosedLeaf; NOP`. The replacement word is
computed from the registered helper leaf address and pseudo-direct
reachability is reconstructed before the first write. The leaf is assembly-only:

```asm
lui   t0, %hi(zeroCtrlBSManClosedHits)
lw    t1, %lo(zeroCtrlBSManClosedHits)(t0)
addiu t1, t1, 1
sw    t1, %lo(zeroCtrlBSManClosedHits)(t0)
jr    ra
addu  v0, zero, zero
```

It has no stack or `gp`, calls no import, and performs no I/O, allocation,
memory query, or hardware access. The kernel writes exactly the two replacement
words after validation and applies D-cache writeback/invalidate and I-cache
invalidate to exactly those eight bytes. All failure paths perform zero BSMan
code writes. The exact original and replacement words are runtime addresses and
are therefore recorded in `[bsman] original_words=... replacement_words=...`.
The static unresolved import image contains `0x03E00008,0x00000000`; these are
research-image words, not a promise about the resolved hardware stub. The
runtime replacement is exactly
`0x08000000 | ((leaf_addr >> 2) & 0x03FFFFFF), 0x00000000`.

### Required configuration and expected evidence

```ini
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
PSP1000SlideTriggerMode = DangerousCaller58D4
PSP1000Diagnostics = Enabled
PSP1000SonyStartTrace = Enabled
PSP1000SelectiveSlideTrigger58D4 = Disabled
PSP1000BSManClosedShim = Enabled
```

All gates are mandatory: model 0, devkit `0x06060110`, SlidePlugin opt-in,
diagnostics, exact `DangerousCaller58D4` mode, disabled ClockAndCalendar, and
the independent BSMan opt-in. Expected deferred records are `[bsman]` state,
exact library/NID/stub/value, original/replacement words, the caller fingerprint,
and changed-only `[late] elapsed_us=... bsman_hit_count=N`. No import traversal
or leaf performs file I/O. A safe reset disables every experimental key and
ClockAndCalendar; recovery may disable the VSH plugin. Nothing writes `flash0`.

This commit intentionally does not implement sceVshBridge/impose, OPEN state,
software transitions, PAF changes, allocations, model spoofing, or hardware
emulation.
