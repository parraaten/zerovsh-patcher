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

### First BSMan hardware run: resolved SYSCALL/NOP form

**PROVEN on real PSP-1000 6.61 hardware:** the existing native baseline was
reproduced (`caller_58d4_hit_count=1`, request/probe/pre-start observed), and
Sony natural `module_start` again entered and returned success. The runtime
import traversal uniquely resolved `sceBSMan` / `0x23E3A9B6` at
`0x09CA3358`. From runtime `module_start=0x09C7A198` and static start offset
`+0xF98`, the module text base is `0x09C79200`; the resolved import is therefore
exactly `text+0x2A158`, consistent with the research image. No address
adjustment is justified.

The runtime words were `0x0000054C,0x00000000`: structurally a MIPS
`SYSCALL; NOP` stub. The prior build did not recognize this form, reported
`validation=0 install=0 cache_sync=0`, and performed zero BSMan writes before
its caller scan. Caller evidence consequently remained zero. This is Outcome E
and provides no evidence that BSMan was called or that CLOSED substitution
helps.

The validator now recognizes `SYSCALL; NOP` by masking the SPECIAL opcode and
`0x0C` function bits rather than matching `0x0000054C`. It records
`stub_form=SYSCALL_NOP` and extracts the 20-bit syscall code for deferred
diagnostics. Existing `J/JAL; NOP` and `JR RA; SYSCALL` forms remain accepted.
All unique-caller, strict `beq v0,zero`, helper-range, reachability,
transaction, two-write, and narrow cache-sync checks remain required and
unchanged. `CLOSED=0` remains **STRONG INFERENCE**. This recognition change is
not yet hardware-verified through installation and does not add impose or PAF
behavior.

## Natural activation localization trace

The next read-only behavioral control keeps `PSP1000BSManClosedShim=Disabled`
and adds `PSP1000ActivationTrace=Enabled`. It does not substitute BSMan or any
other Sony result. Runtime import traversal first re-proves the unique
`sceBSMan`/`0x23E3A9B6` stub and its sole direct caller. From that caller it
searches backward only `0x200` bytes for a unique five-word function prologue,
rather than trusting `+0x9304`. On the research image the unique structure is:

```
+0x9304  addiu sp,sp,-32
+0x9308  sw    s1,4(sp)
+0x930C  move  s1,a0
+0x9310  sw    s0,0(sp)
+0x9314  sw    ra,28(sp)
```

This establishes `+0x9304` as a **STRONG STATIC INFERENCE** for the activation
entry; the runtime trace must independently validate it. Static control flow
from that entry reaches internal work at `+0x16EC`, an imported call at
`+0x2A658` with an early zero-result return, and only then the proven BSMan call
at `+0x93AC`. Farther code contains the known impose-shaped dependency, but its
identity/effect remains an **INFERENCE** and is not patched.

After every address, instruction, helper range, unique-caller, and pseudo-direct
check succeeds as one transaction, three tiny helper leaves record only:

* activation-function entry; and
* arrival immediately before the natural BSMan syscall stub; and
* return from the natural BSMan syscall stub, preserving its result.

The entry leaf reproduces the displaced `addiu sp,sp,-32` and `sw s1,4(sp)` and
jumps to `entry+8`. The call-boundary leaf records the original JAL return
address, substitutes a return breadcrumb, and tail-jumps to the untouched
resolved BSMan stub. The return leaf records completion without modifying
`v0`, then resumes at the original Sony return address. The trace does not
replace BSMan. All leaves use fixed BSS state, no `gp`, no
imports, no allocation, no file I/O, and no diagnostic API. Deferred writer
records changed-only counters and masks. It performs no memory query or
partition capture in the temporary 10 ms fast-poll path.
The leaves also update one monotonic volatile stage (`1=activation entry`,
`2=before BSMan`, `3=after BSMan`). After the RCO breadcrumb, the existing
writer temporarily polls this compact state every 10 ms for two seconds, then
returns to 200 ms; it performs file I/O only when evidence changes.

The hardware run should distinguish: no activation entry; activation entry but
no BSMan boundary; arrival at BSMan without return; or return and farther
execution before the last persisted record. Use the
existing exact T9 configuration except set:

```ini
PSP1000BSManClosedShim = Disabled
PSP1000ActivationTrace = Enabled
```

Expected records include `[activation-trace] validation=1 install=1`,
`slide_last_stage`, `slide_activation_entry_count`,
`slide_bsman_call_boundary_count`, and the prefix records described below. Any
structure mismatch fails closed.

### T10 hardware result and activation-prefix tracer

The first T10 PSP-1000 run **proved** that the structurally resolved activation
entry is runtime text `+0x9304`: installation succeeded, stage 1 was persisted,
and the entry count advanced from one to three within 10 ms. No pre-BSMan
boundary was persisted. The old entry leaf could replace a later stage with
stage 1; stage updates are now monotonic, and the cumulative mask cannot lose
evidence across repeated invocations.

Static analysis of the repository's research PRX gives this prefix CFG:

```
+0x9304  entry/prologue
+0x9328  jal +0x16EC              # relocated-global getter
+0x9330  jal +0x2A658             # scePaf NID 0xED83BBCF
+0x9338  beq v0,zero,+0x9354      # direct early epilogue
+0x9340  lbu v1,relocated_global
+0x9348  bne v1,zero,+0x9378      # otherwise epilogue at +0x9350
+0x9378  jal +0x2A1B0             # scePaf NID 0x0FBE2B67
+0x9388  and s2,v1,0x20000000
+0x938C  bne s2,zero,+0x93AC      # direct pre-BSMan path
+0x9390  andi v1,v1,0x0101
+0x9398  beq v1,0x0101,+0x95DC    # alternate state-machine path
+0x93A0  clear two relocated state fields
+0x93AC  jal sceBSMan/0x23E3A9B6
```

`+0x16EC` is a two-instruction global getter and cannot block. The other two
targets are structurally resolved `scePaf` imports; their private semantics and
model dependence remain unknown, but their results feed every early path before
BSMan. The three following branches are therefore meaningful boundaries rather
than evenly spaced probes.

The next build interposes the first `scePaf` JAL to distinguish the preceding
internal getter from the import, and replaces only the three proven branch
sites with call-free leaves. The PAF leaves preserve its natural result and
return address; the branch leaves reproduce displaced branch/delay semantics
and jump to the original basic blocks. Before any code write, installation checks
the complete original pairs `0x10400006/0x8FBF001C`,
`0x1460000B/0x00000000`, and `0x10620090/LUI-v0`, all helper ranges, and all
pseudo-direct targets, and uniquely resolves `scePaf` NID `0xED83BBCF` through
the loaded import descriptors. A mismatch installs none of the activation
trace.

`slide_prefix_path_mask` is cumulative: `0x001` entry/internal getter entered;
`0x002` internal getter returned/first PAF entered; `0x004` first PAF returned;
`0x008` first result nonzero; `0x010` flag test; `0x020` flag nonzero;
`0x040` second-call mask test; `0x080` masked result `0x0101`; `0x100`
pre-BSMan; and `0x200` natural BSMan return. `slide_prefix_counts` separately
counts both outcomes of the result, flag, and `0x0101` comparisons so repeated
invocations cannot make the cumulative mask ambiguous.

Interpretation is direct: `result_zero` selects the first imported call's
epilogue; `result_nonzero` plus `flag_zero` selects the flag epilogue;
`flag_nonzero` with neither a mask outcome nor pre-BSMan localizes inside the
second import; `mask_equal` selects `+0x95DC`; and `mask_unequal` should proceed
through the two state clears to pre-BSMan. This remains temporary research
instrumentation and changes no BSMan, impose, VshBridge, or PAF result.

Phase report: changed `user/stub.S`, `user/main.c`,
`kernel/bsman_closed_shim.h`, `kernel/main.c`, the safety verifier, and the two
Phase 3 test documents. Static source and host-assembler checks pass; the final
PSPDEV build remains the required artifact validation. Hardware has proved only
repeated entry and absence of a persisted pre-BSMan marker, not which prefix
exit is taken. Assumptions still requiring hardware are that the private PAF
NIDs have comparable intent on PSP-1000 and that every relevant invocation is
observed before freeze. Return the unedited T11 log and XMB behavior. The
recommended next phase is to analyze those counters and isolate exactly one
natural dependency; do not add compatibility behavior before that evidence.

### First T11 fail-closed result and corrected comparison proof

The first T11 PSP-1000 build correctly failed closed with activation
`validation=0 install=0`. Hardware reported the expected first two branch
pairs, but the third pair was `0x10620090,0x3C0209E5` rather than the
installer's incorrect `0x10420090` fingerprint. No prefix trace site was
written, so this run provides structural evidence only.

Both the checked-in research PRX and the hardware word decode agree:

```
+0x9390  andi  v1,v1,0x0101
+0x9394  addiu v0,zero,0x0101       # 0x24020101
+0x9398  beq   v1,v0,+0x95DC       # 0x10620090
+0x939C  lui   v0,<relocated-hi>    # hardware 0x3C0209E5, delay slot
```

The rejected `0x10420090` would decode as `beq v0,v0`, an unconditional
branch, and was therefore not a valid description of this CFG. The tracer's
comparison implementation was already semantically correct: it compares the
masked `v1` against `0x0101`. It then loads the validated runtime LUI value into
`v0` before resuming either target, reproducing the original delay-slot effect
which occurs on both taken and untaken paths. The installer now requires the
correct `0x10620090` word while retaining the structural `LUI v0` check rather
than hard-coding its relocation-dependent immediate.

Register liveness was reviewed from each patched instruction through every
natural resume:

| Trace | Natural continuation and scratch-register proof |
| --- | --- |
| first PAF call/return | The unchanged JAL delay slot saves the getter result in `s0`. No `t0/t1/t2/t9` value is an input to the imported call, and none is read from return at `+0x9338` through the result/flag paths before the next call or epilogue. |
| first result branch | The zero target `+0x9354` is restore-only epilogue code. The nonzero target `+0x9340` uses only `v0/v1` before the next imported call. The tracer restores the displaced `lw ra,28(sp)` effect on both paths. |
| relocated flag branch | The zero target `+0x9350` enters the restore-only epilogue. The nonzero target `+0x9378` is the next JAL. Neither continuation reads a tracer scratch register; the original delay slot is NOP. |
| `0x0101` branch | The unequal continuation `+0x939C..+0x93AC` and equal state-machine continuation `+0x95DC..+0x9624` contain no read of `t0/t1/t2/t9` before converging on BSMan. The helper recreates both the displaced `addiu v0,zero,0x0101` comparison value and the relocation-derived `LUI v0` delay-slot result. |

The safety verifier independently checks the research PRX words and decodes
all instructions in those continuation ranges to reject any read of the four
scratch registers. This correction adds no breadcrumb or compatibility
behavior; it only makes the existing T11 transaction match the proven Sony CFG.

### T11 path result and callsite-only PAF boolean control

The corrected T11 run **proved on PSP-1000 6.61** that validation and
installation both succeed and that all four observed activations take exactly
the same prefix path: entry, return from the `+0x16EC` global getter, entry and
return of `scePaf` NID `0xED83BBCF`, natural result zero, then the immediate
Sony epilogue. The cumulative mask was `0x007`; the relocated flag, second PAF
call, BSMan, and later activation work were never observed.

The callsite provides these semantic bounds:

* the activation argument in `a0` is saved to `s1` at `+0x930C`; no argument
  register is prepared between entry and the PAF JAL, so the call is not passed
  the getter result as an ordinary argument;
* the getter result is copied to saved register `s0` by the unchanged PAF JAL
  delay slot, independently of the PAF return value;
* the PAF return in `v0` is consumed immediately and solely by
  `beq v0,zero,+0x9354`; no magnitude, sign, pointer, or error-code operation
  occurs before the return path, proving boolean zero/nonzero consumption at
  this callsite; and
* import-table analysis finds exactly one call to this NID in the 6.60 image.
  The equivalent location and identical boolean branch exist in the checked-in
  6.20 and 6.3x images, although their firmware-specific PAF NIDs are
  `0x521F9DBF` and `0x1ABAA558` respectively.

The successful natural call and return on PSP-1000 prove this is not a missing
import. The private PAF implementation is outside the repository, and neither
its formal name nor whether it tests PAF readiness, object presence, or another
global condition is proven. Its position as an argument-free boolean gate
strongly supports an availability/readiness interpretation, but that remains
an inference. No PSP-versus-Go implementation difference is claimed without a
matching PAF binary or symbol evidence.

The next isolated experiment adds default-disabled
`PSP1000PafPresentCompat`. It is armed only with the existing PSP-1000 6.61
master opt-in, diagnostics, `DangerousCaller58D4`, activation trace, disabled
ClockAndCalendar, and disabled BSMan substitution. At the already validated
SlidePlugin `+0x9330` callsite it still tail-calls the uniquely resolved natural
PAF function. On return it records the unmodified `v0`; if and only if the new
option is enabled and that value is zero, it returns strict boolean `1` to the
original Sony branch. Every natural nonzero value passes through bit-for-bit.
No PAF import stub or other caller is changed.

Expected outcomes for the next hardware run are:

* `paf_ed83bbcf_natural=0`, `zero_to_one_count>0`, followed by `flag_zero`:
  the isolated gate worked and the relocated flag is the next natural exit;
* the same natural/substitution evidence followed by `flag_nonzero` and no mask
  or pre-BSMan evidence: execution entered the second PAF call but did not
  return before persistence;
* `mask_equal` or `mask_unequal`: the second PAF returned and selected the
  corresponding already traced branch;
* pre-BSMan/stage 2 or BSMan-return/stage 3: the natural downstream path reached
  those established boundaries; or
* a natural nonzero result: it remains unchanged and substitution count remains
  zero, making this control behaviorally inert for that invocation.

This is an experiment, not a final compatibility decision. If hardware proves
the zero-to-one conversion is required, the optimized implementation should
retain only this validated callsite-specific post-call conversion and remove
the broad temporary masks, counters, writer polling, and analysis strings.

### T12 result and post-BSMan natural-path tracer

T12 **proved on PSP-1000 hardware** that the callsite conversion is effective:
four natural `scePaf` returns were zero, four zero-to-one conversions occurred,
and all four activations then produced `result_nonzero`, `flag_nonzero`,
`mask_unequal`, and pre-BSMan counts. The cumulative prefix mask was `0x37F`.
Stage 3 and bit `0x200` prove at least one natural BSMan return; they do not
prove four returns because the former evidence had no dedicated return count.

Static analysis gives the following post-BSMan CFG and raw tests:

```
+0x93AC  jal  sceBSMan / 0x23E3A9B6
+0x93B4  beq  v0,zero,+0x93E0       # BSMan result: zero/nonzero
+0x93B8  lbu  v0,0xDCD(s3)          # pre-relocation PRX delay-slot word
+0x93BC  load relocated byte flag
+0x93C4  bne  flag,zero,epilogue
          [zero flag sets two state bytes, then joins +0x93E0]
+0x93E0  beq  v0,zero,+0x957C       # byte from +0x93B8: zero/nonzero
+0x93E4  lui  v0,<relocated-hi>      # delay slot on both sides
+0x93EC  jal  scePaf / 0xFF03BCD5   # a0=0 in delay slot
+0x93F4  bgtz v0,epilogue            # positive exits; zero/negative continue
+0x93FC  jal  scePaf / 0xFF03BCD5   # a0=1 in delay slot
+0x9404  bgtz v0,epilogue            # positive exits; zero/negative continue
+0x940C  lui  a0,0x8000
+0x9410  jal  sceVshBridge / 0x639C3CB3
+0x9414  ori  a0,a0,0x000D           # exact argument 0x8000000D
+0x9418  bne  v0,zero,epilogue       # VshBridge result: zero/nonzero
+0x9420  load virtual target +0x50
+0x9424  jalr target                  # farther object/PAF activation work
```

The `0x8000000D` path is therefore not inferred merely from proximity. Runtime
import traversal structurally requires exactly one `sceVshBridge` NID
`0x639C3CB3`; the caller must construct `a0=0x8000000D`, call that exact stub,
and immediately consume its natural result as zero/nonzero. Its private impose
meaning remains unproven, so the tracer calls it naturally and never changes
its argument or result. Likewise, `scePaf` NID `0xFF03BCD5` is uniquely
resolved and both direct callers must target it with exact `a0=0` and `a0=1`
delay slots.

The new post-BSMan mask and counters are temporary fixed-scalar evidence:

| Mask | Boundary |
| --- | --- |
| `0x001` | natural BSMan returned |
| `0x002` / `0x004` | immediate BSMan-result branch reached / result nonzero |
| `0x008` / `0x010` | state-byte branch reached / byte nonzero |
| `0x020` / `0x040` | first `0xFF03BCD5` call entered / returned |
| `0x080` / `0x100` | second `0xFF03BCD5` call entered / returned |
| `0x200` / `0x400` | `sceVshBridge` call entered / returned |

The checked-in research PRX encodes the `+0x93B8` delay slot as
`0x92620DCD` (`lbu v0,0x0DCD(s3)`). The first T13 hardware attempt failed
closed before any trace write because the relocated PSP-1000 image instead
contained `0x926286FD` (`lbu v0,0x86FD(s3)`). This changes only the relocated
16-bit operand; the opcode and `s3`/`v0` registers are identical. The runtime
validator therefore proves the instruction structurally as an LBU with
`rs=s3` and `rt=v0`, while the research-image verifier retains the separate
exact pre-relocation-word proof.

The replacement jump at `+0x93B4` changes only the original branch word. By
MIPS jump-delay semantics, the untouched runtime LBU at `+0x93B8` still runs
before control reaches the trace leaf and leaves the exact Sony state byte in
`v0`. The leaf tests the natural BSMan result previously saved by the return
trace, never reads or writes `v0`, and selects the unchanged natural targets
`+0x93E0` (BSMan zero) or `+0x93BC` (BSMan nonzero). No reconstructed LBU or
relocation-dependent immediate remains in that helper.

Dedicated counters separately record BSMan returns, both immediate branch
outcomes, both state-byte outcomes, entry/return for each PAF call, and
VshBridge entry/return. Raw BSMan, PAF, and VshBridge results are captured
before any tracer use or deferred serialization. The state-branch leaf derives
its relocated `LUI v0` delay value from the validated runtime word and restores
that exact value; it does not hardcode a relocated operand. Call leaves
retain the original PAF `a0=0/1` and VshBridge `a0=0x8000000D` JAL delay slots,
tail-call the validated natural imports, restore the Sony return addresses, and
preserve every natural result.

The next hardware run keeps `PSP1000PafPresentCompat=Enabled` and
`PSP1000BSManClosedShim=Disabled`. A BSMan zero/nonzero counter selects the
immediate branch. A state-zero count localizes to the `+0x957C` path; state
nonzero proceeds toward the two PAF calls. For each PAF, entry without return
localizes inside the import, while a returned positive raw value explains its
immediate epilogue. Two nonpositive PAF results permit VshBridge entry;
VshBridge entry without return localizes inside it, nonzero return selects its
epilogue, and zero return reaches the farther virtual-call path. No downstream
result is substituted in this experiment.

Phase report: changed the shared helper registration, user assembly/registration,
kernel validation/installation and deferred diagnostics, the safety verifier,
and Phase 3 documentation. The static checks and host Allegrex-compatible
assembly check pass; a PSPDEV build and PSP-1000 run remain required. The
VshBridge call shape and raw tests are proven statically, but private PAF,
VshBridge, and virtual-target semantics remain unresolved. Analyze the T13
natural counters before considering any additional compatibility behavior.

### T13 result and exact BSMan-not-linked compatibility control

The corrected T13 hardware run proved activation-trace validation and
installation (`validation=1`, `install=1`). It recorded three natural BSMan
returns, all nonzero, with the latest raw result `0x8002013A`
(`SCE_KERNEL_ERROR_LIBRARY_NOT_YET_LINKED`). No state-byte, post-PAF, or
VshBridge boundary was reached. The error and immediate nonzero exit are
therefore hardware-proven; the private meaning of BSMan NID `0x23E3A9B6` is
not.

Zero is structurally the expected false/closed path at this callsite. The
unchanged instruction at `+0x93B4` is `beq v0,zero,+0x93E0`: zero joins the
same continuation used after the nonzero-result path clears two state bytes,
while any nonzero value proceeds through a relocated flag and may exit. This
proves boolean zero/nonzero consumption and makes zero the narrowest candidate
for a closed/unavailable result. Calling that value **closed** remains an
inference about private BSMan semantics; the available binaries do not provide
its contract.

The next default-disabled experiment is `PSP1000BSManNotLinkedCompat`. It is
gated by the exact existing PSP-1000/6.61, `PSP1000SlidePlugin`, disabled
`ClockAndCalendar`, diagnostics, `DangerousCaller58D4`, activation-trace, and
disabled broad `PSP1000BSManClosedShim` environment. The trace leaf still
calls the natural resolved BSMan import and stores its untouched result before
any decision. Only when the new option is enabled and that result is exactly
`0x8002013A` does it return zero to the original branch. Every other result,
including every other nonzero error, remains bit-for-bit unchanged. A separate
effective-result scalar and exact-substitution counter make all three facts
directly observable.

The conversion is post-call and callsite-only: it neither replaces the BSMan
import stub nor affects another caller. The original BSMan call runs with its
natural side effects; the existing wrapper restores the saved return address,
and the untouched `+0x93B8` LBU remains the jump delay slot before the
post-BSMan branch tracer. All current state, post-PAF, and VshBridge tracers
remain unchanged. No PAF, VshBridge, impose, OPEN/CLOSE, model, or other
compatibility behavior is added.

For the next hardware run, enable `PSP1000BSManNotLinkedCompat` while retaining
the proven T13 configuration. Require `bs_natural:0x8002013A`, a positive
`bs_exact_sub` count, and `bs_effective:0x00000000`. The existing downstream
counters must identify the next natural boundary. If the natural result differs,
the substitution count must remain zero and the effective result must equal the
natural result. This experiment must be hardware-reviewed before retaining it;
the eventual stable implementation should remove the temporary masks, polling,
and trace-only scalars and retain only compatibility behavior hardware proves
necessary.

### Decrypted PSP-1000 6.61 binary evidence for T14

The following findings come from decrypted ELF PRXs obtained from the tested
PSP-1000 firmware. They are research inputs only; no Sony binary is stored in
this repository.

* **PROVEN BY HARDWARE:** T13 naturally returned `0x8002013A` from
  `sceBSMan/0x23E3A9B6`, and execution did not reach the downstream state, PAF,
  or VshBridge boundaries. The real PSP-1000 installation has no
  `flash0:/kd/bsman.prx`.
* **PROVEN BY DECRYPTED PSP-1000 BINARY:** `scePaf/0xED83BBCF` is a small,
  argument-independent getter for a PAF global value. This supports T12's
  natural zero and successful callsite-only zero-to-one control, but the global
  must not be named "ready", "present", or otherwise interpreted more narrowly
  without further evidence.
* **PROVEN BY DECRYPTED PSP-1000 BINARY:** `scePaf/0xFF03BCD5` exists in the
  PSP-1000 PAF. SlidePlugin calls it with `a0=0` and `a0=1`; its private
  semantic identity remains **HYPOTHESIS / UNKNOWN**.
* **PROVEN BY DECRYPTED PSP-1000 BINARY:** the SlidePlugin CFG independently
  confirms the complete `+0x93AC..+0x9424` sequence already used by the T13/T14
  validators: the BSMan zero/nonzero branch, relocation-dependent state LBU,
  two `0xFF03BCD5` calls and positive-result exits, VshBridge call with
  `a0=0x8000000D`, nonzero-result exit, and the following virtual call.
* **PROVEN BY DECRYPTED PSP-1000 BINARY:** VshBridge NID `0x639C3CB3` checks
  user privilege and forwards its argument to
  `sceImposeGetParam` (`sceImpose_driver/0xDC3BECFF`). Thus the observed Sony
  call reaches `sceImposeGetParam(0x8000000D)` through VshBridge.
* **PROVEN BY DECRYPTED PSP-1000 BINARY:** the PSP-1000 `impose_01g` dispatcher
  handles several private `0x8000000X` parameters but has no implementation for
  `0x8000000D`. **STRONG INFERENCE:** its static unsupported-parameter path will
  return `0x80000107`. This is not hardware-proven until T14 reaches and records
  the VshBridge return.
* **STRONG INFERENCE:** the original ZeroVSH hooks for both BSMan
  `0x23E3A9B6` and VshBridge `0x639C3CB3` identify PSP-Go-specific boundaries.
  They do not justify enabling either broad hook. T14 changes only the exact
  post-call BSMan error and must expose all later behavior naturally.

Accordingly, no VshBridge/Impose conversion, model spoof, OPEN/CLOSE forcing,
or other compatibility behavior belongs in T14. If hardware observes
`0x80000107`, that result is evidence for a later separately reviewed control;
if it observes zero, investigation follows Sony's natural `+0x9420` virtual-call
sequence instead.

### T14 hardware result and T15 state-zero localization

**PROVEN BY HARDWARE:** the corrected T14 trace installed and synchronized
successfully. Across four activations, PAF `0xED83BBCF` naturally returned zero
and the existing compatibility converted all four calls to one. BSMan naturally
returned exact `0x8002013A` four times, the exact-error control substituted all
four, and the effective result was zero. Sony consequently selected its
BSMan-zero continuation. The untouched relocated state byte was naturally zero
on all four observations. The stable mask was `0x00B`; neither post-BSMan PAF
call nor VshBridge was entered.

Natural state zero is not itself identified as a blocker. The current blocker
is **HYPOTHESIS / UNKNOWN** somewhere in Sony's alternate
`+0x957C..+0x95D4` path. The decrypted SlidePlugin independently proves this
path compares `s2` with a word loaded through the relocated LUI, tests a second
relocated word, tests a relocated byte, optionally calls the virtual target at
`0x78(s0)`, and classifies its untouched return around 15, 17, and 18 before
either exiting or rejoining the existing PAF path at `+0x93EC`.

T15 adds transparent fixed-scalar localization only. It replaces the seven
natural branches/call at `+0x9580`, `+0x958C`, `+0x959C`, `+0x95A8`,
`+0x95B8`, `+0x95C0`, and `+0x95CC` only after transactionally validating all
fourteen runtime words. Every original delay-slot instruction remains in
place, including both relocation-dependent LUI/load sequences and the Sony
classification operations. The state-byte branch now saves the natural LBU
value before its branch and leaves the original relocated LUI delay slot
untouched rather than reconstructing its immediate.

The cumulative `state_zero_mask` reports:

| Bit | Natural observation |
| --- | --- |
| `0x0001` / `0x0002` | `+0x957C` entered / `s2 == loaded word` |
| `0x0004` / `0x0008` | relocated word tested / nonzero |
| `0x0010` / `0x0020` | relocated byte tested / nonzero |
| `0x0040` / `0x0080` | virtual call entered / returned |
| `0x0100` / `0x0200` | natural return `<15` / `>=15` |
| `0x0400` / `0x0800` | natural return `<17` / `>=17` |
| `0x1000` / `0x2000` | natural return `==18` / `!=18` |

Dedicated scalars retain the exact comparison operands, relocated global word
and byte, virtual target, and untouched virtual return. Counters record state
path entry, virtual-call entry/return, and rejoin selection. The virtual wrapper
temporarily saves and restores its scratch registers and stack pointer, changes
no arguments, invokes the exact target Sony loaded from `0x78(s0)`, captures
the unmodified return, restores Sony's original return address, and resumes the
unaltered classification logic.

T15 retains both hardware-proven compatibility controls and all existing
post-PAF/VshBridge tracers. It performs no result conversion and adds no PAF,
VshBridge, Impose, model, OPEN/CLOSE, state-byte, or ClockAndCalendar behavior.
The required hardware configuration remains:

```ini
ClockAndCalendar = Disabled
PSP1000ActivationTrace = Enabled
PSP1000PafPresentCompat = Enabled
PSP1000BSManNotLinkedCompat = Enabled
PSP1000BSManClosedShim = Disabled
```

Return the complete log and observations. The next decision must follow the
first natural exit proved by these counters; no additional compatibility shim
is justified before that evidence.

Phase report: changed the shared registration ABI, helper assembly and
registration, kernel transactional installer/deferred scalar diagnostics,
safety verifier, and Phase 3 hardware documentation. The technical finding is
that T14's two narrow controls are hardware-proven to reach the natural
state-zero alternate path; the location and nature of the next exit remain
unknown. T15 assumes only the register liveness and destinations proven by the
decrypted CFG and changes no natural result. Static source and host MIPS
assembly checks pass; a PSPDEV build remains required. Required hardware work
is one recovery-protected T15 run with the stated configuration and a complete,
unedited log. No T15 hardware result is available yet. Unresolved questions are
which early test or virtual-result class exits, whether `+0x93EC` is rejoined,
and whether VshBridge is eventually reached. The recommended next phase is to
review that single run before designing any further compatibility behavior.

### T15 hardware result and T16 virtual-target ownership

**PROVEN BY HARDWARE:** T15 installed and synchronized all activation tracing.
The natural state-zero path was observed four times with comparison operands
`0` and `0xFFFFFFFF`, relocated word and byte values of zero, and the same
runtime-relocated virtual target on that boot. The call and return counters
were both four. Its untouched natural result was exactly 15, so Sony's original
classifiers selected `15 >= 15` followed by `15 < 17` and exited without
rejoining `+0x93EC`. No downstream PAF or VshBridge boundary was reached. The
absolute virtual address is not stable evidence across boots.

The first T16 hardware run reproduced the complete T15 result with target
`0x09C462B0`, but emitted neither ownership nor failure output. The earlier and
newer activation entry and virtual target both shifted by exactly `0x100`,
while their distance remained `0x52A54`; **STRONG INFERENCE:** both addresses
are relocation-dependent. No absolute target is hardcoded.

Source inspection proves that the old writer read the nonzero target in the
same loop iteration that emitted the T15 state record, then called
`sceKernelFindModuleByAddress()`, and emitted output only after that call
returned. Consequently the hardware log cannot distinguish a lookup that did
not return normally from interruption at that exact point. It also collapsed
all normal validation failures into one generic record. T16 therefore did not
produce an actionable result and is not complete.

T16.1 removes that unsuitable address lookup. The deferred writer waits for
both a nonzero captured target and a completed virtual return, obtains a
bounded list of at most 128 loaded module UIDs with `sceKernelGetModuleList()`,
and validates each candidate through `sceKernelFindModuleByUID()`. It selects
an owner only when the target word lies in the candidate text range. It then
separately validates reported segment metadata and the complete ten-word range
in both text and segment before the first instruction read. The writer always
emits one compact outcome after a resolution attempt:

```text
[state-zero-vcall-resolve] attempted=1 target=0x........ owner_found=... text_valid=... segment_valid=... fingerprint_valid=... reason=NAME(...)
```

Stable reasons distinguish module-list failure, no text owner, invalid module
segment metadata, no containing segment, and an incomplete fingerprint range.
A successful capture additionally writes compact owner metadata, the stable
text-relative offset, the containing segment, and ten read-only words:

```text
[state-zero-vcall-owner] target=0x........ module=........ text=0x........ text_size=0x........ offset=0x........ segment=... segment_start=0x........ segment_size=0x........
[state-zero-vcall-code] offset=0x........ words=0x........,...
```

Every failure exits before fingerprint reads and fabricates no module output.
T16.1 adds no thread, RAM/flash scanner, hook, patch, argument capture, result
conversion, or cache operation. In particular, it does not interpret or
change 15, and the T15 virtual wrapper and downstream tracers are unchanged.

Phase report: files changed are `kernel/main.c`, the safety verifier, and this
Phase 3 record. The technical findings are the hardware-proven T15 natural
result and exit, and that the original T16 outcome was unobservable after its
address lookup; the precise API failure mode remains **HYPOTHESIS / UNKNOWN**.
T16.1 assumes only that ModuleMgr's bounded loaded-UID list and LoadCore's UID
lookup expose the metadata already used elsewhere in the project. Static
verification and PSPDEV build status must be recorded. The required hardware
test is one recovery-protected PSP-1000 6.61 run with `ClockAndCalendar` and the
broad BSMan shim disabled, the dangerous 58D4 trigger and diagnostics/activation
trace enabled, and both proven narrow compatibility controls enabled. Do not
load `660_plugins_on_661.prx`. Return the complete unedited log containing the
resolver status, owner/fingerprint if successful, and unchanged T15
result/counts. The owner's module name,
stable offset, function semantics, and whether an additional decrypted PRX is
needed remain unresolved. The recommended next phase is offline correlation
against the matching decrypted PSP-1000 PRX; no new compatibility behavior is
justified before that result.

### T16.1 hardware result and T16.2 module-list correction

**PROVEN BY HARDWARE:** T16.1 reached its resolver after the unchanged natural
virtual method returned 15 four times, but stopped before ownership resolution
with `MODULE_LIST_FAILED(1)`. The status reported `owner_found=0`,
`text_valid=0`, `segment_valid=0`, and `fingerprint_valid=0`. This establishes
only a module-list-path failure; it is not evidence about target ownership.

Source review found that T16.1 passed
`module_count * sizeof(SceUID)` as the first argument to
`sceKernelGetModuleList()`. The repository declaration describes that argument
as the list-buffer capacity, and PSPSDK's established helper converts a byte
buffer size to an entry count before invoking this API. **PROVEN BY SOURCE:**
T16.1 therefore advertised up to four times the fixed array's actual 128-entry
capacity. No hardware conclusion can be drawn about what the erroneous call
did internally.

T16.2 keeps the fixed 128-entry, zero-initialized array, captures the raw
`sceKernelModuleCount()` result, clamps that count to 128, and passes the
clamped entry capacity directly to `sceKernelGetModuleList()`. A negative list
result is failure. The return value is retained for diagnostics but is never
reinterpreted as an entry count. Enumeration is bounded solely by the clamped
capacity; zero initialization makes a module-list race that leaves fewer IDs
conservatively resolve unused entries to no owner rather than exposing
uninitialized UIDs.

The single resolution record now includes the pre-clamp count, requested entry
capacity, and raw list result:

```text
[state-zero-vcall-resolve] attempted=1 target=0x........ module_count=... capacity=... list_result=0x........ owner_found=... text_valid=... segment_valid=... fingerprint_valid=... reason=NAME(...)
```

All later owner/text/segment/fingerprint checks are unchanged and remain
read-only. T16.2 changes no T15 wrapper, Sony value, compatibility behavior,
thread, hook, or patch. Static verification must confirm entry-count capacity,
the 128-entry iteration bound, raw return handling, and validation-before-read.
The required hardware work is one recovery-protected run with the unchanged
configuration and complete log. T16 remains incomplete until that log supplies
either actionable raw enumeration failure values or the owner, stable offset,
and ten-word fingerprint. After success, the recommended next phase remains
offline correlation against the matching decrypted PSP-1000 PRX before any
new compatibility experiment.

### T16.2 hardware result and T16.3 fixed-candidate lookup

**PROVEN BY HARDWARE:** T16.2 reached the resolver with the unchanged natural
virtual result of 15, but `sceKernelModuleCount()` returned `0x8002013A`
(`SCE_KERNEL_ERROR_LIBRARY_NOT_YET_LINKED`). The resolver exited immediately.
The logged `capacity=0` was the untouched value before capacity calculation,
and `list_result=0` was the untouched diagnostic value:
`sceKernelGetModuleList()` was never called. This proves failure of the
T16.2 module-count call on the tested hardware; it proves nothing about the
target's owner. **STRONG INFERENCE:** the static ModuleCount import is not
linked. Direct import-stub words have not been captured, so that interpretation
is not promoted to hardware proof. The earlier address-lookup failure having
the same cause remains **HYPOTHESIS / UNKNOWN**.

T16.3 removes ModuleCount, module-list, UID, and address lookup from this
resolver. It reuses only the `sceKernelFindModuleByName()` path already used by
working PSP-1000 activation instrumentation, against exactly six fixed Sony UI
candidates: `scePaf_Module`, `sceVshCommonGui_Module`, `vsh_module`,
`slide_plugin_module`, `impose_plugin_module`, and
`launcher_plugin_module`. Missing candidates are normal. A non-null result must
be an aligned KSEG0 RAM pointer before any `SceModule2` field is read.

The resolver counts present candidates and text-containing candidates, and
requires exactly one containing range. Zero produces `NO_KNOWN_OWNER`; more
than one produces `AMBIGUOUS_OWNER`; a suspicious returned pointer produces
`INVALID_CANDIDATE_POINTER`. Only the unique owner proceeds through the
existing segment and complete ten-word text/segment bounds checks. The compact
result is now:

```text
[state-zero-vcall-resolve] attempted=1 target=0x........ candidates_found=... containing_candidates=... owner_found=... text_valid=... segment_valid=... fingerprint_valid=... reason=NAME(...)
```

On success the existing owner, stable offset, segment, and ten-word code
records follow. T16.3 performs no general enumeration, arbitrary scan,
target-derived read before full validation, import experiment, compatibility
change, new thread, or hot-path modification. The required hardware test is
one recovery-protected run with the unchanged configuration and complete log.
If no fixed candidate owns the target, the next decision should use that result
rather than expanding the runtime list speculatively. If ownership succeeds,
the next phase is offline correlation with the matching decrypted PSP-1000 ELF;
no new compatibility behavior is justified first.

### T16.3 hardware result and T17 TopMenu state observation

**PROVEN BY HARDWARE:** T16.3 uniquely resolved the natural virtual target to
`vsh_module` text offset `+0x1E2B0`. The loaded text and segment both measured
`0x556C0` bytes, matching the external decrypted PSP-1000 VSHMAIN image, and
the fixed fingerprint validated. The unchanged method returned 15 four times
and Sony did not rejoin `+0x93EC`. T16 owner discovery is complete.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** the function at `+0x1E2B0` consists
of eight instructions. It loads a context through a relocated global slot,
returns 15 when byte `context+0x150` is nonzero, and otherwise returns the word
at `context+0x12C`. Both fields are mutable and initialization writes 15 to
`+0x12C` and zero to `+0x150`. The interface is the `+0x78` method of the
pointer SlidePlugin obtains for `topmenu_plugin`; its official semantic name
remains unknown. **STRONG INFERENCE:** 15 is an internal/default TopMenu state,
not evidence of another missing PSP-1000 service.

T17 remains observational. Only after T16 validates the unique VSH owner,
exact `+0x1E2B0` offset, LUI/LW shape, and six fixed non-relocated instructions
does it reconstruct the global slot using a signed 16-bit LW displacement. A
fresh, plausibility-checked `vsh_module` metadata lookup must place the complete
slot word in one of at most four segments before it is read. The resulting
context must be aligned and contain the complete range through `+0x153` inside
a partition range captured before Sony module start. Only then are words
`+0x128`, `+0x12C`, and byte `+0x150` read.

The existing deferred thread captures the first validated state and refreshes
it only when the existing virtual-return counter changes. It retains the last
state and increments one transition counter when the context or any requested
field changes; it does not print on every poll. The compact first record names
the natural source selected by the proven function, and one final record holds
first/last values and the transition count. T17 adds no thread, code patch,
function call, return conversion, context write, or `+0x6F84` behavior.

The required hardware test is one recovery-protected run with the unchanged
configuration and complete log. The key result is whether nonzero `field_150`
selects `FORCED_15`, or zero selects `FIELD_12C` whose value is itself 15.
No compatibility change is justified in T17. After hardware identifies that
branch, inspect the decrypted VSH code responsible for the relevant field's
natural transitions before designing any separate control.

### T17 hardware result and T18 natural field_12C writer trace

**PROVEN BY HARDWARE:** the validated deferred T17 sample read
`field_128=0`, `field_12C=15`, and `field_150=0` from context `0x08AB8970`.
The simultaneous natural virtual result remained 15. Combined with the
decrypted getter, this is **STRONG INFERENCE**, not exact per-call proof, that
the observed result came from `field_12C` rather than the nonzero-`field_150`
fallback. The missing final record means T17 established no temporal transition
count.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** initialization writes the same
`0/15/0` tuple, while the natural store at `vsh_module+0x1DEAC` can replace
`field_12C` with the incoming state retained in `s3`. T18 asks only whether
that writer executes and what it naturally stores.

T18 transactionally validates the `j +0x1D8C4` at `+0x1DEA8` and exact
`0xAC53012C` (`sw s3,0x12C(v0)`) delay slot. Only after every VSH/helper range,
jump-target, instruction, and J-region check passes does it replace the jump
with a jump to a bounded helper leaf while rewriting the original store word
unchanged in the replacement jump's delay slot. The leaf runs after Sony's
natural store, records only hit count, first/last natural `s3`, value-change
count, and natural `v0` context, restores its scratch registers and stack, and
jumps to the original `+0x1D8C4` continuation. It never changes `s3`, `v0`,
the stored field, or the path condition.

The existing deferred writer emits one compact final record:

```text
[topmenu-field12c-write] validation=... install=... cache_sync=... hits=... first=0x........ last=0x........ changes=... context=0x........
```

Files changed are the shared registration ABI, user helper assembly and
registration, kernel transactional installer/state and deferred diagnostics,
safety verifier, and this report. Static verification and the PSPDEV build must
pass. Required hardware work is one recovery-protected PSP-1000 run with the
unchanged configuration and complete log. No T18 hardware result exists yet.
Whether this writer executes, what value it stores, and whether any other
writer changes `field_12C` remain unresolved. The recommended next phase is to
interpret that single run and inspect the upstream natural branch if hits are
zero; do not change `+0x6F84` or add compatibility behavior in T18.


### T18 hardware observation and T18.1 observability

The latest real PSP-1000 run again reached the validated state-zero virtual
call path. **PROVEN BY HARDWARE:** model 0 / devkit 0x06060110 loaded and
started SlidePlugin, requested its RCO, observed the callsite-only PAF
zero-to-one compatibility and exact BSMan not-linked substitution, resolved the
virtual target to `vsh_module+0x1E2B0`, and observed
`field_128=0`, `field_12C=15`, and `field_150=0`. Four natural virtual
returns were 15 and Sony did not reach the downstream PAF/VshBridge path.

The log stopped after the approximately 8.51-second live activation records and
contained neither the deferred `[final]` record nor the existing
`[topmenu-field12c-write]` / `[topmenu-state-final]` records. This does **not**
prove that the T18 writer had zero hits. The T18 scalars existed but were only
reported after the observation loop and final partition capture.

T18.1 changes diagnostics only. The existing deferred writer now emits one
`[topmenu-field12c-write-install]` record after it first observes that the T18
installation attempt has completed. At the same one-shot TopMenu observation
that emits `[topmenu-state]`, it immediately emits
`[topmenu-field12c-write-live]` from the already-existing five helper scalars.
The natural VSH patch site, original `0xAC53012C` delay-slot store, helper leaf,
and all compatibility behavior remain unchanged.

After the observation loop, T18.1 emits
`[checkpoint] slide_observation_window_complete` before the existing final
checkpoint flush, then `[checkpoint] final_partition_capture_begin`
immediately before the final partition capture and
`[checkpoint] final_partition_capture_end` immediately after it returns. The
interpretation is intentionally precise:

- no `slide_observation_window_complete`: the diagnostic writer did not prove
  that it exited the observation loop;
- `slide_observation_window_complete` but no
  `final_partition_capture_begin`: progression stopped in the existing final
  slide-checkpoint flush or before the capture-begin record could be emitted;
- capture begin without capture end: the final partition-capture call is the
  observed blocking/failing boundary;
- capture end present: finalization progressed beyond partition capture and any
  later missing output must be localized separately.

The observation window remains 12,000,000 microseconds. T18.1 adds no new
thread, no per-hit logging, no new polling path, no Sony state write, and no
compatibility conversion.
## T19: natural case-14 dispatch observation

### Evidence entering T19

**PROVEN BY HARDWARE:** T18 installed successfully, the known
`vsh_module+0x1DEAC` writer had zero hits before the TopMenu observation, and
the observed `field_12C` value remained 15. This does not show that Sony wrote
15 at that site.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** `vsh_module+0x1D7A4` dispatches
values 0 through 21. Its validated jump table is at `+0x4FDA0`, entry 14 begins
at `+0x1DE18`, and the dispatcher preserves its argument in `s3`. If that
natural case reaches `+0x1DEAC`, its unchanged delay-slot store writes the
natural value 14 to `field_12C`. Neither 14 nor 15 is assigned an invented
Sony state name.

**HYPOTHESIS / UNKNOWN:** It is unknown whether activation naturally dispatches
case 14, which caller would do so, why the transition is absent if no dispatch
occurs, or whether another consumer of `+0x6F84` participates upstream.

### Instrumentation and safety boundary

T19 is evidence-only. On model 0 and devkit `0x06060110`, it transactionally
validates the dispatcher fingerprint, derives and checks the jump-table address,
checks all VSH/helper ranges, and confirms that aligned entry 14 naturally
contains `vsh_module+0x1DE18`. Only after every check succeeds does it replace
that one data word with a transparent helper address and synchronize those four
data bytes. A mismatch leaves `validation=0 install=0` and performs no VSH
write. T18's `+0x1DEA8`/`+0x1DEAC` trace remains unchanged.

The leaf helper makes no calls, performs no I/O or allocation, creates no
thread, preserves `s3`, `$ra`, and its temporary registers, records only
`case14_hits`, `first_ra`, `last_ra`, and `ra_changes`, then jumps to the
original `+0x1DE18` entry without skipping or emulating any Sony instruction.
The caller `$ra` is valid here because the dispatcher reaches its case with
`jr` and has made no intervening call.

The existing diagnostic writer emits the once-only
`[topmenu-case14-install]` record and emits `[topmenu-case14-live]` immediately
after the T18.1 live writer record at the working TopMenu boundary. The broken
12-second final block is neither required nor changed. Broad `+0x6F84`, its
`+0x13F6C` and `+0x14020` consumers, forcing case 14, and any compatibility
behavior remain disabled.

### Required hardware test and interpretation

Build and deploy through the existing Memory Stick recovery workflow without
writing `flash0:` and preserve the specified configuration. Return the complete
log and normal-use stability observations. Required records are
`[topmenu-case14-install]`, `[topmenu-state]`,
`[topmenu-field12c-write-live]`, and `[topmenu-case14-live]`.

* With valid installations and both hit counts zero, **PROVEN BY HARDWARE**
  would be limited to no natural case-14 dispatch before that boundary; research
  should move upstream without forcing the field or case.
* Case-14 hits with zero writer hits would prove entry without reaching the
  known writer and identify a caller through `$ra`; the next experiment should
  localize the existing case path.
* Hits in both traces require correlation of caller RA, natural `s3`, writer
  context, TopMenu context, ordering, and the later field value before any
  conclusion or compatibility work.
* Failed T19 validation invalidates all hit-counter interpretation and must be
  investigated first.

### T19 hardware result and T20 pre-dispatch entry trace

**PROVEN BY HARDWARE:** T19 installed with `validation=1 install=1
cache_sync=1`, but its working TopMenu-boundary record reported zero case-14
hits and zero caller-RA evidence. Jump-table case 14 was therefore not reached
during the observed post-installation interval. T19 remains installed and
unchanged for the next control.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** Before dispatch, the function at
`vsh_module+0x1D7A4` reads a byte at offset `+0x19D` in the active context and
branches to the common `+0x1D8C4` epilogue when that byte is nonzero. Its exact
official meaning is **HYPOTHESIS / UNKNOWN**. An incoming value of 14 passes
the later unsigned `<22` range gate. The upper jump-table cases 14 through 21
begin at `+0x1DE18`, `+0x1DF04`, `+0x1DFA4`, `+0x1E05C`, `+0x1E080`,
`+0x1E0F0`, `+0x1E174`, and `+0x1E1E8`, respectively, and their natural paths
converge on the common `+0x1DEA8/+0x1DEAC` tail. Consequently, that writer is
not exclusive to case 14.

T20 asks only whether the dispatcher is entered after instrumentation and
whether any entry carries the unchanged incoming `a0=14` before the `+0x19D`
gate. It does not inspect individual callers or change the context.

The T20 installer is restricted to model 0, devkit `0x06060110`, and exact VSH
text size `0x556C0`. It validates the dispatcher and pre-gate fingerprint,
including original entry words `0x27BDFFC0` (`addiu sp,sp,-0x40`) and
`0xAFB20018` (`sw s2,0x18(sp)`), every VSH/helper/scalar range, the natural
`+0x1D7AC` resume, and pseudo-direct jump reachability before any VSH write.
It then replaces only the first two entry words with a helper jump and NOP and
synchronizes exactly those eight code bytes.

The transparent leaf records bounded scalars only: total dispatcher entries,
number of incoming case-14 requests, first and last case-14 caller `$ra`, and
RA-change count. It modifies neither `a0` nor `$ra`, preserves all scratch
registers, reproduces both displaced instructions exactly, and resumes at
`+0x1D7AC`. It makes no calls, performs no I/O or allocation, creates no thread,
and reads or writes no Sony context field.

The existing diagnostic writer emits `[topmenu-dispatch-entry-install]` once
and `[topmenu-dispatch-entry-live]` immediately after the retained T19 live
record. Interpretation is limited to the requested distinctions: zero total
hits moves research to callers/scheduling; total hits without case-14 requests
moves research to constant-14 caller prerequisites; case-14 requests without
T19 hits directs the next read-only investigation to the earlier `+0x19D` gate;
case-14 and T19 hits without T18 hits directs later localization inside the
natural case path. Invalid installation invalidates every T20 counter.

Required hardware output is the existing TopMenu state, T18.1 live record,
T19 live record, plus:

```text
[topmenu-dispatch-entry-install] validation=... install=... cache_sync=...
[topmenu-dispatch-entry-live] validation=... install=... cache_sync=... hits=... case14_requests=... first_ra=0x........ last_ra=0x........ ra_changes=...
```

Broad `+0x6F84`, `+0x13F6C`, `+0x14020`, field `+0x19D`, `field_12C`, and all
compatibility behavior remain unchanged. The deferred 12-second finalization
problem is explicitly outside T20.

### T20 hardware result and T21 early installation

**PROVEN BY HARDWARE:** T20 installed successfully, but the live TopMenu
record contained zero dispatcher hits and zero incoming case-14 requests.
Thus `vsh_module+0x1D7A4` did not execute between the former SlidePlugin-time
installation and that boundary. This result does not address earlier VSH
initialization, and it does not make the `+0x19D` gate the current boundary.

T21 reuses the unchanged T20 helper and patch. At the end of the existing
`zeroCtrlRecordVshSlideTarget` path, after original VSH captures/scans and the
selected `+0x58D4` setup, it attempts the same dispatcher-entry installation
before returning to natural VSH startup. T18 and T19 remain installed only in
the later SlidePlugin path.

The installer is explicitly idempotent: if the early installation succeeded,
the later call returns before validating patched instructions, rewriting the
resume scalar, or clearing any of the five counters. On entry to the later
SlidePlugin instrumentation path, kernel state snapshots those five counters
before T18, T19, or the idempotent T20 call. No helper, patch site, polling,
thread, allocation, I/O path, Sony state, or compatibility behavior is added.

The existing deferred writer adds:

```text
[topmenu-dispatch-entry-early-install] attempted=... validation=... install=... cache_sync=...
[topmenu-dispatch-entry-pre-slide] hits=... case14_requests=... first_ra=0x........ last_ra=0x........ ra_changes=...
```

The unchanged T20 live record remains the total since early installation.
Interpretation is limited to timing: zero pre-slide and live hits moves research
upstream; pre-slide hits without case-14 requests motivates caller-condition
analysis; early case-14 requests require a later experiment moving existing
T19/T18 observation earlier; and zero pre-slide with nonzero live hits localizes
activity after the snapshot. Invalid early installation invalidates the early
counters. No compatibility conclusion follows from T21 alone.

### T21 hardware result and T22 natural `+0x6F84` consumers

**PROVEN BY HARDWARE:** Early T20 installed successfully, while both its
pre-SlidePlugin and live snapshots reported zero dispatcher entries and zero
case-14 requests. Thus `vsh_module+0x1D7A4` did not execute from the early
installation through the observed activation interval. The timing ambiguity is
resolved, and the `+0x19D` gate is not yet implicated.

T19's later validation failure is an instrumentation interaction, not Sony
behavior: T20 has already replaced dispatcher words which T19 expects original.
T22 neither uses nor changes T19.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** `vsh_module+0x6F84` returns true
exactly when its shared global is 4, 5, 7, or 9. At `+0x13F6C`, that result
selects `a0=0x828` when true and `a0=0x28` when false. At `+0x14020`, the JAL
delay slot at `+0x14024` consumes the preceding `+0x6F44` result; the `+0x6F84`
result is consumed at `+0x14030` and controls the later `0x40` candidate, not
`0x20`.

T22 replaces only the JAL words at `+0x13F6C` and `+0x14020` with calls to two
dedicated transparent counters. Both natural targets must be `+0x6F84`; the
exact delay slots (`NOP` and `movn s0,v1,v0`) remain untouched. Each wrapper
restores its scratch registers and stack, leaves `$ra` and `$v0` untouched, and
tail-jumps to Sony's natural predicate, which returns directly to the original
`PC+8`. No result or bitmask choice is transformed.

Installation follows all original VSH scans and selected `+0x58D4` setup and
precedes retained early T20 and natural VSH startup. The existing decoded
shared-global address must be valid in a VSH segment; it is read once at early
installation and once at the pre-SlidePlugin snapshot and is never written.

```text
[vsh-6f84-consumers-install] consumer_13f6c_validation=... consumer_13f6c_install=... consumer_13f6c_cache_sync=... consumer_14020_validation=... consumer_14020_install=... consumer_14020_cache_sync=... shared_global_early_valid=... shared_global_early=0x........
[vsh-6f84-consumers-pre-slide] caller_13f6c_hits=... caller_14020_hits=... shared_global_valid=... shared_global=0x........
```

Nonzero counts prove only natural execution. A validated observed global plus
the decrypted predicate establishes the natural result for that snapshot but
does not justify forcing either consumer. A changing global requires transition
localization; zero counts move research to the enclosing initializer. T22 adds
no compatibility and leaves the existing `+0x58D4` substitution unchanged.

### T22.2 validation-failure diagnostics

**PROVEN BY HARDWARE:** The first T22 run reported validation, installation,
cache synchronization, and early shared-global validity all as zero. The hit
counters from that run are not interpretable. T22.2 does not loosen or bypass
the installer; it records which existing guard rejected the transaction.

The bounded guard state distinguishes model/devkit/module/text failures,
shared-global decode and segment validation, predicate/global/helper ranges,
the predicate fingerprint, and every range/opcode/target/delay/pseudo-direct
condition at each callsite. `NONE` is assigned only after all guards pass.
Failure still occurs before either VSH callsite write, leaving both consumers
uninstalled.

T22.2 also captures the VSH text address and size, bounded `nsegment` metadata
(at most four segment address/size pairs), the decoded shared-global address,
the 16 predicate words, both callsite/delay pairs and decoded targets, and the
installer-side helper/scalar range results. These are reads into fixed kernel
diagnostic state; neither Sony data nor the wrappers are changed.

The existing deferred writer retains both T22 records and adds:

```text
[vsh-6f84-consumers-guard] reason=... decode_valid=... segment_valid=... shared_global_addr=0x........ vsh_text=0x........ text_size=0x........ nsegment=...
[vsh-6f84-segment] index=... addr=0x........ size=0x........
[vsh-6f84-callsite] offset=... word=0x........ delay=0x........ decoded_target=0x........
[vsh-6f84-predicate] validation=... first_bad_index=... actual=0x........ expected=0x........
[vsh-6f84-helper] target_scalar=... leaf_13f6c=... counter_13f6c=... leaf_14020=... counter_14020=...
```

The required hardware test is one recovery-protected run with the unchanged
configuration and complete log. The failing reason and captured metadata must
be reviewed before any validator change. The VSH BSS/segment-size relationship,
the actual failing guard, and whether T22 can install remain **HYPOTHESIS /
UNKNOWN**. The recommended next phase is evidence review only.

### T22.3 relocation-aware predicate validation

**PROVEN BY HARDWARE:** T22.2 failed only at predicate word index 1. The loaded
word was `0x8C44EEE0`, and together with the runtime `lui v0,0x09C8` it resolves
to `0x09C7EEE0`, exactly the separately decoded shared-global address. That
address lies within hardware-reported VSH segment 1 (`0x09C7D8C0` through
`0x09C84EA0`), so the prior BSS/segment-range hypothesis is false. Both runtime
consumer JALs decoded to natural `vsh_module+0x6F84`, with their expected delay
slots intact.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** The pre-relocation word at `+0x6F88`
is `0x8C441620`. Its `0x1620` immediate is not an invariant after relocation.

T22.3 changes only that validator rule. Word 0 remains a structural
`LUI v0,imm` check. Word 1 must structurally match `LW a0,imm(v0)`, and the
actual HI16 plus signed LO16 are decoded with the same pure helper used by the
existing shared-global derivation. The resulting runtime address must equal the
already decoded, segment-validated, range-valid shared-global address. All
remaining predicate words, the natural jump target, both callsites, both delay
slots, transactional ordering, wrappers, and diagnostics remain unchanged.
The bounded predicate record now also reports that reconstructed address so a
structurally valid load with the wrong effective target is unambiguous.

### T22.3 hardware result and T23 natural return capture

**PROVEN BY HARDWARE:** Both T22 consumers installed and each executed once
before SlidePlugin. The independently decoded shared global was zero at both
bounded snapshots, but T22 did not exclude a transient value or directly
capture either natural predicate result.

T23 changes only the two existing evidence wrappers. Each now uses a private
16-byte frame containing `t0`, `t1`, `t2`, and the original caller `$ra`.
After incrementing its existing counter, it loads the already validated Sony
`+0x6F84` target and performs the single intentional `jalr`. On return it stores
natural `$v0` verbatim to its dedicated result scalar, restores every saved
register and the stack, and returns through the original `$ra`. It performs no
comparison, normalization, arithmetic, or branch on `$v0`.

Registration range-validates both new result scalars. The T22 transaction
initializes each to `0xFFFFFFFF` before either callsite commit, and failure of
either range check prevents both patches. The same JAL words remain the only
VSH writes and both original delay slots remain untouched.

At the existing pre-SlidePlugin boundary the deferred writer adds:

```text
[vsh-6f84-consumers-natural] caller_13f6c_hits=... caller_13f6c_result=0x........ caller_14020_hits=... caller_14020_result=0x........
```

Results of zero at both one-hit consumers would be **PROVEN BY HARDWARE**
evidence that both natural consumers returned false in this startup. Combined
with the decrypted binary, that would establish the natural `0x28` selection
at `+0x13F6C` and absence of the later `0x40` contribution at `+0x14020`, but
would not itself justify compatibility. No consumer or predicate is forced.

### T23 hardware result and T24 selective `+0x14020` compatibility

**PROVEN BY HARDWARE:** T23 installed both transactional consumer wrappers,
each natural consumer executed once, and both `+0x13F6C` and `+0x14020`
observed an untouched natural `+0x6F84` result of zero.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** false at `+0x13F6C` selects argument
`0x28` rather than `0x828`. False at `+0x14020` omits candidate mask bit
`0x40`; Sony's unchanged `movn` at `+0x14030` contributes that bit when the
effective result is nonzero. The surrounding mask is passed to the
`scePaf/0xF48A9040` import. No unofficial semantic name is assigned to that
NID.

T24 adds the default-disabled `PSP1000Consumer14020Compat` control. It is armed
only on PSP-1000 firmware 6.61 with the SlidePlugin master opt-in, disabled
ClockAndCalendar, enabled diagnostics, and exact `DangerousCaller58D4` trigger
mode. It does not select `ZERO_TRIGGER_14020` or use the legacy combined direct
trigger.

The `+0x13F6C` wrapper remains the pure T23 evidence wrapper: it calls Sony
once, stores natural `$v0`, and returns it unchanged. The existing `+0x14020`
wrapper still calls Sony once and stores natural `$v0` first. Only when its
dedicated compatibility scalar is one and natural `$v0` is exactly zero does
it substitute effective `$v0=1` and increment its dedicated substitution
counter. Arbitrary nonzero values are returned exactly. The effective result
is stored after that decision and returned to Sony, which consumes it through
the original `+0x14030` instruction. The `+0x14024` delay slot remains
`0x0062800B` and is not patched.

All three new helper scalars are fixed storage, registered, range-validated,
and initialized before either existing consumer JAL commit. Any validation
failure prevents both callsite writes, preserving the T22 all-or-none
transaction. No thread, allocation, polling, helper I/O, Sony global write,
global predicate force, or additional VSH code write is introduced. Deferred
pre-SlidePlugin diagnostics add:

```text
[vsh-6f84-14020-compat] enabled=1 hits=1 natural=0x00000000 effective=0x00000001 substitutions=1
```

**HYPOTHESIS / UNKNOWN:** Whether adding only the `+0x14020` candidate `0x40`
capability is sufficient to advance Sony SlidePlugin state on PSP-1000. The
hardware run must compare every existing downstream T23 record, especially
`field_12C`, state-zero, dispatcher, and live topmenu state. Execution of the
substitution alone is not success. If downstream behavior is unchanged,
`+0x14020` alone is insufficient; if the XMB freezes or crashes, the isolated
substitution is unsafe. Neither outcome authorizes a `+0x13F6C` compatibility.

### T24 hardware result and T25 selective `+0x13F6C` compatibility

**PROVEN BY HARDWARE — T24:** the isolated `+0x14020` control observed natural
zero, returned effective one, and recorded one substitution. Nevertheless,
Sony's downstream state remained `field_12C=15`, the state-zero virtual call
returned 15, and both the field writer and dispatcher recorded zero hits.
Selective `+0x14020` compatibility is therefore insufficient by itself on the
tested PSP-1000; execution of the substitution was not a compatibility success.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** the natural false result at
`vsh_module+0x13F6C` selects argument `0x28`, while an effective true result
selects `0x828` before the call through the `sceVshBridge/0xC949966C` import at
`+0x3FAF8`. No unofficial semantic name is assigned to that NID.

T25 adds default-disabled `PSP1000Consumer13F6CCompat`. Under the same PSP-1000
6.61, SlidePlugin opt-in, disabled ClockAndCalendar, diagnostics, and exact
`DangerousCaller58D4` gates, its wrapper records natural `$v0` and changes only
exact zero to effective one. It records effective `$v0` and a dedicated
substitution count, while arbitrary nonzero values remain exact. Sony's
unchanged branch at `+0x13F74` selects the argument; neither the branch nor its
arguments are patched.

The new fixed helper scalars are registered and range-validated before the
existing all-or-none two-consumer commit. The `+0x13F70` NOP delay slot remains
untouched. T24's `+0x14020` implementation remains available and unchanged, but
must be configured Disabled during the isolated T25 run. Deferred diagnostics
add:

```text
[vsh-6f84-13f6c-compat] enabled=1 hits=1 natural=0x00000000 effective=0x00000001 substitutions=1
[vsh-6f84-14020-compat] enabled=0 hits=1 natural=0x00000000 effective=0x00000000 substitutions=0
```

**HYPOTHESIS / UNKNOWN:** Whether isolated `+0x13F6C` false-to-true is
sufficient to advance Sony SlidePlugin state on PSP-1000. Substitution alone is
not success; every downstream T24 state, PAF/VshBridge, field-writer, and
dispatcher record must be compared before considering any later combined test.

### T26 hardware result and T27 capability-mask diagnostics

**PROVEN BY HARDWARE — T26:** the dangerous `+0x58D4` consumer executed once,
and both selective consumers observed natural zero and returned effective one
with one substitution. Thus all three known direct `+0x6F84` consumers were
effectively true. Sony nevertheless retained `field_12C=15`, a state-zero
virtual result of 15, zero field-writer hits, and zero dispatcher hits. Making
all known direct `+0x6F84` consumers true is insufficient on the tested
PSP-1000; T27 adds no further compatibility.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** the mask chain at `+0x14000` uses
results from `+0x6F44`, `+0x6F84`, `+0x6FC4`, and `+0x7004` to contribute
candidate bits `0x20`, `0x40`, `0x80`, and `0x100`, respectively. The final
unchanged `$a0` mask is passed by the unique direct call at `+0x1404C` to the
`scePaf/0xF48A9040` import. No unofficial semantic name is assigned to that
NID.

T27 transactionally replaces only the four JAL words at `+0x14014`,
`+0x1402C`, `+0x14038`, and `+0x1404C` after validating model, firmware, VSH
text size, JAL forms and targets, exact delay words, helper/scalar ranges, and
pseudodirect reachability. The predicate wrappers call their natural targets
once, record untouched results, and return those results exactly. The mask
wrapper records incoming `$a0` and tail-transfers to the original PAF import
with the original JAL `$ra`; it does not inspect or transform the return value.
The delay slots at `+0x14018`, `+0x14030`, `+0x1403C`, and `+0x14050` remain
untouched. No thread, allocation, I/O, data write, or compatibility is added.

**HYPOTHESIS / UNKNOWN — T27:** whether adjacent natural hardware-capability
predicates feeding the PAF initialization mask expose the missing PSP-1000
prerequisite. Direct call-time results and the exact mask must be reviewed
before considering any later controlled experiment.

### T27 natural control and T28 exact PAF-mask compatibility

**PROVEN BY HARDWARE:** with both consumer compatibilities disabled, the three
adjacent predicates at `+0x6F44`, `+0x6FC4`, and `+0x7004` each returned zero,
and the exact natural capability mask passed at `+0x1404C` was `0x00000002`.
The earlier T27 run with only the existing effective `+0x6F84` contribution
produced `0x00000042`, confirming candidate bit `0x40` reaches this mask.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** the complete predicate chain maps its
nine results to bits `0x001` through `0x100`, and shared selector value 4 yields
mask `0x000001E9`. The selector has no established official model semantic, and
`0x1E9` is not hardware-proven to be a PSP Go mask.

T28 extends the existing `+0x1404C` tail wrapper only. It records untouched
incoming `$a0`, and when its dedicated default-disabled mode is enabled changes
only exact natural `0x00000002` to effective `0x000001E9`, incrementing a fixed
substitution counter. Every other mask is preserved exactly. The wrapper stores
the effective value and tail-transfers to the already validated
`scePaf/0xF48A9040` stub without a frame, nested call, `$ra` change, or `$v0`
use. The existing four-callsite T27 transaction remains the only owner and
still leaves the `+0x14050` delay word untouched.

**HYPOTHESIS / UNKNOWN:** whether presenting `0x000001E9` to PAF reproduces a
missing prerequisite needed for Sony SlidePlugin state progression on
PSP-1000. T28 must disable both separate consumer compatibilities and compare
the first changed downstream boundary; substitution alone is not success.

### T29 hardware result and T30 state-zero return control

**PROVEN BY HARDWARE — T29:** isolated `+0x13F6C` compatibility and exact PAF
mask `0x00000002` to `0x000001E9` substitution both executed, while the
`+0x14020` control remained disabled. Sony still reported `field_12C=15`, a
state-zero virtual-call result of 15, zero field-writer hits, zero dispatcher
hits, and zero case14 requests. The combined `0x828` path and `0x1E9` mask are
therefore insufficient on the tested PSP-1000.

**PROVEN BY DECRYPTED PSP-1000 BINARY:** ignoring stack accesses, the relevant
VSH context field is initialized to 15 at `+0x1FC98`, written at runtime only by
the dispatcher at `+0x1DEAC`, and read at `+0x1E2C4`. Dispatcher case 14 reaches
that writer with the original entry value and naturally stores 14. Hardware has
not reached the dispatcher or writer.

T30 extends only the existing state-zero virtual-return owner. It retains the
untouched natural result, and under a new default-disabled exact gate converts
only natural 15 to effective 14, counts substitutions, stores the effective
result, and returns through the already saved Sony `$ra`. Every other result is
preserved exactly. It does not invoke the dispatcher, write the Sony context,
modify a selector/global, add a callsite, or add any PAF, predicate, or
VshBridge compatibility.

**HYPOTHESIS / UNKNOWN:** whether effective state value 14 alone is sufficient
to leave or alter the stuck state-zero path. A changed boundary would identify
15 as an immediate blocker but would not justify retaining the substitution;
an unchanged path would show that case14 side effects or another prerequisite
are still required.

### T30.1 cross-instrumentation correction

**PROVEN BY DECRYPTED PSP-1000 BINARY + SOURCE:** the initial T30 return wrapper
correctly retained natural 15 and presented effective 14 in `$v0`, but the
existing T15 Class15/Class17 branch owners reloaded the untouched natural-result
scalar. They would therefore reconstruct the `<15` and `<17` decisions for 15
while Sony's intervening instructions operated on 14, neutralizing the isolated
experiment.

T30.1 changes only the classification-input scalar used by the existing
Class15 and Class17 wrappers. They now load
`zeroCtrlStateZero15To14EffectiveResult`; the natural
`zeroCtrlStateZeroVCallResult` slot remains unchanged for diagnostics. When the
control is disabled or the natural result is not 15, effective equals natural
and routing remains transparent. Class18 remains unchanged and continues to
compare Sony's `$v1`, which already received the effective return value.

No hardware conclusion is assigned to the pre-correction T30 implementation.
No patch owner, callsite, compatibility rule, dispatcher invocation, or Sony
context/global write is added by this correction.

### T30.1 hardware result and T31 exact impose-return control

**PROVEN BY HARDWARE — T30.1:** natural state result 15 became effective 14 on
four returns. The state-zero mask changed from `0x06D5` to `0x01D5`, and rejoin
increased from zero to four. Natural state value 15 was therefore an immediate
blocker, and effective 14 exposes the Class15-true/rejoin path.

The newly reached sequence completed both instrumented PAF calls with zero and
then called `sceVshBridge/0x639C3CB3` with argument `0x8000000D`, returning
natural `0x80000107`. Public NID data identifies the function as
`vshImposeGetParam`; no official semantic name is assigned to private parameter
`0x8000000D`. Sony's immediate nonzero branch returns to the retry path.

T31 extends only the existing post-VshBridge call/return owners. The call owner
records untouched `$a0`. The return owner records natural `$v0` and, only when
T30 is enabled, activation tracing is enabled, the argument is exactly
`0x8000000D`, and natural result is exactly `0x80000107`, presents effective
zero and increments its fixed counter. All other argument/result pairs are
preserved exactly, and the original saved Sony `$ra` restoration remains.

**HYPOTHESIS / UNKNOWN:** whether zero is the result expected on the hardware
profile for which Sony designed this private impose-parameter path, and whether
presenting it advances beyond the `activation+0x114` retry branch. No dispatcher
invocation, Sony context/global write, new callsite, or additional compatibility
is part of T31.
