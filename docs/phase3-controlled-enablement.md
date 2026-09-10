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

T16 asks only which loaded executable module owns that natural virtual target.
After the existing helper scalar becomes nonzero, the already-running deferred
diagnostic writer passes it to `sceKernelFindModuleByAddress()`. It accepts the
result only when the complete ten-word fingerprint lies in both the owner's
text range and one of its at most four reported segments. All arithmetic uses
subtraction-based bounds checks before the first target read. A successful
capture writes compact owner metadata, the stable text-relative offset, the
containing segment, and ten read-only instruction words:

```text
[state-zero-vcall-owner] target=0x........ module=........ text=0x........ text_size=0x........ offset=0x........ segment=... segment_start=0x........ segment_size=0x........
[state-zero-vcall-code] offset=0x........ words=0x........,...
```

An unknown module or an invalid text/segment range emits only
`validation=failed`; it never dereferences the captured address. T16 adds no
thread, scanner, hook, patch, argument capture, result conversion, or cache
operation. In particular, it does not interpret or change 15, and the T15
virtual wrapper and downstream tracers are unchanged.

Phase report: files changed are `kernel/main.c`, the safety verifier, and this
Phase 3 record. The technical finding is limited to the hardware-proven T15
natural result and exit described above; T16 has no hardware result yet.
The implementation assumes only that LoadCore's existing address lookup and
reported module ranges describe loaded executable text. Static verification
and PSPDEV build status must be recorded with the change. The required hardware
test is one recovery-protected PSP-1000 6.61 run with `ClockAndCalendar` and the
broad BSMan shim disabled, the dangerous 58D4 trigger and diagnostics/activation
trace enabled, and both proven narrow compatibility controls enabled. Do not
load `660_plugins_on_661.prx`. Return the complete unedited log containing the
owner, fingerprint, and unchanged T15 result/counts. The owner's module name,
stable offset, function semantics, and whether an additional decrypted PRX is
needed remain unresolved. The recommended next phase is offline correlation
against the matching decrypted PSP-1000 PRX; no new compatibility behavior is
justified before that result.
