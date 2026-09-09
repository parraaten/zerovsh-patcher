# PSP-1000 SlidePlugin hardware test matrix (Phases 3–7)

## Safety envelope

These tests target retail PSP-1000 hardware on 6.61 (`0x06060110`). They never
write `flash0`; `slide_plugin.prx` and `slide_plugin.rco` must be legally
user-supplied files under the configured Memory Stick redirection tree. Keep a
recovery method which can disable `zerovsh_patcher.prx` before every run.
Never enable `ClockAndCalendar` during Phase 3 trigger classification.

The same PRX supports all rows below. The diagnostic writer observes transitions
for 12 seconds at 200 ms intervals and writes only changed values plus a final
snapshot. Change only `ms0:/seplugins/zerovsh.ini`,
fully restart VSH, retain the entire `ms0:/zerovsh_psp1000.log`, and record the
wall-clock time and visual result. A missing marker means only that the marker
was not persisted; it is not proof that the corresponding code did not run.

## Common configuration

```ini
[SlidePlugin]
ClockAndCalendar = Disabled

[Experimental]
PSP1000SlidePlugin = Enabled
PSP1000Diagnostics = Enabled
PSP1000SlideTriggerMode = Disabled
```

`PSP1000SelectiveSlideTrigger58D4` is deprecated. If explicitly set to
`Enabled` while the new selector is `Disabled`, it maps to
`DangerousCaller58D4` for compatibility. Delete the deprecated key after
recovery. Unknown selector strings safely behave as `Disabled`.

## Ordered matrix

### T0 — stable instrumented control

* **Config:** common configuration (`Disabled`).
* **Expected markers:** diagnostics header, `disabled_control`, writer alive,
  and the final request/RCO/probe/start state.
* **Observe:** XMB icon arrival, input, suspend/resume, and five minutes idle.
* **Success:** normal XMB and no SlidePlugin request.
* **Crash interpretation:** regression unrelated to a selective caller; stop.
* **Recovery:** disable the VSH plugin from recovery, then set
  `PSP1000SlidePlugin = Disabled`.
* **Next:** T1 only after T0 is stable.

### T1 — caller `+0x13F6C`

* **Config:** `PSP1000SlideTriggerMode = Caller13F6C`.
* **Expected markers:** one trigger record with `caller_offset=0x13F6C`,
  `target=text+0x6F84`, and `validation=1 patch_applied=1 cache_sync=1`.
  `hit_count > 0` proves execution before the deferred read.
* **Observe:** request/probe/start markers, XMB flags or layout changes, and five
  minutes idle.
* **Hardware result:** the caller validated, was patched and cache-synchronized,
  executed once, and produced no request/RCO/probe/start transition during the
  former three-second window. **PROVEN:** this caller alone was insufficient in
  that observed startup path. Repeat under the 12-second observer as T5.
* **Crash interpretation:** if T0 passed with the identical PRX, this is strong
  evidence that this capability callsite is unsafe alone; it does not identify
  the downstream function.
* **Recovery:** restore selector `Disabled` using recovery.
* **Next:** T2 after restoring and confirming T0.

### T2 — caller `+0x14020`

* **Config:** `PSP1000SlideTriggerMode = Caller14020`.
* **Expected markers:** trigger `0x14020` with all validation fields equal to
  one and a deferred hit count; pipeline breadcrumbs if reached.
* **Observe/success/recovery:** same as T1.
* **Crash interpretation:** isolates the capability-mask `0x40` consumer only
  relative to T0; do not infer that bit `0x40` means “slider.”
* **Hardware result:** the caller validated, executed once, and produced no
  request/RCO/probe/start transition in the former window. **PROVEN:** this
  caller alone was insufficient in that observed startup path. Repeat as T6.
* **Next:** T3 only if T1 and T2 each boot safely.

### T3 — callers `+0x13F6C` and `+0x14020`

* **Config:** `PSP1000SlideTriggerMode = Caller13F6C_14020`.
* **Expected markers:** exactly two trigger records, each validated, patched,
  cache-synchronized, and with an independently reported hit count.
* **Observe:** whether the native VSH requests the user-supplied PRX/RCO, probe
  result, pre-start, previous-handler return, Sony start boundary, and delayed
  alive state.
* **Success:** stable XMB plus a complete breadcrumb sequence. A request is a
  Phase 3 result, not proof of clock/calendar compatibility.
* **Crash interpretation:** interaction between these capabilities is possible;
  compare hit counts and last persisted breadcrumb against T1/T2.
* **Recovery:** selector `Disabled`; do not proceed to behavior enablement.
* **Next:** M0 if native start/delayed-alive is reached, otherwise return logs
  for call-graph analysis. Do not manually load the Sony module.
* **Hardware result:** both callers validated and each executed once, with no
  request/RCO/probe/start transition in the former window. **PROVEN:** this pair
  was insufficient during the observed startup path. Repeat as T7.

### D1 — known-dangerous caller `+0x58D4` (not routine testing)

* **Config:** `PSP1000SlideTriggerMode = DangerousCaller58D4`.
* **Hardware result:** extended T4 **PROVED** a `+0x58D4` hit near 6.8 seconds,
  followed by PRX request, probe, pre-start handler observation, and RCO request
  near 7.2 seconds before a crash. This is the smallest currently proven
  selective native-pipeline trigger. `start=1` proves only pre-start handler
  observation, not entry into or return from Sony's natural `module_start`.
* **Use:** only if a later analysis has a specific reason to repeat it.
* **Recovery:** mandatory recovery access; return selector to `Disabled`.
* **Never use:** `DangerousCaller58D4_13F6C`,
  `DangerousCaller58D4_14020`, and `DangerousAllCallers` unless a reviewed
  hypothesis explicitly requires the combination.

### D2 — controlled historical global predicate reproduction

* **Config:** `PSP1000SlideTriggerMode = DangerousGlobalPredicate6F84`, with
  PSP-1000 SlidePlugin and diagnostics enabled and ClockAndCalendar disabled.
* **Expected markers:**
  `global_predicate_6f84_patch=enabled_dangerous`, a `[global6f84]` record with
  validation/patch/cache fields equal to one, changed-only `[late]` counter and
  pipeline transitions, and the 12-second `[final]` snapshot if VSH survives.
* **Observe:** exact ordering of global predicate hits, PRX request, RCO request,
  LoadCore probe, pre-start/start, XMB freeze, or power-off.
* **Recovery:** use recovery mode and restore all three experimental settings to
  `Disabled`; never alter `flash0`.
* **Semantic limit:** `DangerousAllCallers` changes only the three verified
  direct JAL callsites. It is **not proven equivalent** to this mode, which
  redirects the predicate entry and therefore also affects unidentified
  indirect, tail, or otherwise unclassified runtime paths.

### M0 — native Sony memory baseline

Run only after a safe mode reaches the native request/start path. Preserve the
successful trigger selector and user-supplied assets; do not enable historical
clock/power patches. Compare `[mem]` and partition records at kernel start,
hooks, request/probe, pre-start, and delayed state. Success is a stable delayed
state with a complete log. Attribute deltas only to adjacent isolated captures.
A failed allocation or freeze is a decision gate for a narrow Sony compatibility
patch, not permission to shrink unknown buffers.

### F0 — visual fidelity observation

Run only after M0 is repeatably stable. Record video of PSP Go reference and
PSP-1000 from cold VSH arrival through clock/calendar entry/exit, background
transition, button interaction, suspend/resume, and repeated state changes.
Record firmware, assets' hashes (not assets), configuration, and timings.
No Phase 5 behavior is declared compatible until this comparison exists.

### S0 — production rollback control

```ini
[SlidePlugin]
ClockAndCalendar = Disabled
[Experimental]
PSP1000SlidePlugin = Disabled
PSP1000SlideTriggerMode = Disabled
PSP1000Diagnostics = Disabled
```

Success is a normal XMB with no diagnostic writer and no PSP-1000 VSH write.
This is the shipping-safe configuration until hardware promotes a tested mode.

## Twelve-second repeat labels

Use the common configuration above and change only the selector:

* **T4:** `DangerousCaller58D4`
* **T5:** `Caller13F6C`
* **T6:** `Caller14020`
* **T7:** `Caller13F6C_14020`
* **D2/global reproduction:** `DangerousGlobalPredicate6F84`

For each run expect changed-only `[late] elapsed_us=...` records and, if the XMB
survives the complete interval, `[final] observation_window_us=12000000`, all
four final hit counts, and final request/RCO/probe/start state. D2 additionally
requires `[global6f84] validation=1 ... patch_applied=1 cache_sync=1`; a failed
validation must leave `patch_applied=0`. Do not infer execution from patch
application alone.

### T8 — natural Sony `module_start` boundary

Use only after the proven extended T4 path and retain recovery access:

The preceding direct-return-site build recognized the three-word prologue but
found no unique bounded `jr ra`, so it failed closed with `validation=0` and
`install=0`; its subsequent crash is not attributed to that tracer. T8 now uses
only the validated entry and saved-RA interposition.

```ini
[SlidePlugin]
ClockAndCalendar = Disabled

[Experimental]
PSP1000SlidePlugin = Enabled
PSP1000SlideTriggerMode = DangerousCaller58D4
PSP1000Diagnostics = Enabled
PSP1000SonyStartTrace = Enabled
PSP1000SelectiveSlideTrigger58D4 = Disabled
```

Expected installation evidence is
`[experiment] psp1000_sony_start_trace=enabled_natural`, followed by
`[sony-start-ra] attempted=1 validation=1 install=1 cache_sync=1`, plus
`[sony-start-entry]` evidence for all three validated originals and the two
replacement words. The ordinary
`caller_58d4_hit_count`, request, probe, pre-start `start`, and RCO breadcrumbs
remain enabled. `start=1` still means only that the pre-start handler observed
the module.

The entry stub preserves `a0`, `a1`, and `gp`, saves the incoming ModuleMgr
`ra`, substitutes the exit stub address, reproduces both displaced prologue
instructions, and resumes at original `module_start + 8`. Sony's validated and
untouched `sw ra,4(sp)` saves that interposed address naturally. The exit stub
records `v0` without changing it and jumps through the saved caller address.
Neither stub performs file I/O or a memory query; no Sony return is patched.

Interpret results as follows:

* **A — entered=0, crash after validated installation:** determine whether
  ModuleMgr invokes another entry path; do not infer that the traced function
  ran.
* **B — entered=1, returned=0, crash:** failure lies within Sony
  `module_start`, its imported registration call, the internal function near
  static `+0xFE8`, or a synchronous callback before return. Instrument those
  internal boundaries next.
* **C — entered=1, returned=1, result=0, later crash:** Sony natural
  `module_start` completed successfully. Only then should the next experiment
  consider BSMan/impose, PAF/page activation, and memory boundaries.
* **D — entered=1, returned=1, result!=0:** classify that exact startup or
  registration failure before adding any shim.

If validation or installation is zero, no Sony code is redirected. Return the
complete log and runtime module metadata rather than weakening validation.

#### T8 registration-localization markers

Before interpreting entry behavior, require one deferred registration record:

```text
[sony-start-register] called=1 success=... fail_reason=NAME(ID)
[sony-start-register-addresses] entry=... entry_end=... exit=... exit_end=...
[sony-start-register-slots] resume=... caller_ra=... entry_seen=... return_seen=... result=...
[sony-start-register-helper] text=... text_size=... data_size=... bss_size=... segments=...
[sony-start-register-segment] index=... start=... size=...
```

If registration succeeds but installation exits before `attempted=1`, expect
`[sony-start-guard] checked=1 reason=NAME(ID)`. Do not adjust a range or make the
caller-RA slot optional from this log alone; return the complete evidence for
analysis first.

## T9 — BSMan-only CLOSED-state Strategy B experiment

This row supersedes T8's former unknown-start interpretation. Hardware has now
**PROVEN** the `+0x58D4` native request/probe path, natural Sony `module_start`
entry and successful return, and the subsequent RCO request. The failure
boundary is downstream runtime/RCO/activation/PAF.

Use the exact configuration in `phase3-controlled-enablement.md`, retaining the
validated Sony saved-RA trace and enabling only `PSP1000BSManClosedShim` as the
new variable. The shim is **EXPERIMENT — NOT YET HARDWARE VERIFIED**.

* **A — `install=1`, `hit_count=0`, unchanged freeze:** **PROVEN** installed and
  not called before the last persisted observation; global irrelevance is not
  proven. Investigate ordering, impose, or PAF evidence next without changing
  BSMan.
* **B — `install=1`, `hit_count>0`, unchanged freeze:** **PROVEN** Sony reached
  BSMan and CLOSED-only substitution was insufficient. A later, separate
  sceVshBridge `0x639C3CB3`/`0x8000000D` experiment may be proposed, but is not
  part of this build.
* **C — hit and farther progress:** **STRONG HARDWARE EVIDENCE** that BSMan state
  participates. Capture the last breadcrumb, correlated (not attributed)
  memory snapshot, RCO progress, and visible PAF state.
* **D — hit and stable XMB:** very strong evidence that CLOSED compatibility
  removes the immediate failure. Hold this as the sole shim while testing idle,
  navigation, normal operations, and reboot; do not implement OPEN.
* **E — `validation=0`, `install=0`:** inconclusive. Return exact import/caller
  evidence; do not weaken validation.

Safe reset:

```ini
PSP1000SlidePlugin = Disabled
PSP1000SlideTriggerMode = Disabled
PSP1000Diagnostics = Disabled
PSP1000SonyStartTrace = Disabled
PSP1000SelectiveSlideTrigger58D4 = Disabled
PSP1000BSManClosedShim = Disabled
ClockAndCalendar = Disabled
```

### T9 Outcome E hardware result and retry

The first T9 run is **PROVEN Outcome E**: `sceBSMan` / `0x23E3A9B6` uniquely
resolved at runtime `text+0x2A158` (`0x09CA3358`) with words
`0x0000054C,0x00000000`, but the old validator did not accept the observed
`SYSCALL; NOP` form. It installed nothing and performed zero BSMan code writes.
The zero caller evidence means the caller scan was not reached; it does not show
that BSMan was or was not called.

Repeat T9 with the same configuration. Require `stub_form=SYSCALL_NOP`, retain
the unique direct-JAL and strict-zero-test evidence, and interpret behavior only
if `validation=1 install=1`. CLOSED remains **STRONG INFERENCE**, and no fix is
claimed.

## T10 — natural activation-to-BSMan localization

Keep the proven `DangerousCaller58D4` path and Sony start trace, disable the
BSMan CLOSED shim, and enable only `PSP1000ActivationTrace`. Require the runtime
resolver/caller evidence and `[activation-trace] validation=1 install=1` before
interpreting counters.

* Entry count zero: activation was not observed before persistence; investigate
  earlier RCO/PAF dispatch without claiming non-execution.
* Entry count positive and BSMan-boundary count zero: the improved last-safe
  boundary lies inside the naturally executed activation prefix, including its
  internal/imported early-return dependencies.
* `slide_last_stage=2`: natural execution reaches the known BSMan syscall but
  no return breadcrumb was persisted.
* `slide_last_stage=3`: the natural BSMan syscall returned; failure is farther
  into activation/impose/PAF processing. Use ordering and deferred memory
  correlation to select the next isolated investigation.

This row performs no BSMan, impose, PAF, OPEN, or model substitution. Missing
asynchronous output is not proof of non-execution.

The first T10 run recorded successful installation, stage 1, and an activation
entry count increasing from one to three within 10 ms, with no persisted
pre-BSMan boundary. This strongly localizes the next question to the naturally
executed `+0x9304..+0x93AC` prefix.

## T11 — activation-prefix branch localization

Retain the T10 configuration and natural BSMan stub. Require activation
validation/installation and the exact `[activation-prefix] branch_words`
fingerprint before interpreting `slide_prefix_path_mask` or
`slide_prefix_counts`. The mask is cumulative; use counts to distinguish paths
across repeated activations.

* `result_zero>0`: the first `scePaf` import selected the direct epilogue.
* `result_nonzero>0, flag_zero>0`: the relocated byte selected the epilogue.
* `flag_nonzero>0` with no mask outcome and no pre-BSMan count: the second
  `scePaf` import was entered but no return was persisted.
* `mask_equal>0`: the alternate `+0x95DC` state-machine path was selected.
* `mask_unequal>0` without pre-BSMan: localize to the two state clears.
* A pre-BSMan count proves the prefix completed; interpret stage 2/3 as above.

This build changes no Sony result. Return the complete unedited log and normal
XMB observations before selecting any compatibility behavior.

The first T11 attempt is **fail-closed structural evidence**:
`validation=0 install=0`. Hardware returned the third pair as
`0x10620090,0x3C0209E5`. The first word is `beq v1,v0`, matching the research
PRX and the documented `v1 == 0x0101` test; the second is the relocated
`LUI v0` delay slot. The prior `0x10420090` expectation incorrectly encoded
`beq v0,v0`. Repeat T11 with the corrected exact branch word, the structural
`LUI v0` delay check, and unchanged configuration. Interpret no path evidence
unless validation and installation both equal one.

## T12 — isolated first-PAF boolean control

T11 subsequently produced `validation=1 install=1` and four identical natural
paths: the first PAF call entered and returned zero, `result_zero` incremented,
all later counters remained zero, and the cumulative mask was `0x007`. This
proves the immediate PAF-result epilogue is the active boundary.

Repeat the same configuration with only:

```ini
PSP1000PafPresentCompat = Enabled
```

Keep `PSP1000BSManClosedShim=Disabled`. Require the validated PAF callsite/NID
fingerprint and `paf_ed83bbcf_natural` record. The experiment executes the
natural function, changes only a natural zero result to strict boolean one for
this callsite, and leaves natural nonzero results unchanged. Interpret the
existing flag, mask, pre-BSMan, and BSMan-return evidence as described in the
Phase 3 report. Do not enable impose, OPEN-state, or any other compatibility
control in this run.

## T13 — post-BSMan natural boundary localization

T12 recorded four natural first-PAF zeros, four isolated conversions, and four
paths through the prefix to pre-BSMan. Stage 3 proves at least one BSMan return,
not four. Retain `PSP1000PafPresentCompat=Enabled`, keep
`PSP1000BSManClosedShim=Disabled`, and change no other behavior.

Require the exact `[post-bsman]` fingerprints, including uniquely resolved
`scePaf/0xFF03BCD5`, `sceVshBridge/0x639C3CB3`, and VshBridge argument
`0x8000000D`. Interpret dedicated entry/return counters and raw results:

* BSMan return count plus zero/nonzero counters identifies its immediate path.
* State zero selects `+0x957C`; state nonzero advances to the PAF pair.
* A PAF entry without return localizes inside that import; a positive returned
  value selects its `bgtz` epilogue, while zero or negative advances.
* VshBridge entry proves the verified `0x8000000D` path is active. Entry without
  return localizes inside it; nonzero return selects the epilogue; zero return
  reaches the virtual-call sequence at `+0x9420`.

Return the unedited log and XMB observations. This row substitutes no BSMan,
second-PAF, VshBridge, impose, OPEN/CLOSE, or model result.
