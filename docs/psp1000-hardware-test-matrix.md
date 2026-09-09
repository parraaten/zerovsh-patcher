# PSP-1000 SlidePlugin hardware test matrix (Phases 3–7)

## Safety envelope

These tests target retail PSP-1000 hardware on 6.61 (`0x06060110`). They never
write `flash0`; `slide_plugin.prx` and `slide_plugin.rco` must be legally
user-supplied files under the configured Memory Stick redirection tree. Keep a
recovery method which can disable `zerovsh_patcher.prx` before every run.
Never enable `ClockAndCalendar` during Phase 3 trigger classification.

The same PRX supports all rows below. Change only `ms0:/seplugins/zerovsh.ini`,
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
* **Success:** stable XMB; retain the log whether or not Sony assets are
  requested.
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

### D1 — known-dangerous caller `+0x58D4` (not routine testing)

* **Config:** `PSP1000SlideTriggerMode = DangerousCaller58D4`.
* **Known evidence:** installation and no early request were proven; an enabled
  run later crashed while the identical disabled PRX remained stable.
* **Use:** only if a later analysis has a specific reason to repeat it.
* **Recovery:** mandatory recovery access; return selector to `Disabled`.
* **Never use:** `DangerousCaller58D4_13F6C`,
  `DangerousCaller58D4_14020`, and `DangerousAllCallers` unless a reviewed
  hypothesis explicitly requires the combination.

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
