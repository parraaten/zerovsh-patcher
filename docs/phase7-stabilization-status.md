# Phase 7 stabilization status and recovery

## Honest release status

The integration is **research-ready, not behaviorally production-certified**.
The safe production configuration below performs no PSP-1000 selective VSH
write and starts no diagnostic writer. Sony SlidePlugin enablement cannot be
made the default until real PSP-1000 evidence selects and stabilizes a trigger
mode and demonstrates delayed runtime survival. No source-only result can close
that gate.

## Safe configuration

```ini
[SlidePlugin]
ClockAndCalendar = Disabled

[Experimental]
PSP1000SlidePlugin = Disabled
PSP1000SlideTriggerMode = Disabled
PSP1000Diagnostics = Disabled
```

All three controls default to `Disabled` when absent. Unknown trigger strings
also map to disabled. The obsolete `PSP1000SelectiveSlideTrigger58D4` key is
recognized only for compatibility; an explicit legacy `Enabled` maps to the
conspicuously named dangerous mode and should be removed from production files.

The new safe trigger candidates are `Caller13F6C`, `Caller14020`, and
`Caller13F6C_14020`. Modes containing `58D4` are prefixed `Dangerous`; none is
implicit. The framework writes only a validated JAL callsite word per selected
caller, never the shared model state or predicate body.

## Recovery

1. Before testing, ensure recovery mode can disable the Memory Stick VSH
   plugin without entering the normal XMB.
2. On freeze, crash, power-off, or boot loop, disable
   `zerovsh_patcher.prx` in recovery (or remove/rename its VSH plugin entry).
3. Edit `ms0:/seplugins/zerovsh.ini` to the safe configuration above. Remove
   `PSP1000SelectiveSlideTrigger58D4` or set it to `Disabled`.
4. Do not alter `flash0`. Preserve the log and note the last visible state.
5. Re-enable the plugin, boot once, and verify the S0 rollback control before
   another experiment.

If user-supplied Sony assets are missing or invalid, leave the PSP-1000 option
disabled. Failure must return to ordinary XMB through configuration rollback;
there is no approved manual loader fallback.

## Static release gates

`tools/verify_psp1000_safety.py` checks the disabled selector default, one
central selective-write primitive, explicit suppression of the global
predicate patch, retained ELF alignment validation, forbidden literal flash0
write operations, JAL reconstruction arithmetic, helper stub symbols, and
helper disassembly for gp/sp/JAL use. `build_linux.sh` runs it against the real
user ELF before embedding and separately retains the final 64-byte symbol
alignment test. `git diff --check` remains required.

## Remaining hardware gates, in order

1. T0 stable instrumented control.
2. T1 `Caller13F6C` including its hit count and five-minute stability.
3. Restore T0, then T2 `Caller14020`.
4. Only if both are safe, T3 combined mode.
5. If a native request/start path appears, M0 isolated memory and delayed-alive
   evidence with Sony behavior patches still disabled.
6. Only after repeatable M0 survival, capture PSP Go versus PSP-1000 reference
   video/timing under F0 and identify the first incompatible Sony operation.
7. Select Strategy A, or add one narrowly validated Strategy B transaction.
   Strategies C–E remain unimplemented until preceding strategies have
   repeatably failed for a known reason.

Hardware logs must be returned unedited. None of these pending tests is claimed
as passed by this document.
