# Sony-first PSP-1000 SlidePlugin compatibility plan

## Scope and present decision gate

This repository contains no Sony PRX/RCO and must never acquire one. Runtime
redirection uses only assets supplied by the owner on Memory Stick. The native
VSH pipeline remains the only approved loader path:

`VSH decision -> redirected request -> LoadCore probe -> pre-start handler -> Sony module_start -> runtime`

Static work cannot establish that any Sony entry point, allocation, hardware
operation, or animation works on a PSP-1000. Consequently the compatibility
layer is deliberately staged rather than populated with guessed offsets. The
next decision requires T1–T3 and M0 hardware logs from
`psp1000-hardware-test-matrix.md`.

## Evidence classification

### PROVEN on hardware

* PSP-1000 VSH model state is zero and is populated through the structurally
  resolved `sceVshBridge` NID `0x21C243FE` (`vshKernelGetModel`). This VSH
  wrapper identity is distinct from a direct `sceKernelGetModel` import.
* Predicate `+0x6F84` reads that state and has three direct callers:
  `+0x58D4`, `+0x13F6C`, and `+0x14020`.
* Replacing the predicate globally freezes VSH. Selectively replacing the
  `+0x58D4` call installed correctly and a later crash correlated strongly
  with that one enabled control, while no request occurred in its first
  diagnostic window.
* An earlier native experiment requested, relocated, and reached the pre-start
  callback for the unmodified user-supplied Sony module, then froze. This does
  not prove Sony `module_start` or delayed runtime survival.

### INFERENCE from captured instructions

* `+0x13F6C` selects `0x828` rather than `0x028` when the predicate is true.
* `+0x14020` contributes capability bit `0x40` when true.
* These consumers treat the result as boolean; changing `1` to `-1` would not
  explain the known direct-call behavior.

### HYPOTHESIS pending hardware/binary evidence

* One of `+0x13F6C`, `+0x14020`, or their combination is the minimum native
  SlidePlugin request capability.
* Capability bit `0x40`, flag `0x800`, or their downstream users correspond to
  slide UI. Their meanings must not be named as facts yet.
* Sony startup failure may involve absent Go hardware or PSP-1000 memory
  pressure. Neither cause is established, and no allocation size may be
  modified until ownership and lifetime are traced.

## Compatibility strategy ladder

1. **A — unchanged Sony module/resources:** use only a hardware-validated
   selective VSH decision. This remains preferred.
2. **B — narrow runtime compatibility:** after a reproducible failing boundary,
   structurally resolve the responsible Sony function/import, validate module
   identity, firmware, segment, original instructions, and pseudo-direct
   reachability, then replace only nonexistent hardware interaction or a traced
   optional allocation.
3. **C — isolated replacement:** retain Sony resources/control flow while a
   PSP-1000-safe leaf supplies a virtual slide state. State must be UI-only;
   it must not claim that PSP-1000 has Go power, display, Bluetooth, or slider
   hardware.
4. **D — resource-driven hybrid:** use user-supplied Sony RCO semantics only if
   A–C fail for documented, repeatable hardware reasons.
5. **E — custom recreation:** last resort. It is not implemented because A–D
   have not been disproven. Beginning it now would invent behavior without the
   PSP Go reference and violate the Sony-original-first priority.

A lower strategy is not activated merely because a test crashes. Each move
requires identical-build control evidence, the last safe breadcrumb, module
metadata, isolated memory snapshots, and a documented target function/import.

## Patch transaction rules

Every future Sony or VSH patch must be represented as a transaction containing
module name/ID, expected devkit, text and segment bounds, expected original
word(s), reconstructed semantic target, replacement address and reachability,
original-word backup, applied count, and cache-sync result. Multiple validated
words must not be committed piecemeal: validation completes before the first
write. Failure leaves the normal XMB path untouched. A callback target keeps
the helper resident; handler replacement must chain and must never leave a
pointer into unloaded memory.

No model-global spoof, manual Sony module load, flash write, or guessed Sony
offset is an acceptable fallback.

## Visual versus hardware behavior

Phase 5 measurements must separately catalogue visual state (clock/calendar,
RCO pages, transitions, timing, background, open/close presentation) and real
Go hardware effects. PSP-1000 can provide a virtual UI open/closed state through
an explicit safe control only after Sony's state consumer is identified. Go
power-management, display, LED, brightness, and physical-slider operations stay
disabled unless a PSP-1000-safe semantic substitute is individually proven.

## Memory method

The historical `0x01220000` USER transition is not assigned to the small helper.
For native SlidePlugin testing capture total free and largest block at adjacent
lifecycle boundaries. Use module segment metadata for intrinsic footprint.
Trace allocation call, requested size, owner, success, lifetime, and consumers
before changing anything. Heavy reverse-engineering arrays remain fixed and
bounded; production can now disable the writer thread and all log file I/O via
`PSP1000Diagnostics = Disabled`. The helper remains loaded because VSH callback
and trigger targets point into it.

Stack reductions are deferred until real high-water measurements exist. A
smaller guessed stack is not a memory optimization.
