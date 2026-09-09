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

## Current Strategy B decision: BSMan CLOSED only

Hardware now **PROVES** that `DangerousCaller58D4` opens the native Sony
pipeline, LoadCore probe returns zero, natural Sony `module_start` enters and
returns success, and the RCO request follows. The active failure boundary is
post-start runtime/RCO/activation/PAF. Memory is substantially lower at the
deferred return observation, but its owner is **UNKNOWN**.

The isolated `sceBSMan` / `0x23E3A9B6` CLOSED shim is an
**EXPERIMENT — NOT YET HARDWARE VERIFIED**. Runtime import descriptors and a
unique boolean caller are structurally resolved; static `+0x93AC` branches on
`v0 == 0` into the non-open path, supporting `CLOSED=0` as a **STRONG
INFERENCE**. The experiment changes only that resolved two-word import stub and
returns virtual UI CLOSED. It does not implement impose, OPEN, PAF, allocation,
model, physical-slider, power, display, LED, or brightness behavior. Hardware
outcomes must be evaluated using T9 before selecting any next shim.

### BSMan runtime-stub hardware evidence

The first real T9 run **PROVED** unique resolution of `sceBSMan` /
`0x23E3A9B6` at runtime `text+0x2A158` and observed the resolved words
`0x0000054C,0x00000000` (`SYSCALL; NOP`). The prior validator rejected that
shape and made zero writes, so the run is Outcome E: it proves neither a BSMan
call nor any effect from CLOSED substitution. The narrow retry recognizes this
form structurally while retaining all caller and transaction checks. CLOSED=0
remains **STRONG INFERENCE**, and impose/PAF remain outside this change.

## Activation localization and eventual overhead

The current natural-behavior trace structurally derives the activation entry
from the unique BSMan caller and records entry plus the pre-BSMan-call boundary.
It is research instrumentation, not a compatibility layer. Its helper leaves
and four scalar slots are intentionally tiny, while all serialization and
memory queries remain deferred. The eventual stable implementation should
remove this trace, the large fixed VSH scan/capture arrays, diagnostic writer
thread and stack, verbose strings, and superseded trigger modes after hardware
selects the minimal compatibility behavior. No such memory optimization is
made before the evidence is collected.
