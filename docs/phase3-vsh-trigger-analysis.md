# Phase 3.1c: tracing PSP-1000 VSH predicate callers

## Scope and safety

This remains a read-only PSP-1000 firmware 6.61 experiment. It never writes
VSH text or the shared state, never requests Sony SlidePlugin directly, and
keeps the clock, RTC, injection, button, power, LED, brightness, and CPU-speed
paths disabled. It remains gated by `PSP1000SlidePlugin=Enabled` together with
`ClockAndCalendar=Disabled`; the experimental PSP-1000 `+0x6F84` redirection
remains disabled.

## Proven hardware findings

The completed `0x180`-byte capture came from a fully functional XMB boot:

```text
vsh text address:       0x09C26E00
vsh text size:          0x000556C0
capture offsets:        0x6F04..0x7083
capture end (exclusive):0x7084
capture size:           0x180 (96 words)
candidate address:      0x09C2DD84
```

The capture proves that `+0x6F84` is the aligned start of a complete small leaf
predicate rather than an arbitrary interior instruction. Its verified code is:

```text
+6F84  3C0209C8  lui    v0, 0x09C8
+6F88  8C44DAE0  lw     a0, -0x2520(v0)
+6F8C  2483FFFC  addiu  v1, a0, -4
+6F90  38820007  xori   v0, a0, 7
+6F94  2C630002  sltiu  v1, v1, 2
+6F98  2C420001  sltiu  v0, v0, 1
+6F9C  00621825  or     v1, v1, v0
+6FA0  14600006  bnez   v1, +6FBC
+6FA4  00002821  move   a1, zero
+6FA8  24020009  addiu  v0, zero, 9
+6FAC  50820001  beql   a0, v0, +6FB4
+6FB0  24050001  addiu  a1, zero, 1
+6FB4  03E00008  jr     ra
+6FB8  30A200FF  andi   v0, a1, 0xFF
+6FBC  ...       jump   +6FB4
+6FC0  ...       set    a1, 1 (delay slot)
```

The signed address calculation is exact:
`0x09C80000 + sign_extend(0xDAE0) = 0x09C80000 - 0x2520 = 0x09C7DAE0`.
The routine returns exactly 0 or 1 and is true for state values `{4,5,7,9}`.
The neutral name used here is `vsh_predicate_6f84`.

The same capture shows a cluster of independent leaf predicates reading the
same global: `+0x6F04`, `+0x6F44`, `+0x6F84`, `+0x6FC4`, `+0x7004`, `+0x701C`,
`+0x7030`, and `+0x7070`. The observed sets/ranges are respectively
`{2,3,6,8}`, `{4,5,7,9}`, `{4,5,7,9}`, `{4,5,7,9}`, approximately `3..9`,
`<2`, `{4,5,7,9}`, and `<10` for the apparent non-negative domain. This is
strong evidence for a finite state/capability classifier cluster, but not a
basis for assigning slide semantics.

Leaving `+0x6F84` untouched produces a normal XMB. The historical replacement
returns `-1` instead of the predicate's strict 0/1 result and can freeze the
PSP-1000 before any Sony request. It is not yet known whether that difference,
or forcing a true state on hardware without a slide, explains the freeze.

## Direct caller scan algorithm

The kernel scans every complete word in the loaded `vsh_module` text. It accepts
only opcodes 3 (`JAL`) and 2 (`J`), in two passes so JAL matches occupy the fixed
array before less useful tail jumps. For source address `pc` and word `insn`,
the target is resolved with the MIPS pseudo-direct rule:

```text
target = ((pc + 4) & 0xF0000000) | ((insn & 0x03FFFFFF) << 2)
```

The full resolved address, not merely the low 26-bit field, is compared against
all eight runtime predicate addresses. Every match increments both a total and
the corresponding predicate-matrix cell. At most 32 matches are retained; all
additional matches increment `vsh_direct_reference_overflow`. Thus counts remain
visible even when detailed records are truncated.

Each retained record contains source address, source text offset, raw word,
`J`/`JAL`, predicate offset, and a bounds-clamped `0x80`-byte window from source
minus `0x30` through source plus `0x4F`. The window includes argument setup, the
call and delay slot, and the initial return-value consumer when those lie within
that range. Its deterministic format is:

```text
[vshref] source=0x........ offset=0x..... word=0x........ kind=JAL predicate=0x6F84
[vshref_window] index=N start=0x..... size=0x80
[vshrefcode] index=N addr=0x........ word=0x........
```

Offline analysis must classify every caller independently as nonzero boolean,
exact comparison, signed test, arithmetic, store, argument propagation, or
unknown. No assumption that `-1` equals 1 is made across callers.

## Verified direct callers and result consumers

The latest hardware scan found exactly three direct references to
`vsh_predicate_6f84`, all `JAL` instructions:

- `+0x058D4` consumes the result with `bne v0, zero`; 1 and -1 are equivalent
  for this control-flow decision.
- `+0x13F6C` also uses `bne v0, zero`, selecting approximately argument `0x828`
  when true and `0x028` when false. Again, 1 and -1 are equivalent.
- `+0x14020` is part of a capability/state mask pipeline. Its result controls a
  `movn` that contributes bit `0x40`; `movn` tests nonzero, so 1 and -1 are
  equivalent here too.

Thus every known direct caller uses nonzero semantics. This substantially
weakens the strict-boolean form of H1, although it does not prove that indirect
`JALR`/function-pointer consumers are absent. For the corrected-global run, the
writer retains all matrix counts but serializes detailed direct-reference
windows only for predicate `+0x6F84`, avoiding repetition of the already
captured windows for the other predicates.

## Runtime global derivation and reference scan

The scanner derives the shared-global address from the first two loaded
instructions at `vsh_predicate_6f84`; it does not hardcode an address or either
observed relocation-dependent displacement. It validates a `LUI`, validates a
compatible load immediately after it, and requires the load base register to
match the LUI destination. It then computes using explicit 32-bit arithmetic:

```text
upper        = lui_immediate << 16
displacement = sign_extend_16(load_immediate)
global_addr  = upper + displacement
global_offset = global_addr - vsh_text_addr
```

For the latest run, `0x09C80000 + sign_extend(0xD9E0)` produces
`0x09C7D9E0`, and the expected diagnostic offset is `0x56CE0`. The offset is a
consistency observation only, never the resolver. Decode failure is recorded
and disables the global scan rather than falling back to a guess.

The full-text scan then considers byte/halfword/word loads and stores. For each
access it searches backward at most four instructions for a LUI defining the
same base register and reconstructs the candidate effective address using that
LUI's upper immediate and the access's signed immediate. Only a reconstructed
address equal to the runtime-derived global is retained; raw immediates are
never compared.

To reduce false pairs, the backward walk stops if an intervening instruction
definitely overwrites the base through common `LUI`, `ORI`, `ADDIU`, load, or
R-type `ADDU`/`OR` (including their usual move forms). This is conservative,
not complete MIPS data-flow analysis; offline inspection of each retained
window remains authoritative.

Two passes retain stores (`SB`, `SH`, `SW`) before loads (`LB`, `LH`, `LW`,
`LBU`, `LHU`). Each retained record includes access address/offset, raw word,
load/store kind, base/value register numbers, matching LUI offset, and the same
clamped `-0x30/+0x50` window. Storage remains fixed at 32 records; total,
stored, and overflow counters are separate. Output is:

```text
[vshglobal] source=0x........ offset=0x..... word=0x........ kind=STORE base=N value=N lui=0x.....
[vshglobal_window] index=N start=0x..... size=0x80
[vshglobalcode] index=N addr=0x........ word=0x........
```

Stores are prioritized because they are the best route to initialization and
state transitions. This scan cannot by itself prove what the global represents
or what values it has during startup.

## Predicate caller matrix

The scanner maintains a count for each hardware-confirmed predicate offset and
serializes it even if detailed storage overflows:

```text
[vshmatrix] predicate=0x6F04 references=N
[vshmatrix] predicate=0x6F44 references=N
[vshmatrix] predicate=0x6F84 references=N
[vshmatrix] predicate=0x6FC4 references=N
[vshmatrix] predicate=0x7004 references=N
[vshmatrix] predicate=0x701C references=N
[vshmatrix] predicate=0x7030 references=N
[vshmatrix] predicate=0x7070 references=N
```

This matrix can reveal shared callers and grouping without dumping the full
`0x556C0`-byte VSH text.

## Expected hardware markers

The writer thread emits the existing VSH metadata and 96-word evidence followed
by:

```text
[experiment] vsh_reference_scan=read_only
[experiment] vsh_direct_windows=predicate_6f84_only
[event] vsh_direct_reference_total result=0x........
[event] vsh_direct_reference_stored result=0x........
[event] vsh_direct_reference_overflow result=0x........
[vshmatrix] ... (eight records)
[vshref] / [vshref_window] / [vshrefcode] ...
[event] vsh_shared_global_addr result=0x........
[event] vsh_shared_global_offset result=0x00056CE0
[event] vsh_shared_global_decode_valid result=0x00000001
[event] vsh_global_reference_total result=0x........
[event] vsh_global_reference_stored result=0x........
[event] vsh_global_reference_overflow result=0x........
[vshglobal] / [vshglobal_window] / [vshglobalcode] ...
```

All scanning is read-only, all retained data lives in fixed kernel storage, and
only the existing diagnostic writer performs persistent I/O. There are zero
writes to VSH text, zero writes to `0x09C7DAE0`, and zero new USER allocations.

## Hypotheses and unknowns

- **H1 — strict boolean incompatibility:** substantially weakened because all
  three known direct callers treat 1 and -1 identically as nonzero. It is not
  absolutely disproven because indirect `JALR`/function-pointer references have
  not been proven absent.
- **H2 — incompatible forced host state:** strengthened by the nonzero consumers
  and especially the `+0x14020` capability-mask path contributing bit `0x40`.
  PSP-1000 may be unable to complete the transition enabled by that capability.

Not proven: the global's semantic identity; its initializer or writer; which
caller requests SlidePlugin; whether any caller distinguishes 1 and `-1`;
which caller causes the pre-request freeze; equivalence on supported models;
Sony `module_start` compatibility; or whether safe activation should patch this
predicate at all. No alternate behavioral patch is proposed.

## One next controlled hardware experiment

Boot this scanner once with `PSP1000SlidePlugin=Enabled`,
`ClockAndCalendar=Disabled`, and `vsh_slide_patch=disabled`. Return the complete
unedited log and report XMB stability. Do not request SlidePlugin or modify any
predicate/global. Offline analysis of caller/global windows is the next step;
no return-value experiment should occur before that evidence is reviewed.

## Phase report

- **Files changed:** `kernel/main.c`, this report, the Phase 3 procedure, and
  `AGENTS.md`.
- **Technical findings:** hardware establishes a strict 0/1 leaf predicate at
  `+0x6F84`, true for `{4,5,7,9}`, inside a classifier cluster over
  `0x09C7DAE0`; the three direct `+0x6F84` callers all use nonzero semantics.
- **Assumptions:** the returned real-hardware 96-word capture and stability
  report are authoritative; compatible global references require offline
  confirmation for intervening register writes.
- **Build status:** `./build_linux.sh` was attempted in the development
  container but PSPDEV is unavailable (`psp-config` and `/lib/build.mak` are
  missing). A PSPDEV build remains required; building cannot establish runtime
  safety.
- **Hardware test required:** the single read-only caller/global scan above.
- **Hardware result available:** the preceding 96-word read-only capture booted
  to a fully functional XMB.
- **Unresolved questions:** listed above.
- **Recommended next phase:** offline caller-consumer and state-writer analysis,
  without a behavioral patch.

## Phase 3.1e: tracing the state generator

### New hardware evidence

The relocation-aware run derived `vsh_shared_state` at `0x09C7D7E0`, offset
`+0x56CE0` from VSH text `0x09C26B00`, with decode validation successful. The
address is `0x1620` bytes beyond executable text and is therefore consistent
with module data/BSS state, although its semantic identity remains unknown.
The scan found 15 references with no overflow and exactly one direct store, at
`+0x0671C`:

```text
+0x670C  jal   +0x3F970
+0x6710  nop
+0x6714  lui   v1, runtime-upper
+0x6718  j     +0x6700
+0x671C  sw    v0, vsh_shared_state (delay slot)
```

The hardware words around `+0x66EC` independently decode as `sltiu a0,a0,1`,
followed by a `-0x10` stack allocation, `and a1,a1,a0`, conditional branch,
return block, and the generator call/store block. Thus generation occurs only
when the incoming `a0` is zero and bit 0 of incoming `a1` is set. The function must
begin at or before `+0x66EC`; the exact entry cannot be proven from the returned
window because the preceding function boundary was not captured. The neutral
names are `vsh_shared_state_initializer` (candidate entry `+0x66EC`) and
`vsh_state_generator_3f970`.

### Read-only capture design

The next build captures `+0x6680..+0x673F` to establish the initializer's exact
boundary and `+0x3F8F0..+0x3FAEF` to cover the generator and its surrounding
boundaries. It scans all VSH text for correctly reconstructed direct J/JAL
references to initializer candidate `+0x66EC` and generator `+0x3F970`.
Each target retains at most 16 references, JAL before J, with separate total,
stored, and overflow counts and the existing clamped `-0x30/+0x50` caller
window. If the wider initializer context proves a different entry, another
read-only scan—not a behavioral patch—will be required for that corrected
entry.

The global address is validated against trusted `SceModule2.nsegment`,
`segmentaddr[]`, and `segmentsize[]` metadata obtained in kernel mode by module
name and checked against the captured module UID. The complete four-byte range must fit in one of at most four reported
segments. Only after revalidating immediately in the delayed writer thread is
its current word read. Failed validation records `segment_valid=0` and performs
no read. The delayed current value is the preferred non-invasive observation of
`vsh_state_generator_3f970`'s stored result; no hook or trampoline is installed.

To reduce repetition, all predicate matrix counts remain available, detailed
caller windows remain limited to the three `+0x6F84` calls, and only the sole
STORE global window is repeated. The new output is:

```text
[event] vsh_shared_global_segment_valid result=0x........
[event] vsh_shared_global_value result=0x........  # only when segment-valid
[event] vsh_state_initializer_offset result=0x000066EC
[event] vsh_state_initializer_refs result=0x........
[event] vsh_state_generator_offset result=0x0003F970
[event] vsh_state_generator_refs result=0x........
[vshstate_window] name=initializer_context ...
[vshstate_window] name=generator ...
[vshstate_ref] / [vshstate_refcode] ...
```

There are zero writes to VSH, zero writes to `vsh_shared_state`, no Sony request,
and no USER allocation. The scanner cannot yet determine whether the generator
uses model, syscon, motherboard, configuration, or device-presence inputs;
unknown call targets and imports must be reported by raw address/NID rather than
named speculatively.

### One next controlled experiment

Run this read-only build once with `PSP1000SlidePlugin=Enabled`,
`ClockAndCalendar=Disabled`, and `vsh_slide_patch=disabled`. Return the complete
unedited state-window/reference records, segment-validation/value events, and
XMB stability result. Offline analysis must establish the initializer boundary,
its callers, the generator's complete return paths and calls, and evidence for
or against hardware/model classification before any behavioral experiment.
