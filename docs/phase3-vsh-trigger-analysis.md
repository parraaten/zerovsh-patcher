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

## Phase 3.1f: resolving the state-source import

### Corrected hardware findings

The delayed, segment-validated read proved that `vsh_shared_state` is `0` on
the tested PSP-1000. The sole store remains at `+0x671C`, but the call producing
that value targets `+0x3F970`, whose two hardware words decode as:

```text
03E00008  jr      $ra
000985CC  syscall 0x2617
```

Consequently `+0x3F970` is a resolved import/syscall stub, not an internal
generator. Its 29 direct references are consistent with a shared import. The
neutral name is `vsh_state_source_import`; the runtime syscall number is not an
import NID and is not used to identify it. The earlier
`vsh_state_generator_3f970` label and generator-disassembly interpretation are
withdrawn.

The wider initializer context also corrects its condition:

```text
+66E0  xori   a1, a1, 0xFFFF
+66E4  xori   a0, a0, 1
+66E8  sltiu  a1, a1, 1
+66EC  sltiu  a0, a0, 1
+66F0  addiu  sp, sp, -0x10
+66F4  and    a1, a1, a0
+66F8  bnez   a1, +670C
+66FC  sw     ra, 0(sp)
```

The state assignment therefore occurs only when original `a0 == 1` and
original `a1 == 0x0000FFFF`. The previous `(a0 == 0) && (a1 & 1)` interpretation
is removed. Because `+0x66D8` is an unconditional backward jump and `+0x66DC`
is its delay slot, `+0x66E0` is the new strong entry candidate. It is not called
proven until the full-text scan finds and contextualizes direct callers.

### Validated import-table traversal

The kernel obtains the loaded `vsh_module` by name and checks its module ID and
text address against the captured values. It accepts `stub_top/stub_size` only
when the complete range lies in one of the module's at most four trusted
segments. Each `SceLibraryStubTable` descriptor is first validated far enough
to read `len`; zero length is rejected. The traversal advances only by
`len * 4`, requires the descriptor to fit both the declared stub range and a
trusted segment, and requires enough descriptor bytes to contain `stubtable`.

For each descriptor, the complete `stubcount * 4` NID array and `stubcount * 8`
function-stub array must fit trusted segments before either is indexed. The
resolver compares `stubtable + index * 8` with runtime text `+0x3F970`. Only a
matched entry's library string is read, one validated byte at a time, into a
fixed 32-byte kernel buffer; absence of a terminator or leaving a segment marks
the name invalid. No arbitrary-memory structure scan is performed.

A match records raw library, index, NID, stub/NID table addresses, and both stub
words. Real PSP-1000 hardware subsequently proved that the validated tuple is
`sceVshBridge:0x21C243FE`, publicly identified as the VSH wrapper
`vshKernelGetModel`. This is distinct from importing `sceKernelGetModel`
directly from a system-memory library. The diagnostic exact-match flag now
recognizes the proven VSH wrapper tuple. The import stub is never called or
modified.

### Initializer caller scan and concise output

The relocation-safe direct-reference scanner now targets `+0x66E0`, not the
interior `+0x66EC`. It retains JAL before J, at most 16 records, with explicit
total/stored/overflow and clamped caller windows for offline `a0/a1` preparation
analysis. The obsolete 0x200-byte import-stub-table dump and its 29 caller
windows are removed. Existing predicate matrix counts and the three known
`+0x6F84` callers remain preserved.

Expected new records are:

```text
[event] vsh_state_initializer_offset result=0x000066E0
[event] vsh_state_initializer_refs result=0x........
[event] vsh_state_import_offset result=0x0003F970
[event] vsh_state_import_match result=0x........
[event] vsh_state_import_get_model_match result=0x........
[event] vsh_state_import_library_valid result=0x........
[event] vsh_state_import_word0 result=0x03E00008
[event] vsh_state_import_word1 result=0x000985CC
[vshimport] stub=... offset=0x3F970 library=... index=... nid=... stubtable=... nidtable=...
```

### Current evidence, unknowns, and safety

**PROVEN:** structural traversal returned `sceVshBridge:0x21C243FE`, the public
`vshKernelGetModel` wrapper identity; the initializer's verified caller passes
`a0=1, a1=0xFFFF`; and the resulting PSP-1000 VSH model state is 0.
**INFERENCE:** the wrapper ultimately obtains the hardware model represented by
that state. **HYPOTHESIS:** meanings of the downstream capability bits and the
minimum caller combination needed to request SlidePlugin remain unresolved.

This change performs zero VSH writes, zero shared-state writes, zero import-stub
calls, and no Sony request. `vsh_slide_patch=disabled` and
`vsh_reference_scan=read_only` remain active.

### One next controlled experiment

Run once with `PSP1000SlidePlugin=Enabled`, `ClockAndCalendar=Disabled`, and the
VSH patch disabled. Return the complete unedited `[vshimport]`, import events,
`+0x66E0` caller windows, and stability result. Resolve the returned raw NID and
caller argument preparation offline before proposing any behavioral experiment.

### Phase report

- **Files changed:** `kernel/main.c`, this report, the Phase 3 procedure, and
  `AGENTS.md`.
- **Technical findings:** hardware proves shared state 0, corrects the
  initializer condition and candidate entry, and reclassifies `+0x3F970` as an
  import stub; its library/NID await the new structural capture.
- **Assumptions:** loaded `SceModule2` segment/import metadata is authoritative
  only after the implemented module identity and range checks.
- **Build status:** `./build_linux.sh` was attempted, but this container lacks
  PSPDEV (`psp-config` and `/lib/build.mak`).
- **Hardware test required:** the single import-resolution/initializer-caller
  run above.
- **Hardware result available:** the prior read-only run booted normally,
  validated the shared-state segment, and read value 0.
- **Unresolved questions:** downstream capability semantics, indirect users,
  and cross-model behavior; this evidence does not claim a direct
  `sceKernelGetModel` import.
- **Recommended next phase:** analyze only the returned import tuple and
  initializer caller windows before designing any behavioral control.

## Phase 3.2: selective caller `+0x58D4` behavioral control

Hardware has now structurally resolved the shared-state source as
`sceVshBridge:0x21C243FE`, publicly identified as `vshKernelGetModel`.  The
PSP-1000 VSH model state is proven to be 0.  The initializer at `+0x66E0` is
called directly from `+0x70E0` with `a0 = 1` and `a1 = 0xFFFF`, and stores the
model query result when that condition is met.  The leaf at `+0x6F84` is thus a
model/capability predicate; globally forcing it freezes PSP-1000.  Exactly
three direct callers are proven at `+0x058D4`, `+0x13F6C`, and `+0x14020`.

The first behavioral control modifies only the JAL at `+0x58D4`, directing it
to a dedicated strict-true (`1`) function.  It is separately, default-disabled
by `PSP1000SelectiveSlideTrigger58D4`, and additionally requires model 0,
firmware 6.61, `PSP1000SlidePlugin=Enabled`, and
`ClockAndCalendar=Disabled`.  Runtime validation requires the word to be a JAL,
its relocation-aware pseudo-direct target to equal text `+0x6F84`, and the
replacement to share the callsite's upper four address bits.  Failure is a
normal no-patch boot.  The delay slot and all other VSH words remain untouched;
the prior Sony `module_start` no-op is dormant so any Sony start is natural.

It remains unknown whether `+0x58D4` specifically causes the native VSH to
request SlidePlugin.  Request/RCO/probe/start breadcrumbs and the selective
validation, original/replacement word, application, and cache-sync records are
the required hardware evidence.  A build cannot establish runtime behavior.

The hardware build must verify that `psp-nm -n user/zerovsh_upatcher.elf |
grep zeroCtrlReturnTrue` reports a distinct symbol and that its disassembly is
a standalone, state-independent leaf equivalent to `jr $ra; li $v0, 1` (the
return assignment may occupy the branch delay slot).  In `main.o`, a displayed
`jal 0 <zeroCtrlDummyFunc>` at offset `0x228` is only the unresolved pre-link
placeholder: its `R_MIPS_26 zeroCtrlRecordVshSlideTarget` relocation identifies
the actual link target and must not be interpreted as a dummy-function call.

## Phase 3.3: late observation and controlled global reproduction

Real 6.61 PSP-1000 T1, T2, and T3 runs proved that `+0x13F6C`, `+0x14020`,
and their combination each executed but did not cause a PRX/RCO request, probe,
or start in the observed startup window. Extended T4 subsequently **PROVED**
that `+0x58D4` executes at roughly 6.8 seconds and is the smallest presently
proven selective trigger for PRX request, probe, pre-start observation, and RCO
request before the later crash. The writer polls fixed state every 200 ms for
12 seconds, persists only transitions, and emits a final snapshot when VSH
survives long enough.

`DangerousGlobalPredicate6F84` is a separate, explicit reproduction mode. It
validates the hardware-captured first two predicate instructions semantically:
`LUI v0,upper` followed by `LW a0,signed_disp(v0)` must reconstruct the
independently derived, segment-validated shared global at text `+0x56CE0`.
The runtime words remain logged because the load displacement changes when VSH
relocates. The mode then redirects only the predicate entry to a dedicated
counted strict-true assembly leaf. It does not
modify the shared model or any known direct caller. `DangerousAllCallers` is
**not proven equivalent**: it changes three known direct JALs, whereas the global
mode affects every path reaching the predicate, including unidentified indirect
or tail paths. The expected request/probe/freeze sequence remains historical
evidence until the new mode is run on hardware.
