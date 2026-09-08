# Phase 3.1b: PSP-1000 VSH trigger analysis

## Scope and safety

This phase is a read-only reverse-engineering experiment for PSP-1000 firmware
6.61. It leaves `vsh_module + 0x6F84` untouched, does not request or change the
Sony SlidePlugin, and keeps all PSP-1000 clock, RTC, button, power, LED, and
brightness behavior disabled. The experiment remains gated by
`PSP1000SlidePlugin=Enabled` together with `ClockAndCalendar=Disabled`.

## Proven hardware observations

- The original Sony SlidePlugin can be requested, loaded, relocated, and can
  reach the pre-start callback on PSP-1000.
- The XMB can freeze before any Sony request: the breadcrumb run ended with
  `request=0 rco_request=0 probe=0 start=0`.
- In the controlled A/B, applying the historical `vsh_module + 0x6F84` forced
  return froze the XMB before icons, while suppressing only that modification
  restored a normal, usable XMB boot.
- The safe run identified VSH text as `0x09C11600..0x09C66CBF` and the candidate
  address as `0x09C18584`, which is within that text range.

These observations prove that the forced modification was necessary for the
observed freeze. They do not prove that the offset is wrong or that Sony's
`module_start` is compatible.

## New capture

The fixed kernel diagnostic state now holds up to `0x180` bytes (96 words).
For an unclamped capture it covers candidate-relative offsets `-0x80` through
`+0xFF`, so the reported range for the observed module will be
`0x09C18504..0x09C18683` (VSH text offsets `0x6F04..0x7083`). The end value in
the event record is exclusive (`0x7084`) and the size is `0x180`.

The kernel validates the candidate against the module text, clamps both ends
to text boundaries, aligns them down to complete words, and only then reads.
It records the actual start offset, exclusive end offset, size, and result.
No USER allocation is made. The callback merely submits module metadata; the
kernel copies instructions into fixed diagnostic storage and publishes the
`vsh_module_seen` flag last. Only the existing writer thread serializes them:

```text
[event] vsh_code_capture_start result=0x00006F04
[event] vsh_code_capture_end result=0x00007084
[event] vsh_code_capture_size result=0x00000180
[event] vsh_code_capture_result result=0x00000000
[vshcode] addr=0x09C18504 word=0xXXXXXXXX
...
```

The exact 96-word raw capture is necessarily pending the next PSP-1000 run.

## Currently available raw words and verified decode

The earlier hardware capture provides only these six words:

```text
address     word        decode
09C1857C    0A70615D    j      0x09C18574
09C18580    24050001    addiu  $a1, $zero, 1
09C18584    3C0209C7    lui    $v0, 0x09C7
09C18588    8C4482E0    lw     $a0, -0x7D20($v0)
09C1858C    2483FFFC    addiu  $v1, $a0, -4
09C18590    38820007    xori   $v0, $a0, 7
```

The jump target was independently calculated using the MIPS pseudo-direct
rule: the upper four bits of `PC + 4` combined with the 26-bit field shifted
left two bits. The instruction at `0x09C18580` is its delay slot.

The `lw` immediate is signed. Consequently its effective address is
`0x09C70000 - 0x7D20 = 0x09C682E0`, **not** `0x09C782E0`. That address is
`0x566E0` bytes from the reported VSH text base, `0x1620` bytes beyond the
reported text end. Module data/BSS boundaries were not captured, so ownership
of the address is not yet proven.

## Function boundaries and control flow

The available window has no stack adjustment, saved-register operation,
`jal`, epilogue, or `jr $ra`. The instruction immediately preceding the
candidate is the delay slot of an unconditional backward jump to offset
`0x6F74`. Thus `+0x6F84` is not demonstrated to be a function entry and cannot
be reached by simple fall-through from `+0x6F7C`; it may be a separately
targeted basic block, a continuation entered by a branch outside the six-word
window, or dead/aligned code. Classification is currently **E (unknown)**,
with “basic block inside a function” more plausible than an entry but not yet
proven.

No direct caller/reference to `+0x6F84` is visible in the six words. The one
known control-flow reference is:

```text
caller offset  instruction   target offset
0x6F7C         j 0x09C18574  0x6F74
```

It targets the preceding loop/block, not the candidate. The expanded capture
can reveal local branch and jump references, but direct callers elsewhere in
the approximately 0x556C0-byte text cannot be found without a complete exact
binary or a subsequent whole-text read-only search.

## Global-state evidence

The candidate loads one word from `0x09C682E0`, derives `$a0 - 4` and
`$a0 XOR 7`, and, in the limited evidence, performs no module-load call and no
store. This is consistent with state/value computation but is insufficient to
identify a boolean, return value, or slide meaning. The expanded window is
needed to see the consumers, comparisons, branches, and return paths. Nearby
references to the same global cannot yet be enumerated.

## Firmware and supported-model comparison

The repository contains the three Sony SlidePlugin PRX/RCO families, but no
PSP-1000 6.61 `vsh_module` dump and no exact supported-model or PSP Go
`vsh_module` binary. Therefore no byte-for-byte static VSH comparison is
possible from repository assets, and no PSP Go binary has been substituted as
PSP-1000 evidence.

The source confirms that historical ZeroVSH selected offsets `0x6D78` (6.20),
`0x6F6C` (6.3x), and `0x6F84` (6.60/6.61) only for non-1000/non-Go models and
replaced the first two instructions with a jump to a function returning `-1`.
Source offsets establish patch intent, not semantic equivalence between model
specific VSH builds. With no comparison binaries, neither a supported-model
match nor a PSP-1000 equivalent candidate can responsibly be ranked.

## H1 versus H2

- **H1 (different PSP-1000 code/semantics):** remains viable. The candidate is
  not shown to be an entry, the original code excluded model 0, and exact
  cross-model binaries are unavailable. The newly corrected global address
  also shows why semantics should not be inferred from the preliminary decode.
- **H2 (equivalent routine, invalid forced `-1` on hardware without a slide):**
  also remains viable. The A/B proves the forced return causes the tested
  freeze but says nothing about offset equivalence. If the routine interprets
  `-1` as a state transition that PSP-1000 cannot satisfy, the same address can
  be correct while the replacement result is unsafe.

Neither hypothesis currently dominates. There is no evidence-supported
alternate PSP-1000 offset yet.

## Explicit unknowns

The complete function boundaries, candidate predecessors/successors, direct
callers, return paths, value returned, ownership and values of `0x09C682E0`,
other references to that address, model-to-model equivalence, safe host-side
condition, Sony `module_start` compatibility, and full-initialization memory
headroom all remain unknown.

## One next controlled hardware experiment

Boot this read-only build once in the already verified safe configuration:
`PSP1000SlidePlugin=Enabled`, `ClockAndCalendar=Disabled`, and the VSH slide
patch disabled. Return the complete unedited log containing all 96
`[vshcode]` records and the four capture events. Observe only whether icons
appear and the XMB remains usable. Do not request SlidePlugin or change any
candidate instruction. The returned window is the single new variable and
will permit offline control-flow analysis before considering any further
capture or behavioral experiment.

## Phase report

- **Files changed:** `kernel/main.c`, `user/main.c`, this report, the Phase 3
  procedure, and `AGENTS.md`.
- **Technical finding:** the prior global address interpretation missed signed
  immediate extension; the effective address is `0x09C682E0`. Existing words
  do not establish `+0x6F84` as a function entry.
- **Assumptions:** the hardware-reported module metadata and six words are
  authoritative; the expanded words are not known until hardware returns them.
- **Build status:** recorded with the change commit; a build cannot prove PSP
  hardware safety or semantics.
- **Hardware test required:** the one read-only capture described above.
- **Hardware result available:** trigger-disabled XMB boot was normal; expanded
  capture has not yet been run.
- **Unresolved questions:** listed above.
- **Recommended next phase:** offline disassembly of the returned expanded
  window, without a behavioral patch.
