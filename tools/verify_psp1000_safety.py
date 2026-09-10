#!/usr/bin/env python3
"""Fail the build when statically-verifiable PSP-1000 safety rules regress."""

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys


STUBS = (
    "zeroCtrlTrigger58D4",
    "zeroCtrlTrigger13F6C",
    "zeroCtrlTrigger14020",
    "zeroCtrlGlobalPredicate6F84True",
)
COUNTERS = (
    "zeroCtrlTrigger58D4Hits",
    "zeroCtrlTrigger13F6CHits",
    "zeroCtrlTrigger14020Hits",
    "zeroCtrlGlobalPredicate6F84Hits",
)
SONY_ENTRY_STUB = "zeroCtrlSonyModuleStartEntryTrace"
SONY_ENTRY_STUB_END = "zeroCtrlSonyModuleStartEntryTraceEnd"
SONY_EXIT_STUB = "zeroCtrlSonyModuleStartExitTrace"
SONY_EXIT_STUB_END = "zeroCtrlSonyModuleStartExitTraceEnd"
SONY_TRACE_BASELINE_SHA256 = \
    "e670e353062f21147b3574350fdc47bdd3cc446fa9337f09b6ea7e0c7dc7828c"
BSMAN_STUB = "zeroCtrlBSManClosedLeaf"
BSMAN_STUB_END = "zeroCtrlBSManClosedLeafEnd"
BSMAN_COUNTER = "zeroCtrlBSManClosedHits"
BSMAN_RETURN_TRACE = "zeroCtrlBSManReturnTrace"
BSMAN_RETURN_TRACE_END = "zeroCtrlBSManReturnTraceEnd"
BSMAN_CALL_RA = "zeroCtrlBSManCallRA"
PREFIX_TRACE_STUBS = (
    "zeroCtrlSlidePrefixPafCallTrace",
    "zeroCtrlSlidePrefixPafReturnTrace",
    "zeroCtrlSlidePrefixResultTrace",
    "zeroCtrlSlidePrefixFlagTrace",
    "zeroCtrlSlidePrefixMaskTrace",
)
POST_TRACE_STUBS = (
    "zeroCtrlPostBSManBranchTrace",
    "zeroCtrlPostStateBranchTrace",
    "zeroCtrlPostPafCallTrace",
    "zeroCtrlPostPafReturnTrace",
    "zeroCtrlPostVshCallTrace",
    "zeroCtrlPostVshReturnTrace",
)
STATE_ZERO_TRACE_STUBS = (
    "zeroCtrlStateZeroCompareTrace", "zeroCtrlStateZeroWordTrace",
    "zeroCtrlStateZeroByteTrace", "zeroCtrlStateZeroVCallTrace",
    "zeroCtrlStateZeroVReturnTrace", "zeroCtrlStateZeroClass15Trace",
    "zeroCtrlStateZeroClass17Trace", "zeroCtrlStateZeroClass18Trace",
)
T22_CONSUMER_WRAPPERS = (
    ("zeroCtrlConsumer13F6CTrace", "zeroCtrlConsumer13F6CTraceEnd",
     "zeroCtrlConsumer13F6CHits"),
    ("zeroCtrlConsumer14020Trace", "zeroCtrlConsumer14020TraceEnd",
     "zeroCtrlConsumer14020Hits"),
)
T22_CONSUMER_TARGET = "zeroCtrlConsumer6F84Target"


def fail(message):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(1)


def mips_read_registers(word):
    """Return GPRs read by the ordinary MIPS instructions used in the proof."""
    opcode = word >> 26
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    if opcode in (2, 3, 15):
        return set()
    if opcode == 0:
        function = word & 0x3F
        if function in (0, 2, 3):
            return {rt}
        if function in (8, 9):
            return {rs}
        return {rs, rt}
    if opcode == 1 or opcode in (6, 7):
        return {rs}
    if opcode in (4, 5):
        return {rs, rt}
    if 0x20 <= opcode <= 0x27 or 0x30 <= opcode <= 0x37:
        return {rs}
    if 0x28 <= opcode <= 0x2F or 0x38 <= opcode <= 0x3F:
        return {rs, rt}
    return {rs}


def check_research_activation_prefix(root):
    """Independently prove the checked-in PRX operands and tracer scratch liveness."""
    image = (root / "bin/slide/slide_plugin_660.prx").read_bytes()

    def u16(offset):
        return int.from_bytes(image[offset:offset + 2], "little")

    def u32(offset):
        return int.from_bytes(image[offset:offset + 4], "little")

    if image[:4] != b"\x7fELF" or image[4:6] != b"\x01\x01":
        fail("research SlidePlugin is not a little-endian ELF32 image")
    program_offset = u32(28)
    program_size = u16(42)
    program_count = u16(44)
    load_segments = []
    for index in range(program_count):
        header = program_offset + index * program_size
        if u32(header) == 1:
            load_segments.append((u32(header + 8), u32(header + 4),
                                  u32(header + 16)))

    def word(address):
        for virtual, file_offset, file_size in load_segments:
            if virtual <= address and address + 4 <= virtual + file_size:
                offset = file_offset + address - virtual
                return int.from_bytes(image[offset:offset + 4], "little")
        fail("research SlidePlugin prefix lies outside its load segments")

    if word(0x9394) != 0x24020101:
        fail("research prefix no longer loads v0 with 0x0101")
    if word(0x9398) != 0x10620090:
        fail("research prefix no longer compares v1 with v0")
    if (word(0x939C) & 0xFFFF0000) != 0x3C020000:
        fail("research prefix no longer executes LUI v0 in the branch delay slot")
    post_words = {
        0x93B4: 0x1040000A, 0x93B8: 0x92620DCD,
        0x93E0: 0x10400066, 0x93F0: 0x00002021,
        0x9400: 0x24040001, 0x940C: 0x3C048000,
        0x9414: 0x3484000D, 0x9418: 0x1440FFCE,
        0x941C: 0x8FBF001C,
    }
    for address, expected in post_words.items():
        if word(address) != expected:
            fail("research post-BSMan word changed at +0x%X" % address)
    if (word(0x93E4) & 0xFFFF0000) != 0x3C020000:
        fail("post-BSMan state branch delay is not LUI v0")

    scratch = {8, 9, 10, 25}  # t0, t1, t2, t9
    live_ranges = (
        (0x9338, 0x9378, "first PAF/result/flag resumes"),
        (0x939C, 0x93B4, "0x0101 unequal resume"),
        (0x95DC, 0x9628, "0x0101 equal resume"),
        (0x93BC, 0x93EC, "BSMan nonzero resume"),
        (0x93F4, 0x93FC, "first post-BSMan PAF return"),
        (0x9404, 0x9410, "second post-BSMan PAF return"),
        (0x9418, 0x9424, "VshBridge return"),
        (0x957C, 0x9628, "post-BSMan state-zero resume"),
    )
    for start, end, description in live_ranges:
        for address in range(start, end, 4):
            used = mips_read_registers(word(address)) & scratch
            if used:
                fail("tracer scratch register is live at %s: +0x%X" %
                     (description, address))


def check_sources(root):
    check_research_activation_prefix(root)
    kernel = (root / "kernel/main.c").read_text()
    user = (root / "user/main.c").read_text()
    kernel_exports = (root / "kernel/exports.exp").read_text()
    user_imports = (root / "user/import.S").read_text()
    registration_header = (root / "kernel/sony_start_trace.h").read_text()
    assembly = (root / "user/stub.S").read_text()
    build = (root / "build_linux.sh").read_text()
    sample_config = (root / "bin/zerovsh.ini").read_text()
    if "PSP_EXPORT_FUNC_NID(zeroCtrlRegisterBSManClosedShim, 0x1337357C)" \
            not in kernel_exports:
        fail("kernel BSMan registration export NID is missing or changed")
    if "STUB_FUNC 0x1337357C, zeroCtrlRegisterBSManClosedShim" \
            not in user_imports:
        fail("user BSMan registration import NID is missing or changed")
    if "STUB_FUNC 0x1337357B, zeroCtrlRegisterSonyStartTrace" \
            not in user_imports:
        fail("Sony trace registration import NID changed")
    zeroctrl_import = re.search(
        r'STUB_START\s+"ZeroCtrlForUser"\s+0x[0-9A-Fa-f]+,\s*'
        r'0x([0-9A-Fa-f]{4})0005(?P<body>.*?)STUB_END',
        user_imports, re.S)
    if not zeroctrl_import:
        fail("cannot parse ZeroCtrlForUser import table")
    declared_count = int(zeroctrl_import.group(1), 16)
    actual_count = len(re.findall(r"^\s*STUB_FUNC\b",
        zeroctrl_import.group("body"), re.M))
    if declared_count != actual_count:
        fail("ZeroCtrlForUser declares %d functions but imports %d" %
             (declared_count, actual_count))
    if '"PSP1000SlideTriggerMode", "Disabled"' not in kernel:
        fail("dangerous trigger selector does not default to Disabled")
    if '"PSP1000Diagnostics", "Disabled"' not in kernel:
        fail("production diagnostics do not default to Disabled")
    if '"PSP1000SonyStartTrace", "Disabled"' not in kernel:
        fail("Sony module_start tracing does not default to Disabled")
    if '"PSP1000BSManClosedShim", "Disabled"' not in kernel:
        fail("BSMan CLOSED shim does not default to Disabled")
    for gate in (
        'model == 0', 'devkit == 0x06060110',
        'strcmp(psp1000SlidePlugin, "Enabled") == 0',
        'strcmp(psp1000Diagnostics, "Enabled") == 0',
        'strcmp(psp1000BSManClosedShim, "Enabled") == 0',
        '"DangerousCaller58D4") == 0',
        'strcmp(useSlide, "Disabled") == 0',
    ):
        if gate not in kernel:
            fail("BSMan experiment safety gate is missing " + gate)
    bsman_start = kernel.find("static void zeroCtrlInstallBSManClosedShim(")
    bsman_end = kernel.find("int OnModuleStart(", bsman_start)
    if bsman_start < 0 or bsman_end <= bsman_start:
        fail("BSMan transactional installer is missing")
    bsman = kernel[bsman_start:bsman_end]
    for required in (
        'strcmp(mod->modname, "slide_plugin_module")',
        '0x23E3A9B6', 'mod->stub_top', 'table->nidtable',
        'table->stubtable', 'bsman->match_count == 1',
        'zeroCtrlVshModuleRangeValid', 'zeroCtrlBSManOriginalStubForm',
        'caller_matches != 1', 'bsman->validation = 1',
    ):
        if required not in bsman:
            fail("BSMan structural resolution is missing " + required)
    if 'static const char expected[] = "sceBSMan"' not in kernel:
        fail("BSMan import library is not checked exactly")
    stub_form_start = kernel.find(
        "static unsigned int zeroCtrlBSManOriginalStubForm(")
    stub_form_end = kernel.find("static void zeroCtrlInstallBSManClosedShim(",
        stub_form_start)
    if stub_form_start < 0 or stub_form_end <= stub_form_start:
        fail("BSMan original-stub form validator is missing")
    stub_form = kernel[stub_form_start:stub_form_end]
    for required in (
        "ZERO_BSMAN_STUB_JUMP_NOP",
        "ZERO_BSMAN_STUB_JR_RA_SYSCALL",
        "ZERO_BSMAN_STUB_SYSCALL_NOP",
        "(word0 & 0xFC00003F) == 0x0000000C && word1 == 0",
    ):
        if required not in stub_form:
            fail("BSMan original-stub validator lost form " + required)
    if "0x0000054C" in stub_form:
        fail("BSMan SYSCALL/NOP validation hardcodes one hardware syscall")
    writer_start = kernel.find("static int zeroCtrlWriteSlideDiagnostics(")
    writer_end = kernel.find("static int zeroCtrlCreateSlideDiagnosticsThread(",
        writer_start)
    if writer_start < 0 or writer_end <= writer_start:
        fail("deferred slide diagnostic writer is missing")
    writer = kernel[writer_start:writer_end]
    sony_diag_start = writer.find("if (slide_diag.sony_start_trace.enabled)")
    bsman_diag_start = writer.find(
        "if (slide_diag.bsman.enabled || slide_diag.bsman.activation_enabled)",
        sony_diag_start)
    attempted_start = writer.find(
        "if (bsman->attempted && !observed_bsman_attempted)",
        bsman_diag_start)
    attempted_end = writer.find("if (hits != observed_bsman_hits)",
        attempted_start)
    stub_form_record = '"[bsman] stub_form=%s syscall_code=0x%05X\\n"'
    if min(sony_diag_start, bsman_diag_start, attempted_start, attempted_end) < 0:
        fail("BSMan deferred diagnostic scope is missing")
    if stub_form_record in writer[sony_diag_start:bsman_diag_start]:
        fail("BSMan stub-form diagnostic escaped into Sony trace scope")
    if "bsman->" in writer[sony_diag_start:bsman_diag_start]:
        fail("BSMan diagnostic state is referenced from Sony trace scope")
    if stub_form_record not in writer[attempted_start:attempted_end] or \
            "bsman->stub_form" not in writer[attempted_start:attempted_end] or \
            "bsman->syscall_code" not in writer[attempted_start:attempted_end]:
        fail("BSMan stub-form diagnostic is outside first-attempt BSMan scope")
    for required in (
        '"PSP1000ActivationTrace", "Disabled"',
        'strcmp(psp1000ActivationTrace, "Enabled") == 0',
        'strcmp(psp1000BSManClosedShim, "Disabled") == 0',
        '"PSP1000PafPresentCompat", "Disabled"',
        '"PSP1000BSManNotLinkedCompat", "Disabled"',
        'slide_diag.bsman.activation_enabled &&',
        'strcmp(psp1000PafPresentCompat, "Enabled") == 0',
        '_sw(bsman->paf_compat_enabled ? 1 : 0,',
        'psp1000_paf_present_compat=',
        'strcmp(psp1000BSManNotLinkedCompat, "Enabled") == 0',
        '_sw(bsman->bsman_not_linked_compat_enabled ? 1 : 0,',
        'psp1000_bsman_not_linked_compat=',
        '"slide_activation_entry_count"',
        '"slide_bsman_call_boundary_count"',
        '"slide_last_stage"',
        'fast_poll_until = elapsed + 2000000',
        'elapsed < fast_poll_until ?\n                    10000',
        'candidates != 1',
        'bsman->caller_addr',
        'Transaction commit: all transparent trace sites validated above.',
        'bsman->prefix_original[0] != 0x10400006',
        'bsman->prefix_original[2] != 0x1460000B',
        'bsman->prefix_original[4] != 0x10620090',
        'table->nidtable[i] != 0xED83BBCF',
        'paf_matches != 1',
        'slide_prefix_path_mask=0x%03X',
        'paf_call_words=0x%08X,0x%08X',
        'table->nidtable[i] != 0xFF03BCD5',
        'table->nidtable[i] != 0x639C3CB3',
        'bsman->post_original[0] != 0x1040000A',
        'bsman->post_original[2] != 0x10400066',
        '_lw(bsman->activation_addr + 0x108) != 0x3C048000',
        'bsman->post_original[9] != 0x3484000D',
        'post_bsman_path_mask=0x%03X',
        'state_zero_mask=0x%04X',
        'bsman->state_zero_original[0] != 0x1243FF73',
        '(bsman->state_zero_original[1] & 0xFFFF0000) != 0x3C020000',
        'bsman->state_zero_original[2] != 0x1460FF71',
        'bsman->state_zero_original[3] != 0x8FBF001C',
        'bsman->state_zero_original[4] != 0x1460FF6E',
        'bsman->state_zero_original[5] != 0x8FB60018',
        'bsman->state_zero_original[6] != 0x0040F809',
        'bsman->state_zero_original[7] != 0',
        'bsman->state_zero_original[8] != 0x1440FF8C',
        'bsman->state_zero_original[9] != 0x28620011',
        'bsman->state_zero_original[10] != 0x1440FF64',
        'bsman->state_zero_original[11] != 0x8FBF001C',
        'bsman->state_zero_original[12] != 0x1462FF87',
        'bsman->state_zero_original[13] != 0x8FB60018',
        'bsman->activation_addr + 0x284',
        'bsman->activation_addr + 0x2D0',
        '_sw(bsman->state_zero_replacement[pc],',
        '(const void *)(bsman->activation_addr + 0x27C), 0x50',
        'Transaction commit: all transparent trace sites validated above.',
        'results=bs_natural:0x%08X,bs_exact_sub:%u,',
    ):
        if required not in kernel:
            fail("activation localization trace is missing " + required)
    if '_sw(0, bsman->activation_addr + 0xE0)' in kernel:
        fail("T15 must leave the relocated state-branch LUI delay slot intact")
    activation_start = assembly.find("zeroCtrlSlideActivationTrace:")
    activation_end = assembly.find("zeroCtrlSlideActivationTraceEnd:",
        activation_start)
    call_start = assembly.find("zeroCtrlBSManCallTrace:")
    call_end = assembly.find("zeroCtrlBSManCallTraceEnd:", call_start)
    return_start = assembly.find("zeroCtrlBSManReturnTrace:")
    return_end = assembly.find("zeroCtrlBSManReturnTraceEnd:", return_start)
    if min(activation_start, activation_end, call_start, call_end,
            return_start, return_end) < 0:
        fail("activation localization assembly leaves are missing")
    if "ori     $t1, $t1, 0x0001" not in assembly[activation_start:activation_end] or \
            "bnez    $t2, 1f" not in assembly[activation_start:activation_end] or \
            "sltiu   $t2, $t2, 2" not in assembly[call_start:call_end]:
        fail("activation stage/mask evidence is not monotonic")
    localization_leaves = assembly[activation_start:activation_end] + \
        assembly[call_start:call_end] + assembly[return_start:return_end]
    if any(token in localization_leaves for token in
            ("$gp", "jal ", "jalr", "sceIo", "Alloc", "malloc")):
        fail("activation localization leaves use gp, calls, I/O, or allocation")
    return_leaf = assembly[return_start:return_end]
    natural_result_store = return_leaf.find(
        "sw      $v0, %lo(zeroCtrlPostBSManNaturalResult)")
    first_other_record = return_leaf.find("zeroCtrlPostBSManReturnHits")
    if natural_result_store < 0 or first_other_record <= natural_result_store or \
            "$sp" in return_leaf or \
            "zeroCtrlSlideTraceStage" not in return_leaf or \
            "lw      $ra, %lo(zeroCtrlBSManCallRA)($t0)" not in return_leaf or \
            "jr      $ra" not in return_leaf:
        fail("BSMan return trace does not preserve the natural result")
    for required in (
            "lui     $t2, 0x8002",
            "ori     $t2, $t2, 0x013A",
            "bne     $v0, $t2, 20f",
            "move    $v0, $zero",
            "zeroCtrlPostBSManSubstitutionHits",
            "sw      $v0, %lo(zeroCtrlPostBSManEffectiveResult)"):
        if required not in return_leaf:
            fail("BSMan return trace lacks exact not-linked conversion: " + required)
    if return_leaf.find("zeroCtrlPostBSManCompatMode") < natural_result_store:
        fail("BSMan compatibility is consulted before recording natural result")
    exact_t14_flow = re.compile(
        r"sw\s+\$v0, %lo\(zeroCtrlPostBSManNaturalResult\).*?"
        r"lw\s+\$t1, %lo\(zeroCtrlPostBSManCompatMode\).*?"
        r"beqz\s+\$t1, 20f.*?lui\s+\$t2, 0x8002.*?"
        r"ori\s+\$t2, \$t2, 0x013A.*?bne\s+\$v0, \$t2, 20f.*?"
        r"move\s+\$v0, \$zero.*?"
        r"lw\s+\$t1, %lo\(zeroCtrlPostBSManSubstitutionHits\).*?"
        r"addiu\s+\$t1, \$t1, 1.*?"
        r"sw\s+\$t1, %lo\(zeroCtrlPostBSManSubstitutionHits\).*?"
        r"20:.*?sw\s+\$v0, %lo\(zeroCtrlPostBSManEffectiveResult\)",
        re.S)
    if not exact_t14_flow.search(return_leaf):
        fail("BSMan source flow does not isolate substitution to enabled exact match")
    for symbol in PREFIX_TRACE_STUBS + POST_TRACE_STUBS:
        start = assembly.find(symbol + ":")
        end = assembly.find(symbol + "End:", start)
        if start < 0 or end < 0:
            fail("activation-prefix trace leaf is missing " + symbol)
        leaf = assembly[start:end]
        if any(token in leaf for token in
                ("$gp", "jal ", "jalr", "sceIo", "Alloc", "malloc")):
            fail(symbol + " uses gp, calls, I/O, or allocation")
        if symbol == "zeroCtrlSlidePrefixPafReturnTrace" and \
                ("sw      $v0, %lo(zeroCtrlSlidePrefixPafNaturalResult)" not in leaf or
                 "beqz    $t2, 7f" not in leaf or
                 "bnez    $v0, 7f" not in leaf or
                 "addiu   $v0, $zero, 1" not in leaf or
                 "lw      $ra, %lo(zeroCtrlSlidePrefixPafRA)" not in leaf or
                 "jr      $ra" not in leaf):
            fail("prefix PAF return trace does not isolate zero-to-one and restore ra")
    post_bs = assembly[assembly.find("zeroCtrlPostBSManBranchTrace:"):
        assembly.find("zeroCtrlPostBSManBranchTraceEnd:")]
    post_state = assembly[assembly.find("zeroCtrlPostStateBranchTrace:"):
        assembly.find("zeroCtrlPostStateBranchTraceEnd:")]
    if "sw      $v0, %lo(zeroCtrlPostStateNaturalValue)($t0)" not in post_bs or \
            "lw      $t2, %lo(zeroCtrlPostBSManEffectiveResult)($t0)" not in post_bs or \
            "beqz    $t2, 8f" not in post_bs:
        fail("post-BSMan result branch does not use the effective result")
    check_post_bsman_branch_semantics(post_bs)
    if "lw      $t2, %lo(zeroCtrlPostStateNaturalValue)" not in post_state or \
            "beqz    $t2, 10f" not in post_state or "$v0" in post_state:
        fail("post-BSMan state branch does not preserve the natural LUI delay slot")
    for symbol in (STATE_ZERO_TRACE_STUBS[0:5] + STATE_ZERO_TRACE_STUBS[7:8]):
        start = assembly.find(symbol + ":")
        end = assembly.find(symbol + "End:", start)
        if start < 0 or end < 0:
            fail("T15 state-zero trace leaf is missing " + symbol)
        leaf = assembly[start:end]
        if any(token in leaf for token in ("$gp", "jal ", "jalr", "sceIo", "Alloc", "malloc")):
            fail(symbol + " uses gp, a call, I/O, or allocation")
    for invocation in (
            "STATE_ZERO_CLASS zeroCtrlStateZeroClass15Trace, 15",
            "STATE_ZERO_CLASS zeroCtrlStateZeroClass17Trace, 17"):
        if invocation not in assembly:
            fail("T15 classification tracer is missing " + invocation)
    vcall = assembly[assembly.find("zeroCtrlStateZeroVCallTrace:"):
        assembly.find("zeroCtrlStateZeroVCallTraceEnd:")]
    vreturn = assembly[assembly.find("zeroCtrlStateZeroVReturnTrace:"):
        assembly.find("zeroCtrlStateZeroVReturnTraceEnd:")]
    if "sw      $v0, %lo(zeroCtrlStateZeroVCallTarget)" not in vcall or \
            "jr      $v0" not in vcall or \
            "sw      $v0, %lo(zeroCtrlStateZeroVCallResult)" not in vreturn or \
            "lw      $ra, %lo(zeroCtrlStateZeroVCallRA)" not in vreturn:
        fail("T15 virtual-call trace does not preserve target/result/ra")
    for symbol in ("zeroCtrlPostPafReturnTrace", "zeroCtrlPostVshReturnTrace"):
        start = assembly.find(symbol + ":")
        end = assembly.find(symbol + "End:", start)
        leaf = assembly[start:end]
        if re.search(r"(?:addiu|addu|or|move|lw|lbu)\s+\$v0", leaf):
            fail(symbol + " modifies a natural imported result")
        v0_lines = [line for line in leaf.splitlines() if "$v0" in line]
        expected_count = 2 if symbol == "zeroCtrlPostPafReturnTrace" else 1
        if len(v0_lines) != expected_count or any(
                "sw      $v0," not in line for line in v0_lines):
            fail(symbol + " has unexpected natural-result uses")
    post_paf_source = assembly[assembly.find("zeroCtrlPostPafReturnTrace:"):
        assembly.find("zeroCtrlPostPafReturnTraceEnd:")]
    for result_symbol in ("zeroCtrlPostPafResult0", "zeroCtrlPostPafResult1"):
        if post_paf_source.count(
                "sw      $v0, %lo(" + result_symbol + ")($t0)") != 1:
            fail("post-BSMan PAF return trace lacks exact store to " + result_symbol)
    fast_poll = kernel[kernel.find(
        "if (slide_diag.bsman.activation_enabled)"):kernel.find(
            "#undef WRITE_LATE_FLAG")]
    if "zeroCtrlDiagnosticsMemory" in fast_poll or \
            "zeroCtrlDiagnosticsCapturePartitions" in fast_poll:
        fail("activation fast-poll path performs a memory query")
    owner_capture = kernel[kernel.find(
        "static void zeroCtrlCaptureStateZeroVCallOwner"):
        kernel.find("static unsigned int zeroCtrlParseTriggerMode")]
    expected_candidates = (
        '"scePaf_Module"', '"sceVshCommonGui_Module"', '"vsh_module"',
        '"slide_plugin_module"', '"impose_plugin_module"',
        '"launcher_plugin_module"')
    candidate_list = kernel[kernel.find(
        "static const char *state_zero_vcall_candidates[]"):
        kernel.find("};", kernel.find(
            "static const char *state_zero_vcall_candidates[]"))]
    if any(candidate_list.count(name) != 1 for name in expected_candidates) or \
            candidate_list.count('"') != len(expected_candidates) * 2 or \
            "sizeof(state_zero_vcall_candidates[0])" not in owner_capture or \
            "sceKernelFindModuleByName(" not in owner_capture or \
            "target - candidate->text_addr <=" not in owner_capture or \
            "target - start <= size - sizeof(unsigned int)" not in owner_capture:
        fail("T16.3 ownership lacks its fixed candidate/text/segment checks")
    if any(call in owner_capture for call in (
            "sceKernelModuleCount(", "sceKernelGetModuleList(",
            "sceKernelFindModuleByUID(", "sceKernelFindModuleByAddress(")):
        fail("T16.3 uses a prohibited module lookup")
    pointer_validation = owner_capture.find("candidate_addr < 0x88000000")
    first_metadata_read = owner_capture.find("candidate->text_size")
    if pointer_validation < 0 or first_metadata_read <= pointer_validation:
        fail("T16.3 dereferences candidate metadata before pointer validation")
    if "state_zero_vcall_containing_candidates != 1" not in owner_capture or \
            "ZERO_VCALL_RESOLVE_AMBIGUOUS_OWNER" not in owner_capture:
        fail("T16.3 does not fail closed on ambiguous candidate ownership")
    first_read = owner_capture.find("_lw(target +")
    fingerprint_validation = owner_capture.find(
        "target - slide_diag.state_zero_vcall_segment_addr >")
    if first_read < 0 or fingerprint_validation < 0 or \
            first_read <= fingerprint_validation:
        fail("T16.1 fingerprints the virtual target before complete range validation")
    if "STATE_ZERO_VCALL_CODE_WORDS 10" not in kernel or \
            "state_zero_vcall_fingerprint_valid = 1" not in owner_capture or \
            "ZERO_VCALL_RESOLVE_FINGERPRINT_RANGE_INVALID" not in owner_capture:
        fail("T16.1 virtual target fingerprint is not fixed and fail-closed")
    if any(token in owner_capture for token in
            ("_sw(", "sceKernelDcache", "sceKernelIcache", "sceIo")):
        fail("T16.1 virtual target ownership is not read-only")
    resolve_gate = kernel[kernel.find(
        "if (!observed_state_zero_vcall_owner)"):
        kernel.find("observed_state_zero_vcall_owner = 1", kernel.find(
            "if (!observed_state_zero_vcall_owner)"))]
    if "if (target != 0 && returns != 0)" not in resolve_gate or \
            "[state-zero-vcall-resolve] attempted=1" not in resolve_gate or \
            "state_zero_vcall_candidates_found" not in resolve_gate or \
            "state_zero_vcall_containing_candidates" not in resolve_gate or \
            "if (slide_diag.state_zero_vcall_fingerprint_valid)" not in resolve_gate:
        fail("T16.1 resolution is not gated by target/return or lacks status gating")
    topmenu_validate = kernel[kernel.find(
        "static void zeroCtrlValidateTopMenuState"):
        kernel.find("static void zeroCtrlCaptureTopMenuState")]
    topmenu_capture = kernel[kernel.find(
        "static void zeroCtrlCaptureTopMenuState"):
        kernel.find("static const char *zeroCtrlTopMenuReasonName")]
    for token in ("state_zero_vcall_offset != 0x1E2B0", "0x90620150",
            "0x14400002", "0x2404000F", "0x8C64012C", "0x03E00008",
            "0x00801021", "displacement = (short)(load & 0xFFFF)",
            "sceKernelFindModuleByName(\"vsh_module\")",
            "(unsigned int)vsh < 0x88000000",
            "slot - start <= size - sizeof(unsigned int)"):
        if token not in topmenu_validate:
            fail("T17 TopMenu validation is missing " + token)
    if topmenu_validate.find("(unsigned int)vsh < 0x88000000") > \
            topmenu_validate.find("vsh->text_addr"):
        fail("T17 dereferences VSH metadata before pointer validation")
    slot_read = topmenu_capture.find("_lw(slide_diag.topmenu_global_slot)")
    context_validation = topmenu_capture.find("zeroCtrlRangeInSnapshot(")
    first_field_read = topmenu_capture.find("_lw(context + 0x128)")
    if slot_read < 0 or context_validation <= slot_read or \
            first_field_read <= context_validation or \
            "context, 0x154" not in topmenu_capture or \
            "if (!slide_diag.topmenu_validation) return" not in topmenu_capture:
        fail("T17 reads TopMenu state before slot/context range validation")
    t17_source = topmenu_validate + topmenu_capture
    if any(token in t17_source for token in
            ("_sw(", "_sb(", "sceKernelDcache", "sceKernelIcache",
             "sceKernelCreateThread")):
        fail("T17 TopMenu observation writes state or creates a thread")
    if "returns != observed_topmenu_returns" not in fast_poll or \
            "[topmenu-state]" not in resolve_gate:
        fail("T17 state capture is not bounded by virtual-return transitions")
    field12c_install = kernel[kernel.find(
        "static void zeroCtrlInstallField12CWriteTrace"):
        kernel.find("static void zeroCtrlInstallBSManClosedShim")]
    for token in ("vsh->text_addr + 0x1DEA8",
            "vsh->text_addr + 0x1D8C4", "store_word != 0xAC53012C",
            "zeroCtrlMipsJumpTarget(site, jump_word) != continuation",
            "_sw(replacement, site)", "_sw(store_word, site + 4)",
            "field12c_write_validation = 1",
            "field12c_write_install = 1", "field12c_write_cache_sync = 1"):
        if token not in field12c_install:
            fail("T18 field_12C writer validation is missing " + token)
    commit = field12c_install.find("_sw(replacement, site)")
    validation = field12c_install.find("field12c_write_validation = 1")
    if commit <= validation or "0xAC53012C" not in field12c_install[:commit]:
        fail("T18 patches the jump/store pair before transactional validation")
    field12c_stub = assembly[assembly.find("zeroCtrlField12CWriteTrace:"):
        assembly.find("zeroCtrlField12CWriteTraceEnd:")]
    if not field12c_stub or "$s3" not in field12c_stub or \
            "sw      $v0, %lo(zeroCtrlField12CWriteContext)" not in field12c_stub or \
            "lw      $t2, %lo(zeroCtrlField12CWriteResume)" not in field12c_stub or \
            "jr      $t2" not in field12c_stub or \
            "lw      $t2, -4($sp)" not in field12c_stub:
        fail("T18 tracer does not preserve the natural value/context/continuation")
    if any(token in field12c_stub for token in
            ("jal ", "jalr", "sceIo", "Alloc", "malloc")):
        fail("T18 tracer calls code, performs I/O, or allocates")
    if re.search(r"\b(?:li|addiu|ori)\s+\$s3\b|\b(?:lw|move|addu)\s+\$s3\b",
            field12c_stub) or re.search(
                r"\b(?:li|addiu|ori|lw|move|addu)\s+\$v0\b", field12c_stub):
        fail("T18 tracer modifies Sony's natural s3 value or v0 context")
    if "sceKernelCreateThread" in field12c_install:
        fail("T18 creates a new thread")
    install_record = writer.find("[topmenu-field12c-write-install]")
    bsman_attempt_record = writer.find(
        "if (bsman->attempted && !observed_field12c_write_install_status)")
    if min(install_record, bsman_attempt_record) < 0 or \
            install_record <= bsman_attempt_record:
        fail("T18.1 install status is not emitted once after the writer attempt")
    topmenu_record = writer.find("[topmenu-state]")
    live_record = writer.find("[topmenu-field12c-write-live]")
    topmenu_owner_done = writer.find(
        "observed_state_zero_vcall_owner = 1", topmenu_record)
    if min(topmenu_record, live_record, topmenu_owner_done) < 0 or not (
            topmenu_record < live_record < topmenu_owner_done):
        fail("T18.1 live field_12C result is not adjacent to TopMenu observation")
    for scalar in range(5):
        if ("bsman->field12c_write_scalar_addr[%d]" % scalar) not in \
                writer[live_record:topmenu_owner_done]:
            fail("T18.1 live result is missing field_12C scalar %d" % scalar)
    window_complete = writer.find(
        "[checkpoint] slide_observation_window_complete")
    final_checkpoint_flush = writer.find(
        "zeroCtrlWriteSlideCheckpoints(&written);", window_complete)
    capture_begin = writer.find(
        "[checkpoint] final_partition_capture_begin", window_complete)
    capture_call = writer.find(
        "zeroCtrlDiagnosticsCapturePartitions(&slide_diag.delayed_or_timeout)",
        capture_begin)
    capture_end = writer.find(
        "[checkpoint] final_partition_capture_end", capture_call)
    if min(window_complete, final_checkpoint_flush, capture_begin,
            capture_call, capture_end) < 0 or not (
            window_complete < final_checkpoint_flush < capture_begin <
            capture_call < capture_end):
        fail("T18.1 finalization checkpoints do not localize the final boundary")
    if "#define SLIDE_OBSERVATION_WINDOW_US 12000000" not in kernel:
        fail("T18.1 changed the 12-second observation window")
    case14_install = kernel[kernel.find(
        "static void zeroCtrlInstallCase14Trace"):
        kernel.find("static void zeroCtrlInstallDispatchEntryTrace(void) {")]
    for token in ("model != 0", "sceKernelDevkitVersion() != 0x06060110",
            "vsh->text_addr + 0x1D7A4", "vsh->text_addr + 0x4FDA0",
            "table + 14 * 4", "vsh->text_addr + 0x1DE18",
            "_lw(entry) != natural", "case14_validation = 1",
            "_sw(word, entry)", "case14_install = 1",
            "case14_cache_sync = 1"):
        if token not in case14_install:
            fail("T19 case-14 transaction is missing " + token)
    case14_commit = case14_install.find("_sw(word, entry)")
    case14_validation = case14_install.find("case14_validation = 1")
    if case14_commit <= case14_validation or \
            case14_install.count("_sw(word, entry)") != 1:
        fail("T19 does not transactionally patch exactly jump-table entry 14")
    if any(token in case14_install[:case14_commit] for token in
            ("_sw(word, entry)", "_sw(bsman->case14_leaf_addr, entry)")):
        fail("T19 writes the VSH jump table before validation completes")
    if "sceKernelDcacheWritebackInvalidateRange((const void *)entry, 4)" not in \
            case14_install or "sceKernelIcache" in case14_install:
        fail("T19 does not narrowly synchronize its single data word")
    if "sceKernelCreateThread" in case14_install or \
            "0x6F84" in case14_install:
        fail("T19 creates a thread or enables the broad predicate")
    case14_stub = assembly[assembly.find("zeroCtrlCase14Trace:"):
        assembly.find("zeroCtrlCase14TraceEnd:")]
    if not case14_stub or \
            "sw      $ra, %lo(zeroCtrlCase14FirstRA)" not in case14_stub or \
            "sw      $ra, %lo(zeroCtrlCase14LastRA)" not in case14_stub or \
            "lw      $t2, %lo(zeroCtrlCase14Resume)" not in case14_stub or \
            "jr      $t2" not in case14_stub or \
            "lw      $t2, -4($sp)" not in case14_stub:
        fail("T19 helper does not preserve RA/registers and natural continuation")
    if any(token in case14_stub for token in
            ("jal ", "jalr", "sceIo", "Alloc", "malloc", "sceKernel")):
        fail("T19 helper calls code, performs I/O, or allocates")
    if re.search(r"\b(?:li|addiu|ori|lw|move|addu)\s+\$(?:s3|ra)\b",
            case14_stub):
        fail("T19 helper modifies Sony's s3 argument or caller RA")
    case14_install_record = writer.find("[topmenu-case14-install]")
    case14_live_record = writer.find("[topmenu-case14-live]")
    if min(case14_install_record, case14_live_record) < 0 or not (
            live_record < case14_live_record < topmenu_owner_done):
        fail("T19 records are missing or not at the T18.1 live boundary")
    for scalar in range(4):
        if ("bsman->case14_scalar_addr[%d]" % scalar) not in \
                writer[case14_live_record:topmenu_owner_done]:
            fail("T19 live result is missing case-14 scalar %d" % scalar)
    dispatch_install = kernel[kernel.find(
        "static void zeroCtrlInstallDispatchEntryTrace(void) {"):
        kernel.find("static void zeroCtrlInstall6F84ConsumerTraces(void) {")]
    for token in ("model != 0", "sceKernelDevkitVersion() != 0x06060110",
            "vsh->text_size != 0x556C0", "vsh->text_addr + 0x1D7A4",
            "_lw(site) != 0x27BDFFC0", "_lw(site + 4) != 0xAFB20018",
            "_lw(site + 0x24) != 0x9062019D",
            "_lw(site + 0x28) != 0x1440003D", "resume = site + 8",
            "dispatch_entry_validation = 1", "_sw(replacement, site)",
            "_sw(0, site + 4)", "dispatch_entry_install = 1",
            "dispatch_entry_cache_sync = 1"):
        if token not in dispatch_install:
            fail("T20 dispatcher-entry transaction is missing " + token)
    dispatch_commit = dispatch_install.find("_sw(replacement, site)")
    dispatch_validation = dispatch_install.find("dispatch_entry_validation = 1")
    if dispatch_commit <= dispatch_validation or \
            dispatch_install.count("_sw(replacement, site)") != 1:
        fail("T20 writes VSH before complete dispatcher validation")
    if dispatch_install.count("_sw(0, site + 4)") != 1 or \
            "(const void *)site, 8" not in dispatch_install:
        fail("T20 does not replace and synchronize exactly two entry words")
    if "sceKernelCreateThread" in dispatch_install or \
            "0x6F84" in dispatch_install:
        fail("T20 creates a thread or changes the broad predicate")
    dispatch_stub = assembly[assembly.find("zeroCtrlDispatchEntryTrace:"):
        assembly.find("zeroCtrlDispatchEntryTraceEnd:")]
    for token in ("bne     $a0, $t2", "sw      $ra, %lo(zeroCtrlDispatchCase14FirstRA)",
            "sw      $ra, %lo(zeroCtrlDispatchCase14LastRA)",
            "addiu   $sp, $sp, -0x40", "sw      $s2, 0x18($sp)",
            "lw      $t2, %lo(zeroCtrlDispatchEntryResume)",
            "jr      $t2", "lw      $t2, 0x3C($sp)"):
        if token not in dispatch_stub:
            fail("T20 helper does not preserve displaced entry behavior: " + token)
    dispatch_stack_sequence = (
        "addiu   $sp, $sp, -12\n"
        "    sw      $t0, 0($sp)\n"
        "    sw      $t1, 4($sp)\n"
        "    sw      $t2, 8($sp)")
    dispatch_restore_sequence = (
        "lw      $t1, 4($sp)\n"
        "    lw      $t0, 0($sp)\n"
        "    addiu   $sp, $sp, 12\n"
        "    addiu   $sp, $sp, -0x40\n"
        "    sw      $s2, 0x18($sp)\n"
        "    jr      $t2\n"
        "    lw      $t2, 0x3C($sp)")
    if dispatch_stack_sequence not in dispatch_stub or \
            dispatch_restore_sequence not in dispatch_stub or \
            "lw      $t2, 0x24($sp)" in dispatch_stub:
        fail("T20 stack proof must restore S-4 as (S-0x40)+0x3C")
    if any(token in dispatch_stub for token in
            ("jal ", "jalr", "sceIo", "Alloc", "malloc", "sceKernel")):
        fail("T20 helper calls code, performs I/O, or allocates")
    if re.search(r"\b(?:li|addiu|ori|lw|move|addu)\s+\$(?:a0|ra|s2|s3)\b",
            dispatch_stub):
        fail("T20 helper modifies Sony argument or preserved registers")
    if any(token in dispatch_stub for token in ("0x19D", "0x12C")):
        fail("T20 helper accesses Sony context state")
    dispatch_install_record = writer.find("[topmenu-dispatch-entry-install]")
    dispatch_live_record = writer.find("[topmenu-dispatch-entry-live]")
    if min(dispatch_install_record, dispatch_live_record) < 0 or not (
            case14_live_record < dispatch_live_record < topmenu_owner_done):
        fail("T20 records are missing or not at the existing live boundary")
    for scalar in range(5):
        if ("bsman->dispatch_entry_scalar_addr[%d]" % scalar) not in \
                writer[dispatch_live_record:topmenu_owner_done]:
            fail("T20 live result is missing dispatcher scalar %d" % scalar)
    idempotent_guard = dispatch_install.find(
        "if (bsman->dispatch_entry_install) return;")
    counter_clear = dispatch_install.find(
        "_sw(0, bsman->dispatch_entry_scalar_addr[i])")
    if idempotent_guard < 0 or counter_clear <= idempotent_guard:
        fail("T21 later T20 invocation can clear an existing early trace")
    vsh_record = kernel[kernel.find("void zeroCtrlRecordVshSlideTarget("):
        kernel.find("int (*msIoOpen)")]
    early_call = vsh_record.find("zeroCtrlInstallDispatchEntryTrace();")
    original_scan = vsh_record.find("zeroCtrlScanVshStateTarget(")
    selected_commit = vsh_record.find(
        "Commit pass: selected callsites are all valid or none are written.")
    global_capture = vsh_record.rfind(
        "if (slide_diag.global_predicate_enabled)", 0, early_call)
    if min(early_call, original_scan, selected_commit, global_capture) < 0 or \
            not (original_scan < selected_commit < global_capture < early_call):
        fail("T21 early install does not follow original VSH scans and setup")
    if vsh_record.count("zeroCtrlInstallDispatchEntryTrace();") != 1 or \
            "zeroCtrlInstallField12CWriteTrace();" in vsh_record or \
            "zeroCtrlInstallCase14Trace();" in vsh_record:
        fail("T21 moves T18/T19 early or creates another dispatcher install")
    user_onstart = user[user.find("int OnModuleStart(SceModule2 *mod)"):
        user.find("int module_start", user.find("int OnModuleStart(SceModule2 *mod)"))]
    if user_onstart.find('strcmp(mod->modname, "vsh_module")') < 0 or \
            user_onstart.find("zeroCtrlRecordVshSlideTarget(") < 0:
        fail("T21 is not reached from the existing early VSH observation")
    bsman_install = kernel[kernel.find("static void zeroCtrlInstallBSManClosedShim"):
        kernel.find("int OnModuleStart(SceModule2 *mod)")]
    pre_slide = bsman_install.find(
        "bsman->dispatch_entry_pre_slide[snapshot_index]")
    t18_later = bsman_install.find("zeroCtrlInstallField12CWriteTrace();")
    t19_later = bsman_install.find("zeroCtrlInstallCase14Trace();")
    t20_later = bsman_install.find("zeroCtrlInstallDispatchEntryTrace();")
    if min(pre_slide, t18_later, t19_later, t20_later) < 0 or not (
            pre_slide < t18_later < t19_later < t20_later):
        fail("T21 pre-slide snapshot is not before the unchanged later installers")
    if assembly.count("zeroCtrlDispatchEntryTrace:") != 1:
        fail("T21 adds or removes the existing T20 dispatcher helper")
    early_record = writer.find("[topmenu-dispatch-entry-early-install]")
    pre_slide_record = writer.find("[topmenu-dispatch-entry-pre-slide]")
    if min(early_record, pre_slide_record) < 0:
        fail("T21 early-install or pre-slide diagnostics are missing")
    for scalar in range(5):
        if ("bsman->dispatch_entry_pre_slide[%d]" % scalar) not in \
                writer[pre_slide_record:install_record]:
            fail("T21 pre-slide record is missing snapshot scalar %d" % scalar)
    consumers_install = kernel[kernel.find(
        "static void zeroCtrlInstall6F84ConsumerTraces(void) {"):
        kernel.find("static void zeroCtrlInstallBSManClosedShim")]
    for token in ("0x13F6C, 0x14020", "0x00000000, 0x0062800B",
            "vsh->text_addr + 0x6F84",
            "consumer_callsite_words[i][1] != delays[i]",
            "consumer_callsite_target[i] != target",
            "replacement[i] = 0x0C000000", "_sw(replacement[i], callsite[i])",
            "(const void *)callsite[i], 4", "shared_global_early_valid = 1",
            "_lw(slide_diag.vsh_shared_global_addr)"):
        if token not in consumers_install:
            fail("T22 consumer transaction is missing " + token)
    validation = consumers_install.find("consumer_validation[i] = 1")
    consumer_commit = consumers_install.find("_sw(replacement[i], callsite[i])")
    if validation < 0 or consumer_commit <= validation or \
            consumers_install.count("_sw(replacement[i], callsite[i])") != 1:
        fail("T22 consumer JAL writes are not transactional")
    if re.search(r"_sw\([^\n]*callsite\[i\]\s*\+\s*4", consumers_install):
        fail("T22 modifies a consumer delay slot")
    for word in ("0x2483FFFC", "0x38820007",
            "0x2C630002", "0x2C420001", "0x00621825", "0x14600006",
            "0x50820001", "0x03E00008", "0x30A200FF"):
        if word not in consumers_install:
            fail("T22 does not validate natural +6F84 word " + word)
    decode_helper = kernel[kernel.find(
        "static unsigned int zeroCtrlDecodeLuiSignedLowAddress"):
        kernel.find("static void zeroCtrlDeriveVshSharedGlobal")]
    if "int displacement = (short)(low_instruction & 0xFFFF)" not in \
            decode_helper or \
            "((lui & 0xFFFF) << 16) + (unsigned int)displacement" not in \
            decode_helper:
        fail("T22.3 shared LUI/LO16 decoder lost signed-low semantics")
    derive = kernel[kernel.find("static void zeroCtrlDeriveVshSharedGlobal"):
        kernel.find("static int zeroCtrlVshModuleRangeValid")]
    if "zeroCtrlDecodeLuiSignedLowAddress(lui, access)" not in derive or \
            "zeroCtrlDecodeLuiSignedLowAddress(" not in consumers_install:
        fail("T22.3 does not share address decoding with original derivation")
    if "(_lw(target + 4) & 0xFFFF0000) != 0x8C440000" not in \
            consumers_install or \
            "predicate_global != slide_diag.vsh_shared_global_addr" not in \
            consumers_install:
        fail("T22.3 does not validate LW structure and effective address")
    if "consumer_predicate_decoded_addr = predicate_global" not in \
            consumers_install or "decoded=0x%08X" not in writer:
        fail("T22.3 address mismatch diagnostics omit the decoded runtime address")
    if re.search(r"_lw\(target \+ 4\)\s*(!=|==)\s*0x8C441620",
            consumers_install):
        fail("T22.3 reintroduced the pre-relocation LW immediate")
    for guard in ("if (!slide_diag.vsh_shared_global_decode_valid)",
            "if (!slide_diag.vsh_shared_global_segment_valid)",
            "zeroCtrlVshModuleRangeValid(vsh, slide_diag.vsh_shared_global_addr, 4)"):
        if guard not in consumers_install:
            fail("T22.3 removed required shared-global guard " + guard)
    consumer_stub = assembly[assembly.find(".macro CONSUMER_6F84_TRACE"):
        assembly.find(".endm", assembly.find(".macro CONSUMER_6F84_TRACE"))]
    for token in ("sw      $t0, 0($sp)", "sw      $t1, 4($sp)",
            "sw      $t2, 8($sp)", "lw      $t2, %lo(zeroCtrlConsumer6F84Target)",
            "lw      $t1, 4($sp)", "lw      $t0, 0($sp)",
            "addiu   $sp, $sp, 12", "jr      $t2", "lw      $t2, -4($sp)"):
        if token not in consumer_stub:
            fail("T22 wrapper transparency is missing " + token)
    if any(token in consumer_stub for token in
            ("jal ", "jalr", "$ra", "$v0", "sceIo", "Alloc", "malloc")):
        fail("T22 wrapper calls, changes RA/v0, performs I/O, or allocates")
    if assembly.count("CONSUMER_6F84_TRACE zeroCtrlConsumer") != 2:
        fail("T22 must use exactly two dedicated consumer wrappers")
    if "sceKernelCreateThread" in consumers_install or \
            re.search(r"_sw\([^\n]*vsh_shared_global", consumers_install):
        fail("T22 creates a thread or writes the Sony shared global")
    consumer_early = vsh_record.find("zeroCtrlInstall6F84ConsumerTraces();")
    if consumer_early < global_capture or consumer_early > early_call:
        fail("T22 traces are not installed after scans and before early T20")
    consumer_snapshot = bsman_install.find("consumer_pre_slide_hits[0]")
    if consumer_snapshot < 0 or consumer_snapshot > t18_later:
        fail("T22 pre-slide snapshot is not before later trace installation")
    if writer.find("[vsh-6f84-consumers-install]") < 0 or \
            writer.find("[vsh-6f84-consumers-pre-slide]") < 0:
        fail("T22 deferred consumer diagnostics are missing")
    guard_reasons = (
        "MODEL_MISMATCH", "DEVKIT_MISMATCH", "VSH_NOT_FOUND",
        "HELPER_NOT_FOUND", "VSH_TEXT_SIZE_MISMATCH",
        "SHARED_GLOBAL_DECODE_INVALID", "SHARED_GLOBAL_SEGMENT_INVALID",
        "PREDICATE_RANGE_INVALID", "SHARED_GLOBAL_RANGE_INVALID",
        "TARGET_SCALAR_RANGE_INVALID", "PREDICATE_FINGERPRINT_MISMATCH",
        "CALLSITE_13F6C_RANGE_INVALID", "CALLSITE_13F6C_HELPER_RANGE_INVALID",
        "CALLSITE_13F6C_COUNTER_RANGE_INVALID", "CALLSITE_13F6C_NOT_JAL",
        "CALLSITE_13F6C_TARGET_MISMATCH", "CALLSITE_13F6C_DELAY_MISMATCH",
        "CALLSITE_13F6C_PSEUDODIRECT_RANGE_INVALID",
        "CALLSITE_14020_RANGE_INVALID", "CALLSITE_14020_HELPER_RANGE_INVALID",
        "CALLSITE_14020_COUNTER_RANGE_INVALID", "CALLSITE_14020_NOT_JAL",
        "CALLSITE_14020_TARGET_MISMATCH", "CALLSITE_14020_DELAY_MISMATCH",
        "CALLSITE_14020_PSEUDODIRECT_RANGE_INVALID",
        "REPLACEMENT_TARGET_MISMATCH",
    )
    for reason in guard_reasons:
        if "ZERO_CONSUMER_GUARD_" + reason not in consumers_install:
            fail("T22.2 installer does not record guard " + reason)
    if consumers_install.count("return;") != 1 or \
            "#define CONSUMER_GUARD_FAIL(value)" not in consumers_install:
        fail("T22.2 has a consumer failure return outside the reason macro")
    guard_success = consumers_install.find(
        "consumer_guard_reason = ZERO_CONSUMER_GUARD_NONE")
    validation = consumers_install.find("consumer_validation[i] = 1")
    consumer_commit = consumers_install.find("_sw(replacement[i], callsite[i])")
    if min(guard_success, validation, consumer_commit) < 0 or not (
            guard_success < validation < consumer_commit):
        fail("T22.2 success or VSH commit precedes complete guard validation")
    if "_sw(replacement[i], callsite[i])" in consumers_install[:guard_success]:
        fail("T22.2 writes a VSH callsite on a guard failure")
    if "consumer_segment_count = vsh->nsegment < 4 ? vsh->nsegment : 4" not in \
            consumers_install or \
            "i < bsman->consumer_segment_count" not in consumers_install:
        fail("T22.2 VSH segment capture is not bounded to four entries")
    if "consumer_predicate_words[16]" not in kernel or \
            consumers_install.count("i < 16") != 2:
        fail("T22.2 predicate capture/validation is not bounded to 16 words")
    if consumers_install.count("i < 2") < 4:
        fail("T22.2 callsite/helper capture is not bounded to two consumers")
    for record in ("[vsh-6f84-consumers-guard]", "[vsh-6f84-segment]",
            "[vsh-6f84-callsite]", "[vsh-6f84-predicate]",
            "[vsh-6f84-helper]"):
        if writer.find(record) < 0:
            fail("T22.2 diagnostic record is missing " + record)
    if "i < bsman->consumer_segment_count && i < 4" not in writer:
        fail("T22.2 diagnostic segment iteration is not capped at four")
    if "PSP1000PafPresentCompat = Disabled" not in sample_config:
        fail("callsite PAF compatibility experiment is not default-disabled")
    stub_validation = bsman.find("bsman->stub_form =")
    caller_proof = bsman.find("Runtime caller proof:")
    if stub_validation < 0 or caller_proof <= stub_validation or \
            "caller_matches != 1" not in bsman[caller_proof:]:
        fail("BSMan caller proof no longer follows stub-form validation")
    bsman_commit = bsman.find(
        "Transaction commit: no BSMan code write occurs before every check.")
    if bsman_commit < 0:
        fail("BSMan transaction commit marker is missing")
    if "_sw(bsman->replacement_words" in bsman[:bsman_commit]:
        fail("BSMan code is written before validation completes")
    commit = bsman[bsman_commit:]
    if commit.count("_sw(bsman->replacement_words") != 2:
        fail("BSMan transaction does not write exactly two intended words")
    if "sceKernelDcacheWritebackInvalidateRange(\n            (const void *)bsman->import_stub_addr, 8)" not in commit or \
            "sceKernelIcacheInvalidateRange((const void *)bsman->import_stub_addr, 8)" not in commit:
        fail("BSMan transaction does not narrowly synchronize eight bytes")
    if "_sw(vshbridge_stub, bsman->post_vsh_target_addr)" not in bsman:
        fail("post-BSMan trace does not retain the natural VshBridge target")
    if "_sw(prefix_paf_stub, bsman->prefix_paf_target_addr)" not in bsman:
        fail("activation prefix trace does not retain the natural PAF target")
    if "bsman->caller_addr != bsman->activation_addr + 0xA8" not in bsman:
        fail("post-BSMan trace is not tied to the validated BSMan caller")
    if "(bsman->post_original[1] & 0xFFFF0000) != 0x92620000" not in bsman:
        fail("runtime BSMan delay slot is not structurally validated as LBU v0(s3)")
    if re.search(r"_sw\([^;\n]*bsman->activation_addr \+ 0xB4", bsman):
        fail("runtime BSMan LBU delay slot is overwritten")
    for sync in (
            "(const void *)(bsman->activation_addr + 0xB0), 4",):
        if bsman.count(sync) != 2:
            fail("post-BSMan branch patch does not narrowly synchronize one word")
    for required in (
            "_sw(bsman->activation_addr + 0xDC, bsman->post_bs_target_addr[0])",
            "_sw(bsman->activation_addr + 0xB8, bsman->post_bs_target_addr[1])"):
        if required not in bsman:
            fail("post-BSMan natural branch destination is missing " + required)
    validation_marker = "Validation pass: no VSH write may occur in this loop."
    commit_marker = "Commit pass: selected callsites are all valid or none are written."
    validation_start = kernel.find(validation_marker)
    commit_start = kernel.find(commit_marker)
    if validation_start < 0 or commit_start <= validation_start:
        fail("transactional validation/commit passes are missing or reordered")
    if "_sw(" in kernel[validation_start:commit_start]:
        fail("combined trigger path writes before all validations complete")
    if kernel.count("_sw(evidence->replacement_word, evidence->callsite)") != 1:
        fail("selective framework must have exactly one VSH write primitive")
    if "if (all_selected_valid)" not in kernel[commit_start:]:
        fail("selective commit pass is not gated by aggregate validation")
    global_marker = "Dangerous global predicate block: never edits direct callers."
    global_start = kernel.find(global_marker)
    global_end = kernel.find("slide_diag.vsh_module_seen = 1", global_start)
    if global_start < 0 or global_end <= global_start:
        fail("controlled global predicate patch block is missing")
    global_block = kernel[global_start:global_end]
    if "0x8C44DAE0" in global_block:
        fail("global predicate validation uses a relocation-specific LW word")
    for required in (
        "(lui >> 26) == 0x0F",
        "(load >> 26) == 0x23",
        "global->decoded_global_addr",
        "slide_diag.vsh_shared_global_addr",
        "0x56CE0",
    ):
        if required not in global_block:
            fail("global predicate semantic validation is missing " + required)
    if global_block.count("_sw(global->replacement_words") != 2:
        fail("global predicate mode must write exactly its two entry words")
    if "vsh_trigger_offsets" in global_block or "evidence->callsite" in global_block:
        fail("global predicate mode modifies a selective direct caller")
    if 'strcmp(psp1000SlideTriggerMode,\n\t\t\t\t"DangerousGlobalPredicate6F84") == 0' not in kernel:
        fail("global predicate patch is not gated by its exact dangerous mode")
    if "!slide_diag.global_predicate_enabled ?" not in kernel:
        fail("global predicate mode does not disable selective caller modes")
    if "global_predicate_6f84_patch=disabled" not in kernel:
        fail("global PSP Go predicate patch is not explicitly disabled")
    if "% 64" not in build:
        fail("embedded helper ELF alignment check is missing")
    for required in (
        'strcmp(psp1000SonyStartTrace, "Enabled") == 0',
        '"DangerousCaller58D4") == 0',
        'strcmp(psp1000Diagnostics, "Enabled") == 0',
        'strcmp(useSlide, "Disabled") == 0',
        '(trace->entry_original[2] >> 26) != 0x2B',
    ):
        if required not in kernel:
            fail("Sony start trace safety gate is missing " + required)
    entry_start = assembly.find(SONY_ENTRY_STUB + ":")
    entry_end = assembly.find(SONY_ENTRY_STUB_END + ":", entry_start)
    exit_start = assembly.find(SONY_EXIT_STUB + ":")
    exit_end = assembly.find(SONY_EXIT_STUB_END + ":", exit_start)
    if min(entry_start, entry_end, exit_start, exit_end) < 0:
        fail("Sony direct start trace assembly stubs are missing")
    entry = assembly[entry_start:entry_end]
    exit_stub = assembly[exit_start:exit_end]
    trace_end = assembly.find(".end " + SONY_EXIT_STUB, exit_start)
    trace_end += len(".end " + SONY_EXIT_STUB)
    trace_block = assembly[entry_start:trace_end]
    if hashlib.sha256(trace_block.encode()).hexdigest() != \
            SONY_TRACE_BASELINE_SHA256:
        fail("hardware-validated Sony saved-RA assembly changed")
    if any(token in entry + exit_stub for token in
            ("zeroCtrlDiagnostics", "sceIo", "$gp", "jal ", "jalr")):
        fail("Sony direct start trace stubs use logging, gp, or calls")
    if re.search(r"\$(?:a0|a1)\s*,", entry + exit_stub):
        fail("Sony direct start trace stubs modify original arguments")
    for displaced in ("addiu   $sp, $sp, -16", "sw      $s0, 0($sp)"):
        if displaced not in entry:
            fail("entry trace does not reproduce displaced instruction " + displaced)
    if "jr      $t9" not in entry or "jr      $t9" not in exit_stub:
        fail("Sony RA trace stubs do not resume through validated addresses")
    save_ra = entry.find("sw      $ra, %lo(zeroCtrlSonyModuleStartCallerRA)")
    replace_ra = entry.find("lui     $ra, %hi(zeroCtrlSonyModuleStartExitTrace)")
    if save_ra < 0 or replace_ra <= save_ra:
        fail("Sony entry trace does not save caller ra before interposition")
    if "lw      $t9, %lo(zeroCtrlSonyModuleStartCallerRA)" not in exit_stub:
        fail("Sony exit trace does not resume at the saved caller ra")
    if "sw      $v0, %lo(zeroCtrlSonyModuleStartResult)" not in exit_stub:
        fail("Sony exit trace does not preserve the original result")
    if re.search(r"(?:addiu|addu|or|move|li)\s+\$v0", exit_stub):
        fail("Sony exit trace replaces the original result")
    bsman_leaf_start = assembly.find(BSMAN_STUB + ":")
    bsman_leaf_end = assembly.find(BSMAN_STUB_END + ":", bsman_leaf_start)
    if bsman_leaf_start < 0 or bsman_leaf_end <= bsman_leaf_start:
        fail("BSMan assembly leaf is missing")
    bsman_leaf = assembly[bsman_leaf_start:bsman_leaf_end]
    if any(token in bsman_leaf for token in
            ("$gp", "$sp", "jal ", "jalr", "sceIo", "Alloc", "malloc")):
        fail("BSMan leaf uses gp, stack, calls, I/O, or allocation")
    if "CREATE_TRIGGER_STUB" in bsman_leaf or \
            "addu    $v0, $zero, $zero" not in bsman_leaf or \
            "jr      $ra" not in bsman_leaf:
        fail("BSMan leaf does not deterministically return CLOSED=0")
    transaction = kernel.find("Transaction commit: the complete entry interposition")
    install_end = kernel.find("trace->install = 1", transaction)
    if transaction < 0 or install_end <= transaction:
        fail("Sony direct trace transactional commit is missing")
    if kernel[:transaction].count("_sw(trace->entry_replacement") != 0:
        fail("Sony RA trace writes entry code before all validation completes")
    commit = kernel[transaction:install_end]
    if commit.count("_sw(trace->entry_replacement") != 2:
        fail("Sony RA trace does not commit exactly two entry words")
    if "return_replacement" in kernel or "return_addr" in kernel:
        fail("obsolete Sony return-site patching remains enabled")
    if "sceKernelDcacheWritebackInvalidateRange((const void *)start, 8)" not in commit or \
            "sceKernelIcacheInvalidateRange((const void *)start, 8)" not in commit:
        fail("Sony RA trace does not synchronize exactly its 8-byte entry patch")
    if commit.count("sceKernelDcacheWritebackInvalidateRange") != 1 or \
            commit.count("sceKernelIcacheInvalidateRange") != 1:
        fail("Sony RA trace performs unexpected code-cache synchronization")
    if "mod->module_start_func =" in kernel:
        fail("Sony start trace still relies on metadata-pointer redirection")
    register_start = kernel.find("void zeroCtrlRegisterSonyStartTrace(")
    register_end = kernel.find("void zeroCtrlRecordVshSlideTarget(", register_start)
    installer_start = kernel.find("static void zeroCtrlInstallSonyStartTrace(")
    installer_end = kernel.find("int OnModuleStart(", installer_start)
    if min(register_start, register_end, installer_start, installer_end) < 0:
        fail("Sony registration/installer diagnostic functions are missing")
    register = kernel[register_start:register_end]
    installer = kernel[installer_start:installer_end]
    if any(token in register + installer for token in
            ("zeroCtrlDiagnosticsText", "sceIoOpen", "sceIoWrite")):
        fail("Sony registration diagnostics perform loader-sensitive file I/O")
    if register.count("trace->registered = 1") != 1 or \
            register.find("trace->registration_success = 1") > \
            register.find("trace->registered = 1"):
        fail("Sony registration success does not exclusively gate registered=1")
    if "const ZeroCtrlSonyStartTraceRegistration *registration" not in register:
        fail("Sony trace registration does not use the one-pointer ABI")
    if re.search(r"zeroCtrlRegisterSonyStartTrace\s*\(\s*unsigned int", kernel + user):
        fail("obsolete scalar Sony trace registration ABI remains")
    descriptor_fields = (
        "entry_addr", "entry_end_addr", "exit_addr", "exit_end_addr",
        "resume_slot_addr", "caller_ra_slot_addr", "entry_seen_addr",
        "return_seen_addr", "result_addr",
    )
    for field in descriptor_fields:
        if not re.search(r"\bu32\s+" + field + r"\s*;", registration_header):
            fail("Sony trace descriptor lacks 32-bit field " + field)
    if "sizeof(ZeroCtrlSonyStartTraceRegistration) == 36" not in registration_header:
        fail("Sony trace registration descriptor is not asserted to 36 bytes")
    if "zeroCtrlRegisterSonyStartTrace(&sonyStartTraceRegistration);" not in user:
        fail("user helper does not pass one Sony trace descriptor pointer")
    descriptor_check = register.find(
        "zeroCtrlVshModuleRangeValid(helper, descriptor_addr,")
    descriptor_copy = register.find("memcpy(&copied, registration, sizeof(copied))")
    first_copied_field = register.find("copied.entry_addr")
    if descriptor_check < 0 or descriptor_copy <= descriptor_check or \
            first_copied_field <= descriptor_copy:
        fail("Sony descriptor is read before its complete helper range is validated")
    if "SONY_START_REGISTER_DESCRIPTOR_OUT_OF_RANGE" not in register or \
            "SONY_START_REGISTER_DESCRIPTOR_NULL" not in register:
        fail("Sony registration lacks descriptor pointer failure evidence")
    for reason in (
        "HELPER_NOT_FOUND", "ENTRY_END_ORDER", "EXIT_END_ORDER",
        "ENTRY_STUB_TOO_LARGE", "EXIT_STUB_TOO_LARGE",
        "ENTRY_STUB_OUT_OF_RANGE", "EXIT_STUB_OUT_OF_RANGE",
        "RESUME_SLOT_OUT_OF_RANGE", "CALLER_RA_SLOT_OUT_OF_RANGE",
        "ENTRY_FLAG_OUT_OF_RANGE", "RETURN_FLAG_OUT_OF_RANGE",
        "RESULT_SLOT_OUT_OF_RANGE", "ENTRY_MISALIGNED", "EXIT_MISALIGNED",
    ):
        if "SONY_START_REGISTER_" + reason not in register:
            fail("Sony registration lost validation reason " + reason)
    for reason in ("TRACE_DISABLED", "TRACE_NOT_REGISTERED", "MODEL_MISMATCH",
            "NULL_MODULE", "MODULE_NAME_MISMATCH", "DEVKIT_MISMATCH",
            "TEXT_TOO_SMALL", "ADDRESS_OVERFLOW"):
        if "SONY_START_GUARD_" + reason not in installer:
            fail("Sony installer lost initial guard reason " + reason)
    for stub, counter in zip(STUBS, COUNTERS):
        invocation = "CREATE_TRIGGER_STUB " + stub + ", " + counter
        if invocation not in assembly:
            fail(stub + " does not reference its dedicated counter")
    if "addiu   $v0, $zero, 1" not in assembly:
        fail("trigger stubs do not return strict boolean 1")
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".c", ".h", ".S", ".sh"}:
            text = path.read_text(errors="ignore")
            if re.search(r'sceIo(?:Write|Remove|Rename|Mkdir).*flash0:', text):
                fail("forbidden flash0 write operation in " + str(path))

    # Unit-check the same pseudo-direct reconstruction used on target.
    for pc in (0x088058D4, 0x08813F6C, 0x089FFFFC):
        target = 0x08806F84
        word = 0x0C000000 | ((target >> 2) & 0x03FFFFFF)
        rebuilt = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        if rebuilt != target:
            fail("JAL semantic reconstruction self-test failed")

    # Hardware-style relocation variants of LUI v0 / LW a0,disp(v0).
    for lui, load, expected in (
        (0x3C0209C8, 0x8C44D7E0, 0x09C7D7E0),
        (0x3C0209C8, 0x8C44D9E0, 0x09C7D9E0),
        (0x3C0209C8, 0x8C44DAE0, 0x09C7DAE0),
    ):
        if lui >> 26 != 0x0F or (lui >> 16) & 0x1F != 2:
            fail("global predicate LUI semantic self-test failed")
        if load >> 26 != 0x23 or (load >> 21) & 0x1F != 2:
            fail("global predicate LW base semantic self-test failed")
        if (load >> 16) & 0x1F != 4:
            fail("global predicate LW destination semantic self-test failed")
        displacement = load & 0xFFFF
        if displacement & 0x8000:
            displacement -= 0x10000
        effective = ((lui & 0xFFFF) << 16) + displacement
        if effective != expected:
            fail("global predicate effective-address self-test failed")


def function_body(disassembly, symbol):
    start = disassembly.find("<" + symbol + ">:")
    end = disassembly.find("\n\n", start)
    if start < 0:
        fail("cannot disassemble " + symbol)
    return disassembly[start:end if end >= 0 else None]


def require_only_natural_result_stores(body, symbol, expected_count):
    """Require every instruction use of v0 to be one untouched-result store."""
    v0_lines = [line for line in body.splitlines()
                if re.search(r"\bv0\b", line)]
    if len(v0_lines) != expected_count or any(
            not re.search(r"\bsw\s+v0,", line) for line in v0_lines):
        fail(symbol + " uses v0 other than for the expected natural-result stores")


def require_result_store_relocation(body, function, result_symbol):
    """Tie a natural-result SW to the exact fixed slot in the relocatable object."""
    if len(re.findall(r"R_MIPS_HI16\s+" + result_symbol + r"\b", body)) != 1:
        fail(function + " lacks the unique HI16 relocation for " + result_symbol)
    store_relocation = (r"\bsw\s+v0,[^\n]*\n"
                        r"[^\n]*R_MIPS_LO16\s+" + result_symbol + r"\b")
    if len(re.findall(store_relocation, body)) != 1:
        fail(function + " does not store v0 to " + result_symbol)


def check_t22_consumer_semantics(body, symbol):
    """Prove the assembled T22 wrapper preserves the caller and natural result."""
    forbidden = r"\b(?:at|v[01]|a[0-3]|t[3-9]|s[0-7]|k[01]|gp|fp|ra)\b"
    if re.search(forbidden, body) or re.search(r"\bjalr?\b", body):
        fail(symbol + " uses a forbidden register or function call")
    ordered = (
        r"\baddiu\s+sp,\s*sp,\s*-12\b",
        r"\bsw\s+t0,\s*0\(sp\)",
        r"\bsw\s+t1,\s*4\(sp\)",
        r"\bsw\s+t2,\s*8\(sp\)",
        r"\blui\s+t0,",
        r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b",
        r"\bsw\s+t1,",
        r"\blui\s+t0,",
        r"\blw\s+t2,",
        r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)",
        r"\baddiu\s+sp,\s*sp,\s*12\b",
        r"\bjr\s+t2\b",
        r"\blw\s+t2,\s*-4\(sp\)",
    )
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered transparent operation " + pattern)
        cursor += match.end()
    if len(re.findall(r"\baddiu\s+sp,\s*sp,", body)) != 2 or \
            len(re.findall(r"\bjr\s+t2\b", body)) != 1:
        fail(symbol + " has unexpected stack adjustment or control transfer")
    if len(re.findall(r"\blw\s+", body)) != 5 or \
            len(re.findall(r"\bsw\s+", body)) != 4:
        fail(symbol + " has unexpected memory accesses")
    if not re.search(r"\bjr\s+t2\b[^\n]*\n\s*[0-9a-f]+:\s+[^\n]*"
            r"\blw\s+t2,\s*-4\(sp\)", body, re.I):
        fail(symbol + " does not restore S-4 in the JR delay slot")


def check_post_bsman_branch_semantics(body, relocatable=False):
    """Verify transparent state capture followed by the saved BSMan decision."""
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b|sceIo|Alloc|malloc", body):
        fail("post-BSMan branch trace uses gp, sp, a call, I/O, or allocation")
    if re.search(r"\blbu\b", body):
        fail("post-BSMan branch trace reconstructs the relocated state load")

    v0_lines = [line for line in body.splitlines()
                if re.search(r"\$?v0\b", line)]
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+\$?v0,", v0_lines[0]):
        fail("post-BSMan branch trace does not only store the natural state v0")

    natural_store = re.search(r"\bsw\s+\$?v0,", body)
    effective_load = re.search(r"\blw\s+\$?t2,", body)
    decision = re.search(r"\bbeqz\s+\$?t2,", body)
    if not natural_store or not effective_load or not decision or not (
            natural_store.start() < effective_load.start() < decision.start()):
        fail("post-BSMan branch trace does not store state before the saved-result decision")

    if relocatable:
        require_result_store_relocation(body, "zeroCtrlPostBSManBranchTrace",
                "zeroCtrlPostStateNaturalValue")
        if len(re.findall(
                r"R_MIPS_HI16\s+zeroCtrlPostBSManEffectiveResult\b",
                body)) != 1 or not re.search(
                r"\blw\s+t2,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlPostBSManEffectiveResult\b", body):
            fail("post-BSMan branch trace does not load the effective-result slot")


def check_bsman_return_semantics(body, relocatable=False):
    """Verify the exact T14 post-call transformation, not a v0-use count."""
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b|sceIo|Alloc|malloc", body):
        fail("BSMan return trace uses gp, sp, a call, I/O, or allocation")

    patterns = (
        r"\bsw\s+v0,",                         # untouched natural result
        r"\blw\s+t1,",                         # dedicated mode
        r"\bbeqz\s+t1,",
        r"\blui\s+t2,\s*0x8002\b",
        r"\b(?:ori|addiu)\s+t2,\s*t2,\s*0x13a\b",
        r"\bbne\s+v0,\s*t2,",
        r"\b(?:move\s+v0,\s*zero|addu\s+v0,\s*zero,\s*zero)\b",
        r"\blw\s+t1,",                         # substitution counter
        r"\baddiu\s+t1,\s*t1,\s*1\b",
        r"\bsw\s+t1,",
        r"\bsw\s+v0,",                         # effective result
        r"\blw\s+ra,",
        r"\bjr\s+ra\b",
    )
    cursor = 0
    for pattern in patterns:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail("BSMan return trace lacks ordered T14 operation " + pattern)
        cursor += match.end()

    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    allowed_v0 = (
        r"\bsw\s+v0,",
        r"\bbne\s+v0,\s*t2,",
        r"\b(?:move\s+v0,\s*zero|addu\s+v0,\s*zero,\s*zero)\b",
    )
    if any(not any(re.search(pattern, line, re.I) for pattern in allowed_v0)
            for line in v0_lines):
        fail("BSMan return trace has an unintended v0 transformation")
    if sum(bool(re.search(allowed_v0[2], line, re.I)) for line in v0_lines) != 1:
        fail("BSMan return trace does not have exactly the intended v0=0 operation")

    if relocatable:
        require_result_store_relocation(body, BSMAN_RETURN_TRACE,
                "zeroCtrlPostBSManNaturalResult")
        require_result_store_relocation(body, BSMAN_RETURN_TRACE,
                "zeroCtrlPostBSManEffectiveResult")
        if len(re.findall(r"R_MIPS_HI16\s+zeroCtrlPostBSManCompatMode\b",
                          body)) != 1 or not re.search(
                r"\blw\s+t1,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlPostBSManCompatMode\b", body):
            fail("BSMan return trace does not load the dedicated compat mode")
        if len(re.findall(
                r"R_MIPS_HI16\s+zeroCtrlPostBSManSubstitutionHits\b",
                body)) != 1 or len(re.findall(
                r"R_MIPS_LO16\s+zeroCtrlPostBSManSubstitutionHits\b",
                body)) != 2:
            fail("BSMan return trace lacks exact substitution-counter relocations")


def check_elf(elf):
    nm = subprocess.check_output(["psp-nm", "-n", str(elf)], text=True)
    for symbol in STUBS:
        if not re.search(r"^[0-9a-fA-F]+\s+\w\s+" + symbol + r"$", nm, re.M):
            fail("missing helper trigger stub symbol " + symbol)
    for symbol in (SONY_ENTRY_STUB, SONY_ENTRY_STUB_END,
            SONY_EXIT_STUB, SONY_EXIT_STUB_END, BSMAN_STUB, BSMAN_STUB_END,
            BSMAN_RETURN_TRACE, BSMAN_RETURN_TRACE_END,
            *PREFIX_TRACE_STUBS, *POST_TRACE_STUBS, *STATE_ZERO_TRACE_STUBS,
            "zeroCtrlPostBSManNaturalResult", "zeroCtrlPostBSManCompatMode",
            "zeroCtrlPostBSManSubstitutionHits",
            "zeroCtrlPostBSManEffectiveResult",
            "zeroCtrlPostPafResult0", "zeroCtrlPostPafResult1",
            "zeroCtrlPostVshNaturalResult"):
        if not re.search(r"^[0-9a-fA-F]+\s+\w\s+" + symbol + r"$", nm, re.M):
            fail("missing Sony module_start wrapper symbol " + symbol)
    symbol_addresses = {}
    for line in nm.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+\w\s+(\S+)$", line)
        if match:
            symbol_addresses[match.group(2)] = int(match.group(1), 16)
    for start, end, counter in T22_CONSUMER_WRAPPERS:
        for symbol in (start, end, counter):
            if symbol not in symbol_addresses:
                fail("missing linked T22 symbol " + symbol)
        if symbol_addresses[end] <= symbol_addresses[start]:
            fail(start + " has an empty or reversed linked range")
    if T22_CONSUMER_TARGET not in symbol_addresses:
        fail("missing linked T22 natural-target symbol")
    disassembly = subprocess.check_output(["psp-objdump", "-dr", str(elf)], text=True)
    for symbol in STUBS:
        body = function_body(disassembly, symbol)
        if re.search(r"\bgp\b|\bsp\b|\bjal\b", body):
            fail(symbol + " uses gp, sp, or an imported/called function")
        if not re.search(r"\bjr\s+ra\b", body):
            fail(symbol + " is not a leaf returning through ra")
        if not re.search(
            r"\b(?:li\s+v0,\s*1|addiu\s+v0,\s*zero,\s*1)\b", body
        ):
            fail(symbol + " does not return strict boolean 1")
    body = function_body(disassembly, BSMAN_STUB)
    if re.search(r"\bgp\b|\bsp\b|\bjal\b", body):
        fail("BSMan leaf uses gp, sp, or an imported/called function")
    if not re.search(r"\bjr\s+ra\b", body) or not re.search(
            r"\b(?:move\s+v0,\s*zero|addu\s+v0,\s*zero,\s*zero)\b", body):
        fail("BSMan leaf does not return deterministic CLOSED=0")
    return_trace = function_body(disassembly, BSMAN_RETURN_TRACE)
    check_bsman_return_semantics(return_trace)
    if not re.search(r"\blw\s+ra,", return_trace) or \
            not re.search(r"\bjr\s+ra\b", return_trace):
        fail("BSMan return trace does not restore and return through ra")
    for symbol in PREFIX_TRACE_STUBS + POST_TRACE_STUBS:
        prefix_trace = function_body(disassembly, symbol)
        if re.search(r"\bgp\b|\bjalr?\b", prefix_trace):
            fail(symbol + " uses gp or a call")
        if symbol == "zeroCtrlPostBSManBranchTrace":
            check_post_bsman_branch_semantics(prefix_trace)
        if symbol == "zeroCtrlSlidePrefixPafReturnTrace" and \
                (not re.search(r"\bsw\s+v0,", prefix_trace) or
                 not re.search(r"\bbnez\s+v0,", prefix_trace) or
                 not re.search(
                     r"\b(?:li\s+v0,\s*1|addiu\s+v0,\s*zero,\s*1)\b",
                     prefix_trace) or
                 not re.search(r"\blw\s+ra,", prefix_trace) or
                 not re.search(r"\bjr\s+ra\b", prefix_trace)):
            fail("prefix PAF return trace does not isolate zero-to-one and restore ra")
        if symbol in ("zeroCtrlPostPafReturnTrace",
                "zeroCtrlPostVshReturnTrace"):
            expected_count = 2 if symbol == "zeroCtrlPostPafReturnTrace" else 1
            require_only_natural_result_stores(
                    prefix_trace, symbol, expected_count)
        if symbol == "zeroCtrlPostPafReturnTrace" and \
                (not re.search(r"\b(?:move\s+ra,\s*t9|"
                               r"addu\s+ra,\s*t9,\s*zero)\b", prefix_trace) or
                 not re.search(r"\bjr\s+ra\b", prefix_trace)):
            fail("post-BSMan PAF return trace does not restore ra")
        if symbol == "zeroCtrlPostVshReturnTrace" and \
                (not re.search(r"\blw\s+ra,", prefix_trace) or
                 not re.search(r"\bjr\s+ra\b", prefix_trace)):
            fail("post-BSMan VshBridge return trace does not restore ra")
    for start, _end, _counter in T22_CONSUMER_WRAPPERS:
        check_t22_consumer_semantics(function_body(disassembly, start), start)


def check_stub_object(stub_object):
    disassembly = subprocess.check_output(
        ["psp-objdump", "-dr", str(stub_object)], text=True
    )
    for symbol, counter in zip(STUBS, COUNTERS):
        body = function_body(disassembly, symbol)
        if not re.search(r"R_MIPS_HI16\s+" + counter + r"\b", body):
            fail(symbol + " has no HI16 relocation to its dedicated counter")
        if len(re.findall(r"R_MIPS_LO16\s+" + counter + r"\b", body)) != 2:
            fail(symbol + " does not have two LO16 counter relocations")
    for symbol, _end, counter in T22_CONSUMER_WRAPPERS:
        body = function_body(disassembly, symbol)
        check_t22_consumer_semantics(body, symbol)
        if len(re.findall(r"R_MIPS_HI16\s+" + counter + r"\b", body)) != 1 or \
                len(re.findall(r"R_MIPS_LO16\s+" + counter + r"\b", body)) != 2:
            fail(symbol + " lacks exact dedicated-counter relocations")
        if len(re.findall(r"R_MIPS_HI16\s+" + T22_CONSUMER_TARGET + r"\b",
                body)) != 1 or len(re.findall(
                    r"R_MIPS_LO16\s+" + T22_CONSUMER_TARGET + r"\b", body)) != 1:
            fail(symbol + " lacks unique natural-target relocations")
        if not re.search(r"\blw\s+t2,[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                T22_CONSUMER_TARGET + r"\b", body):
            fail(symbol + " does not load the natural target into t2")
    bsman_leaf = function_body(disassembly, BSMAN_STUB)
    if not re.search(r"R_MIPS_HI16\s+" + BSMAN_COUNTER + r"\b", bsman_leaf) or \
            len(re.findall(r"R_MIPS_LO16\s+" + BSMAN_COUNTER + r"\b",
                bsman_leaf)) != 2:
        fail("BSMan leaf lacks the exact dedicated-counter relocations")
    return_trace = function_body(disassembly, BSMAN_RETURN_TRACE)
    if not re.search(r"R_MIPS_HI16\s+" + BSMAN_CALL_RA + r"\b",
            return_trace) or not re.search(
                r"\blw\s+ra,.*R_MIPS_LO16\s+" + BSMAN_CALL_RA + r"\b",
                return_trace, re.S) or not re.search(r"\bjr\s+ra\b", return_trace):
        fail("BSMan return trace lacks the saved-ra restore relocations")
    check_bsman_return_semantics(return_trace, relocatable=True)
    post_bs_branch = function_body(
            disassembly, "zeroCtrlPostBSManBranchTrace")
    check_post_bsman_branch_semantics(post_bs_branch, relocatable=True)
    post_state_branch = function_body(disassembly, "zeroCtrlPostStateBranchTrace")
    if re.search(r"\bv0\b", post_state_branch) or not re.search(
            r"R_MIPS_HI16\s+zeroCtrlPostStateNaturalValue\b",
            post_state_branch) or not re.search(r"\bbeqz\s+t2,", post_state_branch):
        fail("post-state trace does not preserve the relocated LUI delay result")
    state_vcall = function_body(disassembly, "zeroCtrlStateZeroVCallTrace")
    require_result_store_relocation(state_vcall,
            "zeroCtrlStateZeroVCallTrace", "zeroCtrlStateZeroVCallTarget")
    if not re.search(r"R_MIPS_HI16\s+zeroCtrlStateZeroVCallRA\b", state_vcall) or \
            not re.search(r"\bjr\s+v0\b", state_vcall):
        fail("T15 virtual-call wrapper does not preserve target and original ra")
    state_vreturn = function_body(disassembly, "zeroCtrlStateZeroVReturnTrace")
    require_result_store_relocation(state_vreturn,
            "zeroCtrlStateZeroVReturnTrace", "zeroCtrlStateZeroVCallResult")
    v0_lines = [line for line in state_vreturn.splitlines()
                if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]) or \
            not re.search(r"R_MIPS_HI16\s+zeroCtrlStateZeroVCallRA\b",
                          state_vreturn) or not re.search(r"\bjr\s+ra\b", state_vreturn):
        fail("T15 virtual return does not preserve the natural result and Sony ra")
    post_paf_return = function_body(disassembly, "zeroCtrlPostPafReturnTrace")
    require_only_natural_result_stores(
            post_paf_return, "zeroCtrlPostPafReturnTrace", 2)
    require_result_store_relocation(post_paf_return,
            "zeroCtrlPostPafReturnTrace", "zeroCtrlPostPafResult0")
    require_result_store_relocation(post_paf_return,
            "zeroCtrlPostPafReturnTrace", "zeroCtrlPostPafResult1")
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b", post_paf_return) or \
            not re.search(r"R_MIPS_HI16\s+zeroCtrlPostPafSavedRA\b",
                          post_paf_return) or \
            not re.search(r"\blw\s+t9,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                          r"zeroCtrlPostPafSavedRA\b", post_paf_return) or \
            not re.search(r"\b(?:move\s+ra,\s*t9|"
                          r"addu\s+ra,\s*t9,\s*zero)\b", post_paf_return) or \
            not re.search(r"\bjr\s+ra\b", post_paf_return):
        fail("post-BSMan PAF return trace violates leaf/RA invariants")
    post_vsh_return = function_body(disassembly, "zeroCtrlPostVshReturnTrace")
    require_only_natural_result_stores(
            post_vsh_return, "zeroCtrlPostVshReturnTrace", 1)
    require_result_store_relocation(post_vsh_return,
            "zeroCtrlPostVshReturnTrace", "zeroCtrlPostVshNaturalResult")
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b", post_vsh_return) or \
            not re.search(r"R_MIPS_HI16\s+zeroCtrlPostVshSavedRA\b",
                          post_vsh_return) or \
            not re.search(r"\blw\s+ra,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                          r"zeroCtrlPostVshSavedRA\b", post_vsh_return) or \
            not re.search(r"\blw\s+ra,", post_vsh_return) or \
            not re.search(r"\bjr\s+ra\b", post_vsh_return):
        fail("post-BSMan VshBridge return trace violates leaf/RA invariants")
    entry = function_body(disassembly, SONY_ENTRY_STUB)
    exit_stub = function_body(disassembly, SONY_EXIT_STUB)
    for symbol in ("zeroCtrlSonyModuleStartEntrySeen",
            "zeroCtrlSonyModuleStartResume", "zeroCtrlSonyModuleStartCallerRA",
            "zeroCtrlSonyModuleStartExitTrace"):
        if not re.search(r"R_MIPS_HI16\s+" + symbol + r"\b", entry) or \
                not re.search(r"R_MIPS_LO16\s+" + symbol + r"\b", entry):
            fail("Sony entry trace lacks relocations for " + symbol)
    for symbol in ("zeroCtrlSonyModuleStartResult",
            "zeroCtrlSonyModuleStartReturnSeen", "zeroCtrlSonyModuleStartCallerRA"):
        if not re.search(r"R_MIPS_HI16\s+" + symbol + r"\b", exit_stub) or \
                not re.search(r"R_MIPS_LO16\s+" + symbol + r"\b", exit_stub):
            fail("Sony exit trace lacks relocations for " + symbol)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--user-elf", type=pathlib.Path)
    parser.add_argument("--stub-object", type=pathlib.Path)
    args = parser.parse_args()
    check_sources(args.source_root.resolve())
    if args.user_elf:
        check_elf(args.user_elf)
    if args.stub_object:
        check_stub_object(args.stub_object)
    print("verified PSP-1000 static safety invariants")


if __name__ == "__main__":
    main()
