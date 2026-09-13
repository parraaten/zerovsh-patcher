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
     "zeroCtrlConsumer13F6CHits", "zeroCtrlConsumer13F6CNaturalResult"),
    ("zeroCtrlConsumer14020Trace", "zeroCtrlConsumer14020TraceEnd",
     "zeroCtrlConsumer14020Hits", "zeroCtrlConsumer14020NaturalResult"),
)
T22_CONSUMER_TARGET = "zeroCtrlConsumer6F84Target"
T24_SCALARS = (
    "zeroCtrlConsumer14020CompatMode",
    "zeroCtrlConsumer14020EffectiveResult",
    "zeroCtrlConsumer14020SubstitutionHits",
)
T25_SCALARS = (
    "zeroCtrlConsumer13F6CCompatMode",
    "zeroCtrlConsumer13F6CEffectiveResult",
    "zeroCtrlConsumer13F6CSubstitutionHits",
)
T27_PREDICATE_WRAPPERS = (
    ("zeroCtrlCapability6F44Trace", "zeroCtrlCapability6F44TraceEnd",
     "zeroCtrlCapability6F44Hits", "zeroCtrlCapability6F44NaturalResult",
     "zeroCtrlCapability6F44Target"),
    ("zeroCtrlCapability6FC4Trace", "zeroCtrlCapability6FC4TraceEnd",
     "zeroCtrlCapability6FC4Hits", "zeroCtrlCapability6FC4NaturalResult",
     "zeroCtrlCapability6FC4Target"),
    ("zeroCtrlCapability7004Trace", "zeroCtrlCapability7004TraceEnd",
     "zeroCtrlCapability7004Hits", "zeroCtrlCapability7004NaturalResult",
     "zeroCtrlCapability7004Target"),
)
T27_MASK_SYMBOLS = ("zeroCtrlPafCapabilityMaskTrace",
    "zeroCtrlPafCapabilityMaskTraceEnd", "zeroCtrlPafCapabilityMaskTarget",
    "zeroCtrlPafCapabilityMaskHits", "zeroCtrlPafCapabilityMaskNatural",
    "zeroCtrlPafCapabilityMaskCompatMode", "zeroCtrlPafCapabilityMaskEffective",
    "zeroCtrlPafCapabilityMaskSubstitutionHits")
T33_SYMBOLS = ("zeroCtrlPostMinusOneVCall64Trace",
    "zeroCtrlPostMinusOneVCall64TraceEnd",
    "zeroCtrlPostMinusOneVCall64ReturnTrace",
    "zeroCtrlPostMinusOneVCall64ReturnTraceEnd",
    "zeroCtrlPostMinusOneVCall64Target", "zeroCtrlPostMinusOneVCall64SavedRA",
    "zeroCtrlPostMinusOneVCall64NaturalResult", "zeroCtrlPostMinusOneVCall64Hits",
    "zeroCtrlPostMinusOneVCall64ReturnHits",
    "zeroCtrlPostMinusOneVCall64CollectionEnabled",
    "zeroCtrlPostMinusOneVCall64CountSnapshot",
    "zeroCtrlPostMinusOneVCall64ArraySnapshot",
    "zeroCtrlPostMinusOneVCall64ArrayReadHits")
T35_SYMBOLS = ("zeroCtrlCollectionPafFCF265D8Trace",
    "zeroCtrlCollectionPafFCF265D8TraceEnd",
    "zeroCtrlCollectionPafFCF265D8LastItem",
    "zeroCtrlCollectionPafFCF265D8NaturalResult",
    "zeroCtrlCollectionPafFCF265D8Hits",
    "zeroCtrlCollectionPafFCF265D8NonzeroHits")
T36_SYMBOLS = ("zeroCtrlCollectionPaf9A285882Trace",
    "zeroCtrlCollectionPaf9A285882TraceEnd",
    "zeroCtrlCollectionPaf9A285882LastItem",
    "zeroCtrlCollectionPaf9A285882NaturalResult",
    "zeroCtrlCollectionPaf9A285882Hits",
    "zeroCtrlCollectionPaf9A285882NonzeroHits",
    "zeroCtrlCollectionPaf9A285882ZeroResumeTarget",
    "zeroCtrlCollectionPaf9A285882NonzeroTarget")
T37_SYMBOLS = ("zeroCtrlPostCollectionPafFCF265D8Trace",
    "zeroCtrlPostCollectionPafFCF265D8TraceEnd",
    "zeroCtrlPostCollectionPafFCF265D8NaturalResult",
    "zeroCtrlPostCollectionPafFCF265D8Hits",
    "zeroCtrlPostCollectionPafFCF265D8NonzeroHits",
    "zeroCtrlPostCollectionPafFCF265D8ZeroResumeTarget",
    "zeroCtrlPostCollectionPafFCF265D8NonzeroTarget")
T38_SYMBOLS = ("zeroCtrlMaskedPafC59FC3D0Trace",
    "zeroCtrlMaskedPafC59FC3D0TraceEnd",
    "zeroCtrlMaskedPafC59FC3D0DecisionValue",
    "zeroCtrlMaskedPafC59FC3D0Hits",
    "zeroCtrlMaskedPafC59FC3D0NonzeroHits",
    "zeroCtrlMaskedPafC59FC3D0ZeroResumeTarget",
    "zeroCtrlMaskedPafC59FC3D0NonzeroTarget")
T39_SYMBOLS = ("zeroCtrlMaskedPafC59FC3D0SecondTrace",
    "zeroCtrlMaskedPafC59FC3D0SecondTraceEnd",
    "zeroCtrlMaskedPafC59FC3D0SecondDecisionValue",
    "zeroCtrlMaskedPafC59FC3D0SecondHits",
    "zeroCtrlMaskedPafC59FC3D0SecondNonzeroHits",
    "zeroCtrlMaskedPafC59FC3D0SecondZeroResumeTarget",
    "zeroCtrlMaskedPafC59FC3D0SecondNonzeroTarget")
T32_SYMBOLS = ("zeroCtrlPostImposeVCallTrace",
    "zeroCtrlPostImposeVCallTraceEnd", "zeroCtrlPostImposeVCallReturnTrace",
    "zeroCtrlPostImposeVCallReturnTraceEnd", "zeroCtrlPostImposeVCallTarget",
    "zeroCtrlPostImposeVCallSavedRA", "zeroCtrlPostImposeVCallNaturalResult",
    "zeroCtrlPostImposeVCallHits", "zeroCtrlPostImposeVCallReturnHits")


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
    bsman_header = (root / "kernel/bsman_closed_shim.h").read_text()
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
    minimal_start = writer.find("zeroCtrlWriteSlideCheckpoints(&written)")
    minimal_end = writer.find("for (i = 0; i < VSH_TRIGGER_COUNT; i++)",
            minimal_start)
    minimal = writer[minimal_start:minimal_end]
    for token in ("zeroCtrlWriteSlideCheckpoints(&written)",
            'zeroCtrlWriteFastMemory("probe_entry"',
            "slide_diag.minimal_probe_total_free",
            "slide_diag.minimal_probe_largest_block",
            'zeroCtrlWriteFastMemory("start_handler_entry"',
            "slide_diag.minimal_start_total_free",
            "slide_diag.minimal_start_largest_block",
            "[checkpoint-fast] activation_callback_entered",
            "[checkpoint-fast] slide_module_start_entered",
            "[checkpoint-fast] slide_module_start_returned",
            "[checkpoint-fast] latest=", "fast_poll_until = elapsed + 2000000",
            "elapsed < fast_poll_until", "10000 : SLIDE_OBSERVATION_POLL_US",
            "continue;"):
        if token not in minimal:
            fail("minimal PSP-1000 memory test lacks " + token)
    for verbose in ("[paf-parent-a0]", "[paf-dispatch-window-",
            "[paf-dispatch-control]", "[t40-exit-window-",
            "[natural-50-window-"):
        if verbose in minimal:
            fail("minimal PSP-1000 memory test executes verbose output " + verbose)
    for false_boundary in ("before_slide_module", "before_slide_module_start",
            "after_slide_module_start", "before_activation", "after_activation"):
        if 'zeroCtrlWriteFastMemory("' + false_boundary + '"' in kernel:
            fail("minimal memory test retains retrospective boundary " +
                    false_boundary)
    if "sceKernelDelayThread(10000);" in minimal or "elapsed += 10000;" in minimal:
        fail("minimal memory test forces permanent 10 ms polling")
    if minimal_start + minimal.find("continue;") > writer.find("[paf-parent-a0]"):
        fail("minimal memory test does not bypass parent/PAF diagnostics")
    vsh58_start = kernel.find("static void zeroCtrlWriteFunctionalVsh58Map(void)")
    vsh58_end = kernel.find("static int zeroCtrlWriteSlideDiagnostics(",
            vsh58_start)
    if vsh58_start < 0 or vsh58_end < 0:
        fail("functional PSP-1000 VSH+58D4 map is missing")
    vsh58 = kernel[vsh58_start:vsh58_end]
    for token in ("VSH58_MAP_END - VSH58_MAP_START", "model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "!slide_diag.functional_enabled",
            "!slide_diag.minimal_memory_test", "!slide_diag.vsh_module_seen",
            "vsh->text_addr == 0", "vsh->text_size < VSH58_MAP_END",
            "vsh->text_addr > 0xFFFFFFFFU - VSH58_MAP_END",
            "zeroCtrlVshModuleRangeValid(vsh,",
            "vsh->text_addr + VSH58_MAP_START, map_size)",
            "candidate->source_offset == 0x58D4",
            "candidate->predicate_index == 2", "candidate->kind == 3",
            "original_word = reference->instruction",
            "zeroCtrlMipsJumpTarget(reference->source_addr, original_word)",
            "[vsh58] source=", "[vsh58-callsite] original=",
            "offset == 0x58D4 ? original_word", "[vsh58-map]",
            "offset += 0x20", "unsigned int words[8]", "[vsh58-cf]",
            "zeroCtrlMipsJumpTarget(pc, word)",
            "zeroCtrlMipsBranchTarget(pc, word)", "opcode == 1",
            "opcode >= 0x14 && opcode <= 0x17", "[vsh58-frame]",
            '"STACK_ALLOC"', '"SAVE_RA"', '"RESTORE_RA"', "class=RETURN"):
        if token not in vsh58:
            fail("functional PSP-1000 VSH+58D4 map lacks " + token)
    for definition in ("#define VSH58_MAP_START 0x54D4",
            "#define VSH58_MAP_END   0x5CD4"):
        if definition not in kernel:
            fail("functional PSP-1000 VSH+58D4 map lacks " + definition)
    range_validation = vsh58.find("zeroCtrlVshModuleRangeValid(vsh,")
    first_read = vsh58.find("_lw(")
    if not 0 <= range_validation < first_read:
        fail("VSH+58D4 map reads loaded text before validating the full range")
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL",
            "zeroCtrlRedir", "vsh->text_addr + 0x58D4)("):
        if forbidden in vsh58:
            fail("VSH+58D4 map is not strictly read-only: " + forbidden)
    if "zeroCtrlWriteFunctionalVsh58Map();" in kernel:
        fail("large VSH+58D4 map is still emitted automatically")
    scan_start = kernel.find(
            "static void zeroCtrlWriteFunctionalVshRequestCallers(void)")
    scan_end = kernel.find("static int zeroCtrlWriteSlideDiagnostics(", scan_start)
    if scan_start < 0 or scan_end < 0:
        fail("read-only VSH +589C caller scan is missing")
    request_scan = kernel[scan_start:scan_end]
    for token in ("for (offset = 0; offset + 8 <= vsh->text_size; offset += 4)",
            "opcode == 2 || opcode == 3",
            "zeroCtrlMipsJumpTarget(pc, word)",
            "target == vsh->text_addr + 0x589C",
            "target == vsh->text_addr + 0x57B0",
            "[vsh589c-callers] validation=1 jal=%u jump=%u",
            "[vsh589c-caller]", "[vsh57b0-callers]",
            "[vsh57b0-caller]", "opcode == 0x0F",
            "low_opcode == 9 || low_opcode == 0x0D",
            "upper + (int)(short)(low & 0xFFFF)",
            "upper | (low & 0xFFFF)", "[vsh589c-address-ref]",
            "VSH589C_REPORT_LIMIT"):
        if token not in request_scan:
            fail("VSH +589C/+57B0 scan lacks " + token)
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL",
            "zeroCtrlRedir", "request_function()"):
        if forbidden in request_scan:
            fail("VSH +589C/+57B0 scan is not read-only: " + forbidden)
    window_start = kernel.find("static void zeroCtrlWriteVsh589cWindow(")
    a0_end = scan_start
    request_helpers = kernel[window_start:a0_end]
    for token in ("[vsh589c-window]", "row += 0x20", "_lw(address + 28)",
            "zeroCtrlVsh589cA0Definition", "rt == 4 && opcode == 9",
            "rt == 4 && opcode == 0x0D", "rt == 4 && opcode == 0x0F",
            "rt == 4 && opcode == 0x23", "ADDU_MOVE", "OR_MOVE",
            "zeroCtrlVsh589cControlBarrier", "status=AMBIGUOUS",
            "NO_DEF_FRAME_BOUNDARY"):
        if token not in request_helpers:
            fail("bounded VSH +589C caller/A0 analysis lacks " + token)
    for definition in ("#define VSH589C_WINDOW_BEFORE 0x50",
            "#define VSH589C_WINDOW_AFTER  0x30"):
        if definition not in kernel:
            fail("bounded VSH +589C caller window lacks " + definition)
    if any(token in request_helpers for token in ("_sw(", "Dcache", "Icache")):
        fail("bounded VSH +589C caller/A0 analysis is not read-only")
    if "zeroCtrlWriteFunctionalVshRequestCallers();" in kernel:
        fail("superseded VSH +589C/+57B0 scan is still emitted automatically")
    vsh3_start = kernel.find(
            "static void zeroCtrlWriteFunctionalVsh3f568Analysis(void)")
    vsh3_end = kernel.find("static int zeroCtrlWriteSlideDiagnostics(", vsh3_start)
    if vsh3_start < 0 or vsh3_end < 0:
        fail("VSH +3F568 analysis is missing")
    vsh3 = kernel[vsh3_start:vsh3_end]
    for definition in ("#define VSH3F568_MAP_START 0x3F468",
            "#define VSH3F568_MAP_END   0x3F768",
            "#define VSH3F568_CALLER_WINDOW_BEFORE 0x40",
            "#define VSH3F568_CALLER_WINDOW_AFTER  0x20"):
        if definition not in kernel:
            fail("VSH +3F568 analysis lacks " + definition)
    for token in ("model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "!slide_diag.functional_enabled", "!slide_diag.minimal_memory_test",
            "zeroCtrlVshModuleRangeValid(vsh,",
            "vsh->text_addr + VSH3F568_MAP_START",
            "VSH3F568_MAP_END - VSH3F568_MAP_START",
            "word_56fc = _lw(text + 0x56FC)",
            "word_5700 = _lw(text + 0x5700)",
            "word_5704 = _lw(text + 0x5704)",
            "word_5708 = _lw(text + 0x5708)",
            "((word_56fc >> 16) & 0x1F) != 5",
            "(word_5700 >> 26) != 9",
            "((word_5700 >> 21) & 0x1F) != 5",
            "((word_5700 >> 16) & 0x1F) != 5",
            "(int)(short)(word_5700 & 0xFFFF)",
            "decoded_a1 != text + 0x589C", "(word_5704 >> 26) != 3",
            "zeroCtrlMipsJumpTarget(text + 0x5704, word_5704)",
            "text + 0x3F568", "(word_5708 >> 26) != 0",
            "((word_5708 >> 11) & 0x1F) != 4",
            "[vsh3f568-callsite] validation=1 caller=0x05704",
            "[vsh3f568-map]", "[vsh3f568-cf]", "[vsh3f568-frame]",
            "for (offset = 0x56AC; offset < 0x570C; offset += 4)",
            "[vsh5704-arg0]", "zeroCtrlWriteVsh3f568A1Flow(vsh)",
            "for (offset = 0; offset + 8 <= vsh->text_size; offset += 4)",
            "zeroCtrlMipsJumpTarget(pc, word) == text + 0x3F568",
            "[vsh3f568-callers]", "[vsh3f568-caller]",
            "low_opcode == 9 || low_opcode == 0x0D",
            "upper + (int)(short)(low & 0xFFFF)",
            "upper | (low & 0xFFFF)", "[vsh3f568-address-ref]"):
        if token not in vsh3:
            fail("VSH +3F568 analysis lacks " + token)
    first_vsh3_read = vsh3.find("_lw(")
    vsh3_range = vsh3.find("zeroCtrlVshModuleRangeValid(vsh,")
    if not 0 <= vsh3_range < first_vsh3_read:
        fail("VSH +3F568 analysis reads before validating loaded ranges")
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL",
            "zeroCtrlRedir", "request_function()"):
        if forbidden in vsh3:
            fail("VSH +3F568 analysis is not read-only: " + forbidden)
    a1_start = kernel.find("static void zeroCtrlWriteVsh3f568A1Flow(")
    a1_end = vsh3_start
    a1_flow = kernel[a1_start:a1_end]
    for token in ("tracked = 5", "[vsh3f568-a1-store]",
            "[vsh3f568-a1-copy]", "PASSED_TO_CALL", "USED_IMMEDIATELY",
            "[vsh3f568-next-map]", "zeroCtrlVshModuleRangeValid(vsh, target, 0x40)",
            "zeroCtrlWriteVsh3f568Dispatch(vsh, offset + 4, rs,",
            "status=AMBIGUOUS",
            "opcode == 2 || opcode == 1", "opcode >= 4 && opcode <= 7",
            "opcode >= 0x14 && opcode <= 0x17",
            "opcode == 0 && function == 8"):
        if token not in a1_flow:
            fail("bounded VSH +3F568 a1 dataflow lacks " + token)
    if any(token in a1_flow for token in ("_sw(", "Dcache", "Icache")):
        fail("bounded VSH +3F568 a1 dataflow is not read-only")
    caller_window_start = kernel.find(
            "static void zeroCtrlWriteVsh3f568CallerWindow(")
    caller_window_end = a1_start
    caller_window = kernel[caller_window_start:caller_window_end]
    for token in ("[vsh3f568-window]", "row += 0x20",
            "_lw(address + 28)", "[vsh589c-dispatch]",
            "status=NOT_IDENTIFIED_IN_BOUNDED_FLOW"):
        if token not in caller_window:
            fail("bounded VSH +3F568 caller window lacks " + token)
    if kernel.count("zeroCtrlWriteFunctionalVsh3f568Analysis();") != 1 or \
            "if (!vsh3f568_scan_written && slide_diag.functional_enabled" \
            not in minimal or "vsh3f568_scan_written = 1;" not in minimal:
        fail("VSH +3F568 analysis is not one-shot deferred output")
    minimal_gate = kernel[kernel.find("slide_diag.minimal_memory_test ="):
        kernel.find("slide_diag.global_predicate_enabled =")]
    for token in ("model == 0", "devkit == 0x06060110",
            'strcmp(psp1000SlidePlugin, "Enabled") == 0',
            'strcmp(psp1000Diagnostics, "Enabled") == 0'):
        if token not in minimal_gate:
            fail("minimal memory test gate lacks " + token)
    fast_memory_start = kernel.find("static void zeroCtrlWriteFastMemory(")
    fast_memory_end = kernel.find("static int zeroCtrlWriteSlideDiagnostics(",
            fast_memory_start)
    fast_memory = kernel[fast_memory_start:fast_memory_end]
    for token in ("[mem-fast] %s total_free=%u largest_block=%u",
            "unsigned int total_free", "unsigned int largest_block"):
        if token not in fast_memory:
            fail("minimal memory checkpoint lacks " + token)
    if any(token in fast_memory for token in ("sceKernelAlloc", "malloc", "_sw(",
            "sceKernelPartitionTotalFreeMemSize",
            "sceKernelPartitionMaxFreeMemSize")):
        fail("deferred minimal memory output does not use stored snapshots")
    minimal_final = writer[writer.find("if (slide_diag.minimal_memory_test)",
        minimal_end):writer.find(
            'zeroCtrlDiagnosticsText("[checkpoint] slide_observation_window_complete')]
    for token in ("minimal_observation_window_complete",
            "sceKernelExitDeleteThread(0)", "return 0"):
        if token not in minimal_final:
            fail("minimal memory test does not bypass final verbose dumps")
    probe_scope = kernel[kernel.find("int zeroCtrlModuleProbe("):
        kernel.find("int zeroCtrlHookModule(")]
    start_scope = kernel[kernel.find("int OnModuleStart("):
        kernel.find("int zeroCtrlLoadStartModule(")]
    for scope, prefix in ((probe_scope, "minimal_probe"),
            (start_scope, "minimal_start")):
        for token in ("if (slide_diag.minimal_memory_test)",
                "sceKernelPartitionTotalFreeMemSize(",
                "sceKernelPartitionMaxFreeMemSize(",
                "PSP_MEMORY_PARTITION_USER", prefix + "_total_free",
                prefix + "_largest_block", prefix + "_memory_valid = 1"):
            if token not in scope:
                fail("minimal memory snapshot boundary lacks " + token)
        if scope.find(prefix + "_memory_valid = 1") < \
                scope.find(prefix + "_largest_block"):
            fail("minimal memory snapshot is published before capture completes")
    if re.search(r"hook_import_bynid\([^\n]*(?:Alloc|Malloc|SysMem)", kernel,
            re.IGNORECASE):
        fail("minimal memory test introduces a global allocator hook")
    functional_gate = kernel[kernel.find("slide_diag.functional_enabled ="):
        kernel.find("slide_diag.minimal_memory_test =")]
    for token in ("model == 0", "devkit == 0x06060110",
            'strcmp(psp1000SlidePlugin, "Enabled") == 0',
            'strcmp(useSlide, "Enabled") == 0'):
        if token not in functional_gate:
            fail("PSP-1000 functional gate lacks " + token)
    if "PSP1000Diagnostics" in functional_gate:
        fail("PSP-1000 functional mode incorrectly requires diagnostics")
    for token in ("[psp1000-functional] enabled=1",
            "[psp1000-functional] button_thread=1",
            "[psp1000-functional] runtime_request_blocked=1",
            "[psp1000-functional] runtime_request_valid=1",
            "[psp1000-functional] runtime_request_called=%u",
            "[psp1000-functional] runtime_request_result=0x%08X",
            "[psp1000-functional] slide_module_seen=1",
            "[psp1000-functional] activation_hits=%u"):
        if token not in minimal:
            fail("functional compact diagnostics lack " + token)
    trigger_leaf = assembly[assembly.find("zeroCtrlTrigger58D4:"):
        assembly.find("zeroCtrlTrigger58D4End:")]
    for token in ("zeroCtrlTrigger58D4FunctionalMode",
            "zeroCtrlTrigger58D4Request", "zeroCtrlTrigger58D4OriginalTarget",
            "sw      $zero, %lo(zeroCtrlTrigger58D4Request)",
            "lw      $t0, %lo(zeroCtrlTrigger58D4OriginalTarget)($t0)",
            "jr      $t0", "jr      $ra", "addiu   $v0, $zero, 1"):
        if token not in trigger_leaf:
            fail("functional 58D4 helper lacks " + token)
    if any(token in trigger_leaf for token in
            ("$k0", "$k1", "$sp", "$gp", "jal ", "jalr")):
        fail("functional 58D4 helper uses reserved/stateful registers or calls")
    record_start = kernel.find("void zeroCtrlRecordVshSlideTarget(")
    record_end = kernel.find("int (*msIoOpen)", record_start)
    record = kernel[record_start:record_end]
    for token in ("stub_58d4_end - stub_58d4",
            "evidence->request_addr", "evidence->original_target_addr",
            "evidence->functional_mode_addr",
            "_sw(0, request_evidence->request_addr)",
            "_sw(request_evidence->original_target",
            "_sw(slide_diag.functional_enabled ? 1 : 0",
            "sceKernelDcacheWritebackInvalidateRange("):
        if token not in record:
            fail("functional 58D4 registration lacks " + token)
    scalar_init = record.find("_sw(0, request_evidence->request_addr)")
    trigger_commit = record.find("_sw(evidence->replacement_word")
    if not 0 <= scalar_init < trigger_commit:
        fail("functional 58D4 routing scalars are not initialized before patch")
    button_start = kernel.find("void zeroCtrlReadButtons(")
    button_end = kernel.find("void zeroCtrlCreateBtnThread(", button_start)
    button = kernel[button_start:button_end]
    for token in ("ZERO_SLIDE_STOPPED", "slideStartBtn",
            "slide_diag.functional_enabled",
            "functional_runtime_request_blocked = 1", "request_ready",
            "zeroCtrlSetSlideState(ZERO_SLIDE_STARTING)"):
        if token not in button:
            fail("functional StartBtn request gating lacks " + token)
    if "_sw(1, slide_diag.functional_runtime_request_addr)" in button or \
            "_sw(1, slide_diag.triggers[0].request_addr)" in button or \
            "functional_request_armed = 1" in button:
        fail("functional HOME can still publish an experimental VSH request")
    button_install = kernel[kernel.find("if (slide_diag.functional_enabled)",
        kernel.find("zeroCtrlCreatePatchThread();")):kernel.find("return 0;",
        kernel.find("zeroCtrlCreatePatchThread();"))]
    for token in ("zeroCtrlCreateBtnThread()",
            "sctrlHENSetStartModuleHandler(OnModuleStart)",
            "else if (slide_diag.armed)"):
        if token not in button_install:
            fail("functional button thread/handler gate lacks " + token)
    kernel_module_start = kernel[kernel.find("int OnModuleStart(SceModule2 *mod)"):
        kernel.find("int zeroCtrlLoadStartModule(")]
    for token in ('hook_import_bynid(mod, "sceBSMan", 0x23E3A9B6',
            "zeroCtrlDummyFunc, 1",
            'hook_import_bynid(mod, "sceVshBridge", 0x639C3CB3',
            "zeroCtrlGetParam, 1"):
        if token not in kernel_module_start:
            fail("functional SlidePlugin import integration lacks " + token)
    bsman_hook = kernel_module_start.find(
            'hook_import_bynid(mod, "sceBSMan", 0x23E3A9B6')
    vsh_hook = kernel_module_start.find(
            'hook_import_bynid(mod, "sceVshBridge", 0x639C3CB3')
    sony_install = kernel_module_start.find("zeroCtrlInstallSonyStartTrace(mod)")
    compat_install = kernel_module_start.find("zeroCtrlInstallBSManClosedShim(mod)")
    cache_clear = kernel_module_start.find("ClearCaches()", compat_install)
    functional_return = kernel_module_start.find("return previous_result", cache_clear)
    if not 0 <= bsman_hook < vsh_hook < sony_install < compat_install < \
            cache_clear < functional_return:
        fail("functional SlidePlugin cache clear is missing or incorrectly ordered")
    for gate_name in ("bsman_not_linked_compat_enabled =",
            "post_vsh_compat_enabled ="):
        gate = kernel[kernel.find(gate_name):kernel.find(";", kernel.find(gate_name))]
        if "!slide_diag.functional_enabled" not in gate:
            fail("functional mode double-enables experimental compatibility")
    user_module_start = user[user.find("int OnModuleStart(SceModule2 *mod)"):
        user.find("int module_start(")]
    for token in ("zeroCtrlIsPsp1000SlideFunctionalEnabled()",
            "mod->text_size >= 0xC994",
            "(_lw(mod->text_addr + 0xC990) >> 26) == 3",
            "_lw(mod->text_addr + 0x9038) == 0x27BDFFC0",
            "_lw(mod->text_addr + 0x903C) == 0xAFB40030",
            "MAKE_CALL(mod->text_addr+0xC990",
            "zeroCtrlRedir2Stub(mod->text_addr+0x9038"):
        if token not in user_module_start:
            fail("functional user SlidePlugin integration lacks " + token)
    if "PSP_EXPORT_FUNC_NID(zeroCtrlIsPsp1000SlideFunctionalEnabled, 0x1337357F)" \
            not in kernel_exports or \
            "STUB_FUNC 0x1337357F, zeroCtrlIsPsp1000SlideFunctionalEnabled" \
            not in user_imports:
        fail("functional mode query import/export is missing")
    runtime_validate_start = user.find(
            "static int zeroCtrlValidatePsp1000RuntimeRequest(")
    runtime_validate_end = user.find(
            "static int zeroCtrlPsp1000RuntimeRequestWorker(",
            runtime_validate_start)
    runtime_validate = user[runtime_validate_start:runtime_validate_end]
    if runtime_validate_start < 0 or runtime_validate_end < 0:
        fail("PSP-1000 runtime request validation is missing")
    for token in ("model != 0", "devkit != 0x06060110",
            "zeroCtrlIsPsp1000SlideFunctionalEnabled()",
            "mod->text_addr == 0", "mod->text_size <= 0x5898",
            "target = text + 0x57B0",
            "text > 0xFFFFFFFFU - 0x42FF8",
            "expected_pointer = text + 0x42FF8",
            "zeroCtrlUserModuleRangeValid(mod, target, 0xEC)",
            "zeroCtrlUserModuleRangeValid(mod, text + 0xF7C4, 4)",
            "zeroCtrlUserModuleRangeValid(mod, text + 0x58D4, 0x28)",
            "zeroCtrlUserMipsJumpTarget(text + 0x58D4, original_58d4)",
            "text + 0x6F84", "_lw(text + 0x58D8) != 0",
            "word_58dc = _lw(text + 0x58DC)",
            "word_58dc != 0x14400004",
            "zeroCtrlUserMipsBranchTarget(text + 0x58DC,",
            "text + 0x58F0", "_lw(text + 0x58E0) != 0",
            "word_58f0 = _lw(text + 0x58F0)",
            "zeroCtrlUserMipsJumpTarget(text + 0x58F0, word_58f0)",
            "word_58f8 = _lw(text + 0x58F8)",
            "zeroCtrlUserMipsJumpTarget(text + 0x58F8, word_58f8)",
            "text + 0x58E8", "word_57d0 = _lw(text + 0x57D0)",
            "zeroCtrlUserMipsJumpTarget(text + 0x57D0, word_57d0)",
            "text + 0xF7C4", "word_57b8 = _lw(text + 0x57B8)",
            "word_57bc = _lw(text + 0x57BC)",
            "(word_57b8 >> 26) != 0x0F",
            "((word_57b8 >> 21) & 0x1F) != 0",
            "((word_57b8 >> 16) & 0x1F) != 16",
            "(word_57bc >> 26) != 0x09",
            "((word_57bc >> 21) & 0x1F) != 16",
            "((word_57bc >> 16) & 0x1F) != 16",
            "upper = (word_57b8 & 0xFFFF) << 16",
            "displacement = (short)(word_57bc & 0xFFFF)",
            "decoded_pointer = upper + displacement",
            "decoded_pointer != expected_pointer",
            "zeroCtrlUserModuleRangeValid(mod, decoded_pointer, 4)",
            "psp1000RuntimeRequestTarget = target",
            "psp1000RuntimeRequestValid = 1"):
        if token not in runtime_validate:
            fail("PSP-1000 runtime request validation lacks " + token)
    for word in ("0x27BDFF80", "0xAFB00070",
            "0x02002021", "0xAFBF007C", "0xAFB20078",
            "0x27B2000C", "0x8FBF007C", "0x8FB20078", "0x8FB10074",
            "0x8FB00070", "0x03E00008", "0x27BD0080"):
        if word not in runtime_validate:
            fail("PSP-1000 +57B0 fingerprint lacks " + word)
    for relocation_word in ("0x3C1009C7", "0x2610CBF8"):
        if relocation_word in runtime_validate:
            fail("PSP-1000 +57B0 validation hardcodes relocated word " +
                    relocation_word)
    target_publish = runtime_validate.find("psp1000RuntimeRequestTarget = target")
    valid_publish = runtime_validate.find("psp1000RuntimeRequestValid = 1")
    last_fingerprint = runtime_validate.rfind("_lw(text + 0x5884")
    if not 0 <= last_fingerprint < target_publish < valid_publish:
        fail("runtime request target is published before complete validation")
    worker_start = user.find("static int zeroCtrlPsp1000RuntimeRequestWorker(")
    worker_end = user.find("static void zeroCtrlCreatePsp1000RuntimeRequestWorker(",
            worker_start)
    worker = user[worker_start:worker_end]
    if "#define PSP1000_RUNTIME_REQUEST_EXECUTION_ENABLED 0" not in user or \
            "if (PSP1000_RUNTIME_REQUEST_EXECUTION_ENABLED &&" not in worker:
        fail("direct +57B0 runtime execution is not compile-time disabled")
    for token in ("psp1000RuntimeRequestValid && psp1000RuntimeRequest",
            "psp1000RuntimeRequest = 0", "psp1000RuntimeRequestCalled++",
            "psp1000RuntimeRequestTarget", "request_function()",
            "psp1000RuntimeRequestResult", "sceKernelDelayThread(20000)"):
        if token not in worker:
            fail("PSP-1000 runtime request worker lacks " + token)
    if not worker.find("psp1000RuntimeRequest = 0") < \
            worker.find("psp1000RuntimeRequestCalled++") < \
            worker.find("request_function()"):
        fail("runtime request worker does not consume once before calling")
    worker_create = user[user.find(
            "static void zeroCtrlCreatePsp1000RuntimeRequestWorker("):
            user.find("//OK\nvoid *zeroCtrlRedir2Stub", worker_end)]
    for token in ('sceKernelCreateThread("zeroctrl_vsh_request"',
            "zeroCtrlPsp1000RuntimeRequestWorker", "0x4000",
            "sceKernelStartThread", "sceKernelDeleteThread"):
        if token not in worker_create:
            fail("PSP-1000 runtime request worker creation lacks " + token)
    user_start_prefix = user[user.find("int module_start("):
            user.find("sonyStartTraceRegistration.entry_addr")]
    for token in ("PSP1000_RUNTIME_REQUEST_EXECUTION_ENABLED",
            "model == 0", "devkit == 0x06060110",
            "zeroCtrlIsPsp1000SlideFunctionalEnabled()",
            "zeroCtrlCreatePsp1000RuntimeRequestWorker()"):
        if token not in user_start_prefix:
            fail("runtime request worker is not restricted to functional PSP-1000")
    runtime_record = record[record.find("helper = sceKernelFindModuleByName"):
            record.find("all_selected_valid =")]
    for token in ("runtime_request & 3", "runtime_request_valid & 3",
            "runtime_request_called & 3", "runtime_request_result & 3",
            "zeroCtrlVshModuleRangeValid(helper, runtime_request, 4)",
            "runtime_request_valid, 4", "runtime_request_called, 4",
            "runtime_request_result, 4",
            "functional_runtime_registration_valid = 1"):
        if token not in runtime_record:
            fail("kernel runtime request scalar registration lacks " + token)
    if "_sw(1, slide_diag.triggers[0].request_addr)" in button or \
            re.search(r"\(.*\*.*\)\s*\(.*0x58D4", button):
        fail("functional HOME still arms/calls the old +58D4 mechanism")
    caller_ra_start = writer.find("if (slide_diag.bsman.activation_enabled)")
    caller_ra_end = writer.find(
            "if (slide_diag.bsman.activation_wide_enabled)", caller_ra_start)
    caller_ra = writer[caller_ra_start:caller_ra_end]
    for token in ("[activation-caller-ra]", "registered=%u validation=%d",
            "activation_hits_addr", "activation_caller_ra_addr[0]",
            "activation_caller_ra_addr[1]", "activation_caller_ra_addr[2]",
            "sceKernelFindModuleByAddress(ra)",
            "(ra & 3) == 0",
            "((unsigned int)owner & 3) == 0",
            "(unsigned int)owner >= 0x88000000", "owner->text_addr != 0",
            "(unsigned int)owner < 0x8C000000",
            "owner->text_size >= 8", "owner->nsegment != 0",
            "owner->nsegment <= 4",
            "ra >= owner->text_addr + 8",
            "ra <= owner->text_addr + owner->text_size",
            "callsite = ra - 8", "word = _lw(callsite)",
            "delay = _lw(ra - 4)", "[activation-caller-ra-resolve]",
            "opcode=0x%02X rs=%u rt=%u rd=%u", "function=0x%02X",
            "opcode == 3 ? \"JAL\"", "function == 9 ? \"JALR\"",
            "zeroCtrlMipsJumpTarget(callsite, word)",
            "direct_target == bsman->activation_addr"):
        if token not in caller_ra:
            fail("deferred activation caller RA resolution lacks " + token)
    if caller_ra_start < 0 or caller_ra_end < 0 or any(token in caller_ra for
            token in ("_sw(", "sceKernelDcache", "sceKernelIcache")):
        fail("deferred activation caller RA resolution is not read-only")
    if "[activation-caller-ra]" in assembly or \
            "[activation-caller-ra-resolve]" in assembly:
        fail("activation caller RA output leaked into assembly helpers")
    for token in ('strcmp(owner->modname, "scePaf_Module") == 0',
            "window_start = callsite - 0xC0",
            "window_end = callsite + 0x60",
            "callsite >= owner->text_addr + 0xC0",
            "callsite - owner->text_addr <=",
            "owner->text_size - 0x64", "window_start + item * 4",
            "owner->text_size >= 0x124", "group < 13", "_lw(pc)",
            "[paf-dispatch-window-%u]", "[paf-dispatch-control]",
            "zeroCtrlMipsJumpTarget(pc, instruction)",
            "zeroCtrlMipsBranchTarget(", "regimm_branch",
            "instruction_rt >= 16", "likely_branch",
            "instruction_opcode >= 20", "instruction_opcode <= 23",
            "likely=%d", "instruction_function == 8",
            "instruction_function == 9", "[paf-jalr-t0-def]",
            "instruction_rt == 8", "instruction_rd == 8",
            "instruction_opcode == 35", "instruction_opcode == 36",
            "instruction_opcode == 37", "base=%u displacement=%d",
            "load ? instruction_rs : 0",
            "load ? (short)(instruction & 0xFFFF) : 0",
            "[paf-dispatch-reg-def]", "instruction_rt == 9",
            "instruction_rt == 16", "instruction_rt == 17",
            "instruction_rt == 18", "destination = tracked_immediate",
            "[paf-dispatch-frame-candidate]", "stack_adjust",
            "ra_stack", "return_jump",
            "which == 0 || caller_ra[1] != caller_ra[2]",
            "dispatcher_start = callsite - 0xA0",
            "dispatcher_offset <= owner->text_size - 0xD8",
            "0x27BDFFD0", "0xAFB00020", "0x2403FFFF",
            "0xAFBF002C", "0xAFB20028", "0xAFB10024",
            "0x0100F809", "0x8CE7002C", "0x8FBF002C",
            "0x8FB20028", "0x8FB10024", "0x8FB00020",
            "0x00601021", "0x03E00008", "0x27BD0030",
            "_lw(fingerprint_pc)", "[paf-dispatch-callers]",
            "validation=%d", "jal_matches=%u jump_matches=%u",
            "loaded_words=%u truncated=%u", "scan_offset += 4",
            "scan_opcode == 2 || scan_opcode == 3",
            "zeroCtrlMipsJumpTarget(", "dispatcher_start",
            "[paf-dispatch-caller]", "scan_opcode == 3 ? \"JAL\" : \"J\"",
            "delay_valid = scan_offset <=", "_lw(scan_pc + 4)",
            "reported < 8"):
        if token not in caller_ra:
            fail("PAF JALR window diagnostic lacks " + token)
    if any(label in assembly for label in ("[paf-dispatch-window-",
            "[paf-dispatch-control]", "[paf-jalr-t0-def]",
            "[paf-dispatch-reg-def]", "[paf-dispatch-frame-candidate]",
            "[paf-dispatch-callers]", "[paf-dispatch-caller]")):
        fail("PAF JALR window diagnostic leaked into assembly helpers")
    fingerprint_read = caller_ra.find("_lw(fingerprint_pc)")
    direct_scan = caller_ra.find("for (scan_offset = 0;")
    caller_summary = caller_ra.find('"[paf-dispatch-callers] validation=%d "')
    caller_candidate = caller_ra.find('"[paf-dispatch-caller] index=%u "')
    verbose_window = caller_ra.find('"[paf-dispatch-window-%u]"')
    if not 0 <= fingerprint_read < direct_scan < caller_summary < \
            caller_candidate < verbose_window:
        fail("PAF dispatcher caller scan is not ahead of verbose decoding")
    if caller_ra.count("static const unsigned int fingerprint_offset[]") != 1 or \
            caller_ra.count("dispatcher_start = callsite - 0xA0") != 1 or \
            caller_ra.count('"[paf-dispatch-callers] validation=%d "') != 1 or \
            caller_ra.count('"[paf-dispatch-caller] index=%u "') != 1:
        fail("PAF dispatcher caller scan implementation is duplicated")
    parent_summary = caller_ra.find('"[paf-parent-a0] validation=%d "')
    parent_def = caller_ra.find('"[paf-parent-a0-def] "')
    parent_control = caller_ra.find('"[paf-parent-control] "')
    parent_reaching = caller_ra.find('"[paf-parent-a0-reaching] "')
    if not caller_candidate < parent_summary < parent_def < parent_reaching < \
            verbose_window or parent_control < parent_def:
        fail("PAF parent A0 evidence is not prioritized before verbose output")
    for token in ("unique_caller_pc = scan_pc",
            "dispatcher_start + 0xD8",
            "parent_end = unique_caller_pc + 4",
            "unique_caller_pc - parent_start == 0x1E4",
            "parent_end - owner->text_addr <=", "owner->text_size - 4",
            "0x27BDFFC0", "0xAFB00030", "0x2403FFFF",
            "0xAFBF0038", "0xAFB10034", "0x90820018",
            "0x1440002E", "0x00808021", "0x94820012",
            "0x30420001", "0x1440002A", "0x0E241B07",
            "0xAE2364A0", "jal_matches == 1", "jump_matches == 0",
            "_lw(parent_start +", "_lw(unique_caller_pc + 4)",
            "parent_rt == 4", "parent_rd == 4",
            "[paf-parent-a0-def]", "load ? parent_rs : 0",
            "load ? (short)(parent_instruction &",
            "[paf-parent-control]", "likely=%d",
            "for (phase = 0; phase < 2; phase++)",
            "phase == 0", "phase == 1",
            "zeroCtrlMipsJumpTarget(", "zeroCtrlMipsBranchTarget(",
            "[paf-parent-frame-candidate]",
            "status=ambiguous a0_defs=%u"):
        if token not in caller_ra:
            fail("PAF parent A0 diagnostic lacks " + token)
    if any(label in assembly for label in ("[paf-parent-a0]",
            "[paf-parent-a0-def]", "[paf-parent-control]",
            "[paf-parent-frame-candidate]", "[paf-parent-a0-reaching]")):
        fail("PAF parent A0 diagnostic leaked into assembly helpers")
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
    activation_leaf = assembly[activation_start:activation_end]
    for scalar in ("zeroCtrlSlideActivationCallerRAFirst",
            "zeroCtrlSlideActivationCallerRALast",
            "zeroCtrlSlideActivationCallerRAChanges"):
        if assembly.count(scalar + ": .space 4") != 1:
            fail("activation caller RA lacks exactly one BSS scalar " + scalar)
        if scalar not in activation_leaf:
            fail("activation entry does not record " + scalar)
    if activation_leaf.find("zeroCtrlSlideActivationCallerRAFirst") > \
            activation_leaf.find("zeroCtrlSlideActivationHits") or \
            activation_leaf.find("zeroCtrlSlideActivationCallerRAFirst") > \
            activation_leaf.find("addiu   $sp, $sp, -32"):
        fail("activation caller RA is not captured before existing entry work")
    if any(token in activation_leaf for token in ("lw      $ra", "move    $ra",
            "addu    $ra", "addiu   $ra")) or \
            "sw      $ra, %lo(zeroCtrlSlideActivationCallerRAFirst)" not in \
                activation_leaf or \
            "sw      $ra, %lo(zeroCtrlSlideActivationCallerRALast)" not in \
                activation_leaf:
        fail("activation caller RA capture modifies RA or misses first/last")
    if "addiu   $sp, $sp, -32" not in activation_leaf or \
            "sw      $s1, 4($sp)" not in activation_leaf:
        fail("activation caller RA capture changed Sony prologue reproduction")
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
    state_class_macro = assembly[assembly.find(".macro STATE_ZERO_CLASS"):
        assembly.find(".endm", assembly.find(".macro STATE_ZERO_CLASS"))]
    if state_class_macro.count("zeroCtrlStateZero15To14EffectiveResult") != 2 or \
            "zeroCtrlStateZeroVCallResult" in state_class_macro:
        fail("T30.1 Class15/Class17 routing does not use only the effective result")
    class18_source = assembly[assembly.find("zeroCtrlStateZeroClass18Trace:"):
        assembly.find("zeroCtrlStateZeroClass18TraceEnd:")]
    if "bne     $v1, $t2" not in class18_source or \
            "zeroCtrlStateZero15To14EffectiveResult" in class18_source:
        fail("T30.1 unnecessarily changed Class18 effective-v1 semantics")
    vcall = assembly[assembly.find("zeroCtrlStateZeroVCallTrace:"):
        assembly.find("zeroCtrlStateZeroVCallTraceEnd:")]
    vreturn = assembly[assembly.find("zeroCtrlStateZeroVReturnTrace:"):
        assembly.find("zeroCtrlStateZeroVReturnTraceEnd:")]
    if "sw      $v0, %lo(zeroCtrlStateZeroVCallTarget)" not in vcall or \
            "jr      $v0" not in vcall or \
            "sw      $v0, %lo(zeroCtrlStateZeroVCallResult)" not in vreturn or \
            "lw      $ra, %lo(zeroCtrlStateZeroVCallRA)" not in vreturn:
        fail("T15 virtual-call trace does not preserve target/result/ra")
    for token in ("zeroCtrlStateZero15To14CompatMode", "beqz    $t1, 65f",
            "addiu   $t1, $zero, 15", "bne     $v0, $t1, 65f",
            "addiu   $v0, $zero, 14", "zeroCtrlStateZero15To14SubstitutionHits",
            "\n65:", "zeroCtrlStateZero15To14EffectiveResult"):
        if token not in vreturn:
            fail("T30 state-zero return source lacks " + token)
    if not (vreturn.find("beqz    $t1, 65f") <
            vreturn.find("bne     $v0, $t1, 65f") <
            vreturn.find("addiu   $v0, $zero, 14") < vreturn.find("\n65:") <
            vreturn.find("zeroCtrlStateZero15To14EffectiveResult")):
        fail("T30 source does not guard the exact 15-to-14 substitution")
    for symbol in ("zeroCtrlPostPafReturnTrace",):
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
    post_vsh_call = assembly[assembly.find("zeroCtrlPostVshCallTrace:"):
        assembly.find("zeroCtrlPostVshCallTraceEnd:")]
    post_vsh_return = assembly[assembly.find("zeroCtrlPostVshReturnTrace:"):
        assembly.find("zeroCtrlPostVshReturnTraceEnd:")]
    if post_vsh_call.find("sw      $a0, %lo(zeroCtrlPostVshArgument)") < 0 or \
            post_vsh_call.count("$a0") != 1:
        fail("T31 call wrapper does not capture untouched a0 exactly once")
    for token in ("sw      $v0, %lo(zeroCtrlPostVshNaturalResult)",
            "lw      $t1, %lo(zeroCtrlPostVshCompatMode)", "beqz    $t1, 66f",
            "ori     $t2, $t2, 0x000D", "bne     $t1, $t2, 66f",
            "ori     $t2, $t2, 0x0107", "bne     $v0, $t2, 66f",
            "addu    $v0, $zero, $zero", "zeroCtrlPostVshSubstitutionHits",
            "\n66:", "sw      $v0, %lo(zeroCtrlPostVshEffectiveResult)",
            "lw      $ra, %lo(zeroCtrlPostVshSavedRA)"):
        if token not in post_vsh_return:
            fail("T31 exact return source lacks " + token)
    if not (post_vsh_return.find("zeroCtrlPostVshNaturalResult") <
            post_vsh_return.find("zeroCtrlPostVshCompatMode") <
            post_vsh_return.find("bne     $t1, $t2, 66f") <
            post_vsh_return.find("bne     $v0, $t2, 66f") <
            post_vsh_return.find("addu    $v0, $zero, $zero") <
            post_vsh_return.find("\n66:") <
            post_vsh_return.find("zeroCtrlPostVshEffectiveResult")):
        fail("T31 natural/guard/substitution/effective ordering is invalid")
    post_impose_call = assembly[assembly.find("zeroCtrlPostImposeVCallTrace:"):
        assembly.find("zeroCtrlPostImposeVCallTraceEnd:")]
    post_impose_return = assembly[assembly.find(
        "zeroCtrlPostImposeVCallReturnTrace:"):assembly.find(
        "zeroCtrlPostImposeVCallReturnTraceEnd:")]
    for token in ("sw      $v0, %lo(zeroCtrlPostImposeVCallTarget)",
            "sw      $ra, %lo(zeroCtrlPostImposeVCallSavedRA)",
            "zeroCtrlPostImposeVCallHits", "zeroCtrlPostImposeVCallReturnTrace",
            "jr      $v0"):
        if token not in post_impose_call:
            fail("T32 indirect call wrapper lacks " + token)
    if post_impose_call.count("$v0") != 2 or any(token in post_impose_call for token in
            ("jal ", "jalr", "$gp", "sceIo", "Alloc", "malloc")):
        fail("T32 indirect call wrapper changes target or performs a call/I/O/allocation")
    for token in ("addiu   $sp, $sp, -8", "sw      $t0, 0($sp)",
            "sw      $t1, 4($sp)",
            "sw      $v0, %lo(zeroCtrlPostImposeVCallNaturalResult)",
            "zeroCtrlPostImposeVCallReturnHits",
            "lw      $ra, %lo(zeroCtrlPostImposeVCallSavedRA)",
            "lw      $t1, 4($sp)", "lw      $t0, 0($sp)",
            "addiu   $sp, $sp, 8", "jr      $ra"):
        if token not in post_impose_return:
            fail("T32 indirect return wrapper lacks " + token)
    if post_impose_return.count("$v0") != 1 or any(token in post_impose_return for token in
            ("jal ", "jalr", "$gp", "sceIo", "Alloc", "malloc")):
        fail("T32 return wrapper transforms v0 or performs a call/I/O/allocation")
    t33_call = assembly[assembly.find("zeroCtrlPostMinusOneVCall64Trace:"):
        assembly.find("zeroCtrlPostMinusOneVCall64TraceEnd:")]
    t33_return = assembly[assembly.find("zeroCtrlPostMinusOneVCall64ReturnTrace:"):
        assembly.find("zeroCtrlPostMinusOneVCall64ReturnTraceEnd:")]
    for body, role in ((t33_call, "call"), (t33_return, "return")):
        for token in ("addiu   $sp, $sp, -8", "sw      $t0, 0($sp)",
                "sw      $t1, 4($sp)", "lw      $t1, 4($sp)",
                "lw      $t0, 0($sp)", "addiu   $sp, $sp, 8"):
            if body.count(token) != 1:
                fail("T33 " + role + " wrapper lacks exact frame operation " + token)
        if any(token in body for token in ("jal ", "jalr", "$gp", "sceIo",
                "Alloc", "malloc")):
            fail("T33 " + role + " wrapper calls code or performs I/O/allocation")
    t33_v0_lines = [line for line in t33_return.splitlines() if "$v0" in line]
    if t33_call.count("$v0") != 2 or "jr      $v0" not in t33_call or \
            len(t33_v0_lines) != 3 or \
            "sw      $v0, %lo(zeroCtrlPostMinusOneVCall64NaturalResult)" not in t33_v0_lines[0] or \
            "lw      $t1, 0x364($v0)" not in t33_v0_lines[1] or \
            "lw      $t1, 0x360($v0)" not in t33_v0_lines[2]:
        fail("T33 wrappers transform the indirect target or natural result")
    post_paf_source = assembly[assembly.find("zeroCtrlPostPafReturnTrace:"):
        assembly.find("zeroCtrlPostPafReturnTraceEnd:")]
    for result_symbol in ("zeroCtrlPostPafResult0", "zeroCtrlPostPafResult1"):
        if post_paf_source.count(
                "sw      $v0, %lo(" + result_symbol + ")($t0)") != 1:
            fail("post-BSMan PAF return trace lacks exact store to " + result_symbol)
    fast_poll_start = kernel.find("if (slide_diag.topmenu_validation)")
    fast_poll_end = kernel.find("#undef WRITE_LATE_FLAG", fast_poll_start)
    fast_poll = kernel[fast_poll_start:fast_poll_end]
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
    for token in ("addiu   $sp, $sp, -16", "sw      $t0, 0($sp)",
            "sw      $t1, 4($sp)", "sw      $t2, 8($sp)",
            "sw      $ra, 12($sp)",
            "lw      $t2, %lo(\\target)", "jalr    $t2",
            "sw      $v0, %lo(\\result)($t0)", "lw      $t2, 8($sp)",
            "lw      $t1, 4($sp)", "lw      $t0, 0($sp)",
            "lw      $ra, 12($sp)", "addiu   $sp, $sp, 16", "jr      $ra"):
        if token not in consumer_stub:
            fail("T22 wrapper transparency is missing " + token)
    if "jal " in consumer_stub or consumer_stub.count("jalr    $t2") != 1 or \
            consumer_stub.count("$v0") != 1 or any(token in consumer_stub for token in
            ("sceIo", "Alloc", "malloc")):
        fail("T23 wrapper has an extra call or transforms natural v0")
    compat_13f6c = assembly[assembly.find("zeroCtrlConsumer13F6CTrace:"):
        assembly.find("zeroCtrlConsumer13F6CTraceEnd:")]
    for token in ("jalr    $t2", "zeroCtrlConsumer13F6CNaturalResult",
            "zeroCtrlConsumer13F6CCompatMode", "beqz    $t1, 63f",
            "bnez    $v0, 63f", "addiu   $v0, $zero, 1",
            "zeroCtrlConsumer13F6CSubstitutionHits",
            "zeroCtrlConsumer13F6CEffectiveResult"):
        if token not in compat_13f6c:
            fail("T25 13F6C wrapper lacks " + token)
    mode_bypass_13 = compat_13f6c.find("beqz    $t1, 63f")
    natural_bypass_13 = compat_13f6c.find("bnez    $v0, 63f")
    substitution_13 = compat_13f6c.find("addiu   $v0, $zero, 1")
    no_substitute_13 = compat_13f6c.find("\n63:")
    if min(mode_bypass_13, natural_bypass_13, substitution_13,
            no_substitute_13) < 0 or not (mode_bypass_13 < natural_bypass_13 <
            substitution_13 < no_substitute_13):
        fail("T25 source does not route both bypasses around substitution to 63")
    compat_stub = assembly[assembly.find("zeroCtrlConsumer14020Trace:"):
        assembly.find("zeroCtrlConsumer14020TraceEnd:")]
    for token in ("jalr    $t2", "zeroCtrlConsumer14020NaturalResult",
            "zeroCtrlConsumer14020CompatMode", "beqz    $t1",
            "bnez    $v0", "addiu   $v0, $zero, 1",
            "zeroCtrlConsumer14020SubstitutionHits",
            "zeroCtrlConsumer14020EffectiveResult"):
        if token not in compat_stub:
            fail("T24 14020 wrapper lacks " + token)
    mode_bypass = compat_stub.find("beqz    $t1, 62f")
    natural_bypass = compat_stub.find("bnez    $v0, 62f")
    substitution = compat_stub.find("addiu   $v0, $zero, 1")
    no_substitute = compat_stub.find("\n62:")
    if min(mode_bypass, natural_bypass, substitution, no_substitute) < 0 or \
            not mode_bypass < natural_bypass < substitution < no_substitute:
        fail("T24 source does not route both bypasses around substitution to 62")
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
        "CALLSITE_13F6C_RESULT_RANGE_INVALID",
        "CALLSITE_14020_RESULT_RANGE_INVALID",
        "CALLSITE_14020_COMPAT_MODE_RANGE_INVALID",
        "CALLSITE_14020_EFFECTIVE_RESULT_RANGE_INVALID",
        "CALLSITE_14020_SUBSTITUTION_HITS_RANGE_INVALID",
        "CALLSITE_13F6C_COMPAT_MODE_RANGE_INVALID",
        "CALLSITE_13F6C_EFFECTIVE_RESULT_RANGE_INVALID",
        "CALLSITE_13F6C_SUBSTITUTION_HITS_RANGE_INVALID",
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
    result_symbols = (
        "zeroCtrlConsumer13F6CNaturalResult",
        "zeroCtrlConsumer14020NaturalResult",
    )
    if any(assembly.count(symbol + ": .space 4") != 1
            for symbol in result_symbols):
        fail("T23 does not define exactly two natural-result scalars")
    for field in ("consumer_13f6c_result_addr", "consumer_14020_result_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T23 registration does not validate " + field)
    for field in ("consumer_14020_compat_mode_addr",
            "consumer_14020_effective_result_addr",
            "consumer_14020_substitution_hits_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T24 registration does not validate " + field)
    for field in ("consumer_13f6c_compat_mode_addr",
            "consumer_13f6c_effective_result_addr",
            "consumer_13f6c_substitution_hits_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T25 registration does not validate " + field)
    result_init = consumers_install.find(
        "_sw(0xFFFFFFFF, bsman->consumer_result_addr[i])")
    if result_init < 0 or result_init > consumer_commit or \
            "zeroCtrlVshModuleRangeValid(helper,\n                    bsman->consumer_result_addr[i], 4)" not in consumers_install:
        fail("T23 results are not validated and initialized before VSH commit")
    if writer.find("[vsh-6f84-consumers-natural]") < 0 or \
            "consumer_pre_slide_result[0]" not in bsman_install or \
            "consumer_pre_slide_result[1]" not in bsman_install:
        fail("T23 natural results are not snapshotted and deferred")
    if "PSP1000PafPresentCompat = Disabled" not in sample_config:
        fail("callsite PAF compatibility experiment is not default-disabled")
    if "PSP1000Consumer14020Compat = Disabled" not in sample_config or \
            '"PSP1000Consumer14020Compat", "Disabled"' not in kernel:
        fail("T24 compatibility is not default-disabled")
    if "PSP1000Consumer13F6CCompat = Disabled" not in sample_config or \
            '"PSP1000Consumer13F6CCompat", "Disabled"' not in kernel:
        fail("T25 compatibility is not default-disabled")
    t25_gate = kernel[kernel.find("consumer_13f6c_compat_enabled ="):
        kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
            "consumer_13f6c_compat_enabled ="))]
    for gate in ('devkit == 0x06060110',
            'strcmp(psp1000Diagnostics, "Enabled") == 0',
            '"DangerousCaller58D4"',
            'strcmp(psp1000Consumer13F6CCompat, "Enabled") == 0'):
        if gate not in t25_gate:
            fail("T25 compatibility gating lacks " + gate)
    if "ZERO_TRIGGER_13F6C" in t25_gate:
        fail("T25 compatibility enables the legacy 13F6C direct trigger")
    for scalar in T25_SCALARS:
        if assembly.count(scalar + ": .space 4") != 1:
            fail("T25 does not define exactly one fixed scalar " + scalar)
    t25_validation = consumers_install.find(
        "consumer_13f6c_compat_mode_addr, 4")
    if t25_validation < 0 or t25_validation > guard_success:
        fail("T25 scalar validation does not precede transaction success")
    for initialization in (
            "_sw(bsman->consumer_13f6c_compat_enabled ? 1 : 0,",
            "_sw(0xFFFFFFFF, bsman->consumer_13f6c_effective_result_addr)",
            "_sw(0, bsman->consumer_13f6c_substitution_hits_addr)"):
        position = consumers_install.find(initialization)
        if position < guard_success or position > consumer_commit:
            fail("T25 scalar initialization is outside the guarded transaction")
    if "[vsh-6f84-14020-compat]" not in writer:
        fail("T24 deferred compatibility diagnostic is missing")
    if "[vsh-6f84-13f6c-compat]" not in writer:
        fail("T25 deferred compatibility diagnostic is missing")
    if "PSP1000PafCapabilityMaskCompat = Disabled" not in sample_config or \
            '"PSP1000PafCapabilityMaskCompat", "Disabled"' not in kernel:
        fail("T28 PAF mask compatibility is not default-disabled")
    t28_gate = kernel[kernel.find("paf_mask_compat_enabled ="):
        kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
            "paf_mask_compat_enabled ="))]
    for gate in ('devkit == 0x06060110',
            'strcmp(psp1000Diagnostics, "Enabled") == 0',
            '"DangerousCaller58D4"',
            'strcmp(psp1000PafCapabilityMaskCompat, "Enabled") == 0'):
        if gate not in t28_gate:
            fail("T28 mask compatibility gating lacks " + gate)
    if "PSP1000StateZero15To14Compat = Disabled" not in sample_config or \
            '"PSP1000StateZero15To14Compat", "Disabled"' not in kernel:
        fail("T30 state-zero compatibility is not default-disabled")
    t30_gate = kernel[kernel.find("state_zero_15to14_compat_enabled ="):
        kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
            "state_zero_15to14_compat_enabled ="))]
    for gate in ('devkit == 0x06060110',
            'strcmp(psp1000Diagnostics, "Enabled") == 0',
            '"DangerousCaller58D4"',
            'strcmp(psp1000StateZero15To14Compat, "Enabled") == 0'):
        if gate not in t30_gate:
            fail("T30 state-zero compatibility gating lacks " + gate)
    if "[state-zero-15to14-compat]" not in writer:
        fail("T30 deferred state-zero compatibility diagnostic is missing")
    for field in ("state_zero_15to14_compat_mode_addr",
            "state_zero_15to14_effective_result_addr",
            "state_zero_15to14_substitution_hits_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T30 registration does not range-validate " + field)
    for initialization in (
            "_sw(bsman->state_zero_15to14_compat_enabled ? 1 : 0,",
            "_sw(0xFFFFFFFF, bsman->state_zero_15to14_effective_result_addr)",
            "_sw(0, bsman->state_zero_15to14_substitution_hits_addr)"):
        if initialization not in bsman_install:
            fail("T30 scalar initialization is missing " + initialization)
    if "PSP1000ImposeParam8000000DCompat = Disabled" not in sample_config or \
            '"PSP1000ImposeParam8000000DCompat", "Disabled"' not in kernel:
        fail("T31 impose compatibility is not default-disabled")
    t31_gate = kernel[kernel.find("post_vsh_compat_enabled ="):
        kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
            "post_vsh_compat_enabled ="))]
    for gate in ("slide_diag.bsman.activation_enabled",
            'strcmp(psp1000ImposeParam8000000DCompat, "Enabled") == 0'):
        if gate not in t31_gate:
            fail("T31 impose compatibility gating lacks " + gate)
    if "state_zero_15to14_compat_enabled" in t31_gate:
        fail("T31 impose compatibility still depends on the T30 experiment")
    if "[vsh-impose-param-8000000d-compat]" not in writer:
        fail("T31 deferred impose diagnostic is missing")
    for field in ("post_vsh_argument_addr", "post_vsh_compat_mode_addr",
            "post_vsh_effective_result_addr", "post_vsh_substitution_hits_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T31 registration does not range-validate " + field)
    for initialization in ("_sw(0xFFFFFFFF, bsman->post_vsh_argument_addr)",
            "_sw(bsman->post_vsh_compat_enabled ? 1 : 0,",
            "_sw(0xFFFFFFFF, bsman->post_vsh_effective_result_addr)",
            "_sw(0, bsman->post_vsh_substitution_hits_addr)"):
        if initialization not in bsman_install:
            fail("T31 scalar initialization is missing " + initialization)
    if "PSP1000PostImposeVCallTrace = Disabled" not in sample_config or \
            '"PSP1000PostImposeVCallTrace", "Disabled"' not in kernel:
        fail("T32 trace is not default-disabled")
    t32_gate = kernel[kernel.find("post_impose_vcall_enabled ="):
        kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
            "post_impose_vcall_enabled ="))]
    if "slide_diag.bsman.post_vsh_compat_enabled" not in t32_gate or \
            'strcmp(psp1000PostImposeVCallTrace, "Enabled") == 0' not in t32_gate:
        fail("T32 trace does not require the exact T31 gate and explicit opt-in")
    for token in ("post_impose_vcall_original[0] != 0x0040F809",
            "post_impose_vcall_original[1] != 0",
            "bsman->activation_addr + 0x120",
            "bsman->post_impose_vcall_validation = 1"):
        if token not in bsman_install:
            fail("T32 activation transaction lacks " + token)
    for field in ("post_impose_vcall_target_addr",
            "post_impose_vcall_saved_ra_addr",
            "post_impose_vcall_natural_result_addr",
            "post_impose_vcall_hits_addr",
            "post_impose_vcall_return_hits_addr"):
        if "CHECK_POST_SCALAR(" + field + ")" not in kernel:
            fail("T32 registration does not range-validate " + field)
    if bsman_install.count("bsman->activation_addr + 0x120") < 4 or \
            bsman_install.count("_sw(bsman->post_impose_vcall_replacement,") != 1:
        fail("T32 does not retain one validated activation+0x120 patch owner")
    if "[post-impose-vcall-50]" not in writer:
        fail("T32 deferred diagnostic is missing")
    if "PSP1000PostMinusOneVCall64Trace = Disabled" not in sample_config or \
            '"PSP1000PostMinusOneVCall64Trace", "Disabled"' not in kernel:
        fail("T33 trace is not default-disabled")
    t33_gate = kernel[kernel.find("post_minus_one_vcall64_enabled ="):
        kernel.find(";", kernel.find("post_minus_one_vcall64_enabled ="))]
    if "post_impose_vcall_enabled" not in t33_gate or \
            'strcmp(psp1000PostMinusOneVCall64Trace, "Enabled") == 0' not in t33_gate:
        fail("T33 trace does not require the T32/T31 gate and explicit opt-in")
    for token in ("post_minus_one_vcall64_original[0] != 0x0040F809",
            "post_minus_one_vcall64_original[1] != 0x0000A021",
            "bsman->activation_addr + 0x138",
            "bsman->post_minus_one_vcall64_validation = 1"):
        if token not in bsman_install:
            fail("T33 activation transaction lacks " + token)
    if bsman_install.count("_sw(bsman->post_minus_one_vcall64_replacement,") != 1 or \
            "bsman->activation_addr + 0x13C" in bsman_install[bsman_install.find(
                "/* Transaction commit"):]:
        fail("T33 does not retain one +0x138 owner or overwrites its delay slot")
    if "[post-minus-one-vcall-64]" not in writer or \
            "target_offset == 0x1F8E0" not in writer:
        fail("T33 deferred target-offset diagnostic is missing")
    for field in ("post_minus_one_vcall64_target_addr",
            "post_minus_one_vcall64_saved_ra_addr",
            "post_minus_one_vcall64_natural_result_addr",
            "post_minus_one_vcall64_hits_addr",
            "post_minus_one_vcall64_return_hits_addr"):
        if ("CHECK_POST_SCALAR(" + field + ")") not in kernel:
            fail("T33 registration does not range-validate " + field)
    if "sizeof(ZeroCtrlBSManClosedRegistration) == 1012" not in bsman_header:
        fail("legacy registration ABI is not exactly 1012 bytes")
    # T40 is one default-disabled, all-or-none, observation-only bundle.
    if "PSP1000ActivationWideTrace = Disabled" not in sample_config or \
            '"PSP1000ActivationWideTrace", "Disabled"' not in kernel:
        fail("T40 wide activation trace is not default-disabled")
    caller_register_start = kernel.find("void zeroCtrlRegisterActivationCallerRA(")
    caller_register_end = kernel.find("void zeroCtrlRecordVshSlideTarget(",
            caller_register_start)
    caller_register = kernel[caller_register_start:caller_register_end]
    for token in ("bsman->activation_enabled", "bsman->registered",
            'sceKernelFindModuleByName("ZeroVSH_Patcher_User")',
            "((unsigned int)helper & 3) != 0",
            "(unsigned int)helper < 0x88000000",
            "(unsigned int)helper >= 0x8C000000",
            "helper->text_addr == 0", "helper->text_size == 0",
            "helper->nsegment == 0", "helper->nsegment > 4",
            "(address[index] & 3) != 0",
            "zeroCtrlVshModuleRangeValid(helper, address[index], 4)",
            "for (index = 0; index < 3; index++)",
            "bsman->activation_caller_ra_validation = 1",
            "_sw(0, address[index])",
            "sceKernelDcacheWritebackInvalidateRange((const void *)address[index], 4)",
            "bsman->activation_caller_ra_registered = 1"):
        if token not in caller_register:
            fail("activation caller RA registration lacks " + token)
    validation = caller_register.find("zeroCtrlVshModuleRangeValid")
    initialization = caller_register.find("_sw(0, address[index])")
    registered = caller_register.find(
            "bsman->activation_caller_ra_registered = 1")
    if caller_register_start < 0 or not 0 <= validation < initialization < registered or \
            "sceKernelIcache" in caller_register or \
            "activation_addr" in caller_register:
        fail("activation caller RA registration ordering patches code or is unsafe")
    if "PSP_EXPORT_FUNC_NID(zeroCtrlRegisterActivationCallerRA, 0x1337357E)" \
            not in kernel_exports or \
            "STUB_FUNC 0x1337357E, zeroCtrlRegisterActivationCallerRA" \
            not in user_imports:
        fail("activation caller RA registration import/export is missing")
    caller_user_registration = user[user.find(
        "zeroCtrlRegisterBSManClosedShim(&bsmanClosedRegistration);"):
        user.find("sctrlHENSetStartModuleHandler(OnModuleStart)")]
    for token in ("zeroCtrlRegisterActivationCallerRA(",
            "&zeroCtrlSlideActivationCallerRAFirst",
            "&zeroCtrlSlideActivationCallerRALast",
            "&zeroCtrlSlideActivationCallerRAChanges"):
        if token not in caller_user_registration:
            fail("activation caller RA user registration lacks " + token)
    if "scalar_addr[54]" not in bsman_header or \
            "leaf_addr[11]" not in bsman_header or \
            "sizeof(ZeroCtrlActivationWideRegistration) == 304" not in bsman_header:
        fail("optional T40 registration fields are incomplete")
    for token in ("copied.leaf_addr[wide_index]",
            "copied.scalar_addr[wide_index], 4",
            "zeroCtrlVshModuleRangeValid(helper,\n"
            "                        bsman->activation_wide_leaf_addr[wide_index]",
            "bsman->activation_wide_validation = 1",
            "bsman->activation_wide_install = 1",
            "bsman->activation_wide_cache_sync = 1"):
        if token not in kernel:
            fail("T40 registration/transaction lacks " + token)
    legacy_register = kernel[kernel.find("void zeroCtrlRegisterBSManClosedShim("):
            kernel.find("int zeroCtrlRegisterActivationWide(")]
    optional_register = kernel[kernel.find("int zeroCtrlRegisterActivationWide("):
            kernel.find("void zeroCtrlRecordVshSlideTarget(")]
    if "ZeroCtrlBSManClosedRegistration copied;" not in legacy_register or \
            "activation_wide" in legacy_register:
        fail("disabled T40 still changes or can block legacy registration")
    if "if (!registration) return bsman->activation_wide_enabled;" not in \
            optional_register or \
            optional_register.find("if (!registration)") > optional_register.find("memcpy("):
        fail("optional T40 registration does not gate before descriptor copying")
    legacy_call = user.find("zeroCtrlRegisterBSManClosedShim(&bsmanClosedRegistration);")
    t40_query = user.find("if (zeroCtrlRegisterActivationWide(NULL))")
    t40_population = user.find("activationWideRegistration.leaf_addr[0]")
    handler_install = user.find("sctrlHENSetStartModuleHandler(OnModuleStart)", t40_population)
    if min(legacy_call, t40_query, t40_population, handler_install) < 0 or not \
            legacy_call < t40_query < t40_population < handler_install:
        fail("user T40 population is not optional and after legacy registration")
    if "PSP_EXPORT_FUNC_NID(zeroCtrlRegisterActivationWide, 0x1337357D)" not in \
            kernel_exports or \
            "STUB_FUNC 0x1337357D, zeroCtrlRegisterActivationWide" not in user_imports:
        fail("optional T40 registration export/import is missing")
    if "zeroCtrlTextRangeValid" in kernel or "bsman->helper" in kernel:
        fail("T40 uses an invented helper range API or evidence member")
    if "static const unsigned int offset[7]" in kernel or \
            "static const unsigned int offset[8]" in kernel:
        fail("masked PAF offset arrays shadow the installer's offset local")
    t40_initialize = kernel.find(
            "for (wide_index = 0; wide_index < 54; wide_index++)\n"
            "                _sw(0, bsman->activation_wide_scalar_addr[wide_index]);")
    t40_scalar_sync = kernel.find(
            "/* Routing and counters must be coherent before any owner is live. */",
            t40_initialize)
    t40_patch_write = kernel.find(
            "_sw(bsman->activation_wide_replacement[wide_index]",
            t40_scalar_sync)
    t40_code_sync = kernel.find(
            "sceKernelIcacheInvalidateRange(\n"
            "                        (const void *)(bsman->activation_addr +\n"
            "                            wide_offset[wide_index]), 4);",
            t40_patch_write)
    t40_install_flag = kernel.find("bsman->activation_wide_install = 1;",
            t40_code_sync)
    t40_cache_flag = kernel.find("bsman->activation_wide_cache_sync = 1;",
            t40_install_flag)
    if min(t40_initialize, t40_scalar_sync, t40_patch_write, t40_code_sync,
            t40_install_flag, t40_cache_flag) < 0 or not (
            t40_initialize < t40_scalar_sync < t40_patch_write < t40_code_sync <
            t40_install_flag < t40_cache_flag):
        fail("T40 scalar initialization/cache and code commit ordering is unsafe")
    scalar_sync = kernel[t40_scalar_sync:t40_patch_write]
    if "for (wide_index = 0; wide_index < 54; wide_index++)" not in scalar_sync or \
            "sceKernelDcacheWritebackInvalidateRange(" not in scalar_sync or \
            "activation_wide_scalar_addr[\n                            wide_index], 4" not in scalar_sync or \
            "sceKernelIcacheInvalidateRange" in scalar_sync:
        fail("T40 does not D-cache synchronize all 52 data scalars")
    code_commit = kernel[t40_patch_write:t40_install_flag]
    if "for (wide_index = 0; wide_index < 6; wide_index++)" not in \
            code_commit or "sceKernelDcacheWritebackInvalidateRange(" not in \
            code_commit or "sceKernelIcacheInvalidateRange(" not in code_commit:
        fail("T40 does not synchronize all six code patches before success")
    t40_validation = kernel[kernel.find("if (bsman->activation_wide_enabled) {",
            kernel.find("static void zeroCtrlInstallBSManClosedShim")):
            t40_initialize]
    for token in ("bsman->activation_wide_pre_original =",
            "_lw(bsman->activation_addr + 0x1E8)",
            "(bsman->activation_wide_pre_original >> 26) != 3",
            "bsman->activation_addr - 0x9304 + 0x2A168",
            "_lw(bsman->activation_addr + 0x1EC) != 0",
            "bsman->activation_wide_pre_replacement = 0x0C000000",
            "bsman->activation_wide_leaf_addr[10]"):
        if token not in t40_validation:
            fail("T40 +0x1E8 entry validation lacks " + token)
    pre_scalar_init = kernel.find(
            "_sw(bsman->activation_addr - 0x9304 + 0x2A168,\n"
            "                    bsman->activation_wide_scalar_addr[52]);",
            t40_initialize)
    pre_patch = kernel.find("_sw(bsman->activation_wide_pre_replacement,",
            t40_scalar_sync)
    pre_code_sync = kernel.find(
            "(const void *)(bsman->activation_addr + 0x1E8), 4);",
            pre_patch)
    if min(pre_scalar_init, pre_patch, pre_code_sync) < 0 or not (
            pre_scalar_init < t40_scalar_sync < pre_patch < pre_code_sync <
            t40_install_flag):
        fail("T40 +0x1E8 scalar/patch cache ordering is unsafe")
    entry_helper = assembly[assembly.find("zeroCtrlWide02374143Entry:"):
            assembly.find("zeroCtrlWide02374143EntryEnd:")]
    for token in ("sw $t0, 0($sp)", "sw $t1, 4($sp)",
            "zeroCtrlWide02374143Hits", "zeroCtrlWide02374143Target",
            "jr $t0", "lw $t0, -8($sp)"):
        if token not in entry_helper:
            fail("T40 +0x1E8 entry helper lacks " + token)
    if any(token in entry_helper for token in ("$ra", "$v0", "$a0", "$a1",
            "$a2", "$a3", "$s0", "jal", "sce", "malloc")):
        fail("T40 +0x1E8 entry helper changes live state or performs a call/I/O")
    for word in ("0x1040000C", "0x1040FFF2", "0x26100001",
            "0x8FBF001C", "0x00002021"):
        if word not in kernel:
            fail("T40 Sony fingerprint lacks " + word)
    for offset in ("0x1F8", "0x200", "0x20C", "0x214", "0x21C", "0x22C"):
        if kernel.count(offset) < 2:
            fail("T40 lacks unique validated patch owner for " + offset)
    for helper in ("zeroCtrlActivationWideCompareTrace", "zeroCtrlWide662Call",
            "zeroCtrlWide440Call", "zeroCtrlWideFCFCall",
            "zeroCtrlActivationWideLoopTrace", "zeroCtrlWide090Call"):
        if helper not in assembly or helper not in user:
            fail("T40 helper is not declared/registered: " + helper)
    if "WIDE_DECISION" not in assembly or "WIDE_CALL" not in assembly or \
            "jal " in assembly[assembly.find("/* T40 wide activation diagnostics"):] or \
            "zeroCtrlMipsBranchTarget" not in kernel:
        fail("T40 transparency or branch-target validation regressed")
    for label in ("[activation-wide-compare]", "662922b9", "440665db",
            "fcf265d8", "[activation-wide-loop]", "090ccb3f"):
        if label not in kernel:
            fail("T40 deferred diagnostic missing " + label)
    writer_start = kernel.find("static int zeroCtrlWriteSlideDiagnostics(")
    writer_end = kernel.find("static void zeroCtrlCreateSlideDiagnosticsThread(",
            writer_start)
    writer = kernel[writer_start:writer_end]
    early_start = writer.find("if (slide_diag.bsman.activation_wide_enabled)")
    early_end = writer.find("if (slide_diag.sony_start_trace.enabled)",
            early_start)
    early = writer[early_start:early_end]
    if early_start < 0 or early_end < 0 or \
            "[activation-wide-early]" not in early:
        fail("T40 compact early diagnostic is missing from the writer thread")
    for token in ("registered=%d validation=%d", "install=%d cache_sync=%d",
            "compare=%u/%u/%u", "662=%u/%u/%u", "440=%u/%u/%u",
            "fcf=%u/%u/%u", "loop=%u/%u/%u", "090=%u/%u/%u",
            "pre02374143=%u", "activation_wide_scalar_addr[53]",
            "scalar_index[18]", "zeroCtrlReadHelperCounter(",
            "memcpy(observed_wide_early, current, sizeof(current))"):
        if token not in early:
            fail("T40 early snapshot lacks " + token)
    if any(token in early for token in ("_sw(", "sceKernelDcache",
            "sceKernelIcache", "activation_wide_replacement")):
        fail("T40 early snapshot modifies hot-path or patch state")
    for later in ("[state-zero-vcall-resolve]", "[topmenu-state]",
            "post_bsman_counts="):
        if writer.find("[activation-wide-early]") > writer.find(later):
            fail("T40 early snapshot is ordered after verbose " + later)
    if "[activation-wide-early]" in assembly:
        fail("T40 early file output leaked into assembly helpers")
    if "[activation-prewide-early]" not in early:
        fail("early T37/T38/T39 evidence is missing from the writer thread")
    for token in ("t37=%u/%u/0x%08X", "t38=%u/%u/0x%08X",
            "t39=%u/%u/0x%08X",
            "post_collection_paf_fcf265d8_hits_addr",
            "post_collection_paf_fcf265d8_nonzero_hits_addr",
            "post_collection_paf_fcf265d8_natural_result_addr",
            "masked_paf_c59fc3d0_hits_addr",
            "masked_paf_c59fc3d0_nonzero_hits_addr",
            "masked_paf_c59fc3d0_decision_value_addr",
            "masked_paf_c59fc3d0_second_hits_addr",
            "masked_paf_c59fc3d0_second_nonzero_hits_addr",
            "masked_paf_c59fc3d0_second_decision_value_addr",
            "observed_prewide_early[9]", "observed_prewide_early_ready"):
        if token not in writer:
            fail("early T37/T38/T39 snapshot lacks " + token)
    prewide_start = early.find("if (bsman->registered)")
    prewide_end = early.find("if (slide_diag.sony_start_trace.enabled)",
            prewide_start)
    prewide = early[prewide_start:prewide_end]
    if prewide_start < 0 or any(token in prewide for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache",
            "activation_wide_replacement")):
        fail("early T37/T38/T39 snapshot modifies patch or cache state")
    if "[activation-prewide-early]" in assembly:
        fail("early T37/T38/T39 output leaked into assembly helpers")
    if "[activation-collection-early]" not in early:
        fail("early T33-T36 collection evidence is missing from the writer")
    for token in ("enabled=%d", "t33=%u/%u/0x%08X",
            "t34=%u/%u/0x%08X", "t35=%u/%u/0x%08X/0x%08X",
            "t36=%u/%u/0x%08X/0x%08X",
            "post_minus_one_vcall64_hits_addr",
            "post_minus_one_vcall64_return_hits_addr",
            "post_minus_one_vcall64_natural_result_addr",
            "post_minus_one_vcall64_count_snapshot_addr",
            "post_minus_one_vcall64_array_read_hits_addr",
            "post_minus_one_vcall64_array_snapshot_addr",
            "collection_paf_fcf265d8_hits_addr",
            "collection_paf_fcf265d8_nonzero_hits_addr",
            "collection_paf_fcf265d8_natural_result_addr",
            "collection_paf_fcf265d8_last_item_addr",
            "collection_paf_9a285882_hits_addr",
            "collection_paf_9a285882_nonzero_hits_addr",
            "collection_paf_9a285882_natural_result_addr",
            "collection_paf_9a285882_last_item_addr",
            "observed_collection_early[14]",
            "observed_collection_early_ready",
            "observed_collection_enabled"):
        if token not in writer:
            fail("early T33-T36 collection snapshot lacks " + token)
    collection_start = early.find("unsigned int collection[14]")
    collection = early[collection_start:]
    if collection_start < 0 or any(token in collection for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache",
            "activation_wide_replacement")):
        fail("early T33-T36 collection snapshot modifies patch/cache state")
    for later in ("[state-zero-vcall-resolve]", "[topmenu-state]",
            "post_bsman_counts="):
        if writer.find("[activation-collection-early]") > writer.find(later):
            fail("early T33-T36 collection snapshot follows verbose " + later)
    if "[activation-collection-early]" in assembly:
        fail("early T33-T36 collection output leaked into assembly helpers")
    for label in ("[activation-post-early]", "[activation-post-early-call]"):
        if label not in early:
            fail("early post-BSMan snapshot is missing " + label)
    for token in ("mask=0x%03X", "bs=%u/%u", "state=%u/%u/0x%08X",
            "paf0=%u/%u/0x%08X", "paf1=%u/%u/0x%08X",
            "vsh=%u/%u/arg:0x%08X/nat:0x%08X/",
            "eff:0x%08X/sub:%u",
            "t32=%u/%u/target:0x%08X/nat:0x%08X",
            "post_path_mask_addr", "post_bs_counter_addr[0]",
            "post_bs_counter_addr[1]", "post_state_counter_addr[0]",
            "post_state_counter_addr[1]", "post_state_natural_value_addr",
            "post_paf_entry_counter_addr[0]",
            "post_paf_return_counter_addr[0]", "post_paf_result_addr[0]",
            "post_paf_entry_counter_addr[1]",
            "post_paf_return_counter_addr[1]", "post_paf_result_addr[1]",
            "post_vsh_entry_hits_addr", "post_vsh_return_hits_addr",
            "post_vsh_argument_addr", "post_vsh_natural_result_addr",
            "post_vsh_effective_result_addr",
            "post_vsh_substitution_hits_addr",
            "post_impose_vcall_hits_addr",
            "post_impose_vcall_return_hits_addr",
            "post_impose_vcall_target_addr",
            "post_impose_vcall_natural_result_addr",
            "observed_post_early[22]", "observed_post_early_ready"):
        if token not in writer:
            fail("early post-BSMan snapshot lacks " + token)
    post_early_start = early.find("unsigned int post[22]")
    post_early = early[post_early_start:]
    if post_early_start < 0 or any(token in post_early for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache",
            "activation_wide_replacement")):
        fail("early post-BSMan snapshot modifies patch/cache state")
    for later in ("[state-zero-vcall-resolve]", "[topmenu-state]",
            "post_bsman_counts="):
        if writer.find("[activation-post-early]") > writer.find(later):
            fail("early post-BSMan snapshot follows verbose " + later)
    if "[activation-post-early]" in assembly or \
            "[activation-post-early-call]" in assembly:
        fail("early post-BSMan output leaked into assembly helpers")
    gap_start = writer.find("unsigned int word_f0 = _lw(")
    gap_end = writer.find("if (bsman->post_collection_paf_fcf265d8_enabled)",
            gap_start)
    gap = writer[gap_start:gap_end]
    for token in ("bsman->activation_addr + 0xF0",
            "bsman->activation_addr + 0xF4", "[post-paf0-gap]",
            "word_f0=0x%08X", "word_f4=0x%08X", "opcode=0x%02X",
            "conditional_branch", "zeroCtrlMipsBranchTarget(",
            "branch_target=0x%08X", "target_offset=0x%08X"):
        if token not in gap:
            fail("read-only post-PAF0 gap diagnostic lacks " + token)
    if gap_start < 0 or gap_end < 0 or any(token in gap for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache")):
        fail("post-PAF0 gap diagnostic is not read-only")
    if "[post-paf0-gap]" in assembly:
        fail("post-PAF0 gap diagnostic leaked into assembly helpers")
    exit_start = writer.find("static const unsigned int exit_offsets[18]")
    exit_end = writer.find("if (bsman->post_collection_paf_fcf265d8_enabled)",
            exit_start)
    exit_window = writer[exit_start:exit_end]
    for offset in range(0x234, 0x279, 4):
        if "0x%03X" % offset not in exit_window:
            fail("T40 exit window lacks static read offset 0x%03X" % offset)
    for token in ("exit_words[exit_index] = _lw(bsman->activation_addr +",
            "[t40-exit-window-%u]", "[t40-exit-control]",
            "word=0x%08X", "opcode=0x%02X", "rs=%u", "rt=%u",
            "zeroCtrlMipsJumpTarget(pc, word)",
            "zeroCtrlMipsBranchTarget(pc, word)", "target=0x%08X",
            "target_offset=0x%08X", "direct_jump || branch || register_jump"):
        if token not in exit_window:
            fail("read-only T40 exit-window diagnostic lacks " + token)
    if exit_start < 0 or exit_end < 0 or any(token in exit_window for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache")):
        fail("T40 exit-window diagnostic is not read-only")
    for label in ("[t40-exit-window-", "[t40-exit-control]"):
        if label in assembly:
            fail("T40 exit-window output leaked into assembly helpers")
    if ("_sw(bsman->activation_addr + 0x234,\n"
            "                    bsman->activation_wide_scalar_addr[45]);") \
            not in kernel:
        fail("T40 090 wrapper resume is not activation+0x234")
    natural_start = writer.find("static const unsigned int natural_offsets[26]")
    natural_end = writer.find(
            "if (bsman->post_collection_paf_fcf265d8_enabled)", natural_start)
    natural_window = writer[natural_start:natural_end]
    for offset in range(0x4C, 0xB1, 4):
        if "0x%03X" % offset not in natural_window:
            fail("natural +0x50 window lacks static read offset 0x%03X" % offset)
    for token in ("natural_words[natural_index] = _lw(",
            "[natural-50-window-%u]", "[natural-50-window-4]",
            "[natural-50-control]", "word=0x%08X", "opcode=0x%02X",
            "rs=%u", "rt=%u", "zeroCtrlMipsJumpTarget(pc, word)",
            "zeroCtrlMipsBranchTarget(pc, word)", "target=0x%08X",
            "target_offset=0x%08X", "direct_jump || branch || register_jump"):
        if token not in natural_window:
            fail("read-only natural +0x50 diagnostic lacks " + token)
    if natural_start < 0 or natural_end < 0 or any(
            token in natural_window for token in (
                "_sw(", "sceKernelDcache", "sceKernelIcache")):
        fail("natural +0x50 instruction diagnostic is not read-only")
    for label in ("[natural-50-window-", "[natural-50-control]"):
        if label in assembly:
            fail("natural +0x50 diagnostic leaked into assembly helpers")
    callers_start = writer.find(
            'SceModule2 *slide = sceKernelFindModuleByName(\n'
            '                                "slide_plugin_module")')
    callers_end = writer.find(
            "if (bsman->post_collection_paf_fcf265d8_enabled)", callers_start)
    callers = writer[callers_start:callers_end]
    for token in ("slide->text_addr", "slide->text_size",
            "scan_offset + 8 <=", "word = _lw(pc)",
            "(word >> 26) == 3", "(word >> 26) == 2",
            "zeroCtrlMipsJumpTarget(pc, word) ==",
            "bsman->activation_addr", "[activation-callers]",
            "[activation-caller]", "[activation-jump]",
            "delay=0x%08X", "_lw(pc + 4)", "return=0x%08X", "pc + 8"):
        if token not in callers:
            fail("read-only activation direct-caller scan lacks " + token)
    if callers_start < 0 or callers_end < 0 or any(token in callers for token in (
            "_sw(", "sceKernelDcache", "sceKernelIcache", "jalr")):
        fail("activation direct-caller scan is not read-only/direct-only")
    for label in ("[activation-callers]", "[activation-caller]",
            "[activation-jump]"):
        if label in assembly:
            fail("activation caller-scan output leaked into assembly helpers")
    if "PSP1000PostVCall64CollectionTrace = Disabled" not in sample_config or \
            '"PSP1000PostVCall64CollectionTrace", "Disabled"' not in kernel:
        fail("T34 collection trace is not default-disabled")
    t34_gate = kernel[kernel.find("post_vcall64_collection_enabled ="):
        kernel.find(";", kernel.find("post_vcall64_collection_enabled ="))]
    if "post_minus_one_vcall64_enabled" not in t34_gate or \
            'strcmp(psp1000PostVCall64CollectionTrace, "Enabled") == 0' not in t34_gate:
        fail("T34 does not depend on T33 and its explicit opt-in")
    for token in ("lw      $t1, 0x364($v0)", "beqz    $t1, 67f",
            "lw      $t1, 0x360($v0)", "\n67:"):
        if token not in t33_return:
            fail("T34 return tracer lacks " + token)
    if not (t33_return.find("0x364($v0)") < t33_return.find("beqz    $t1, 67f",
            t33_return.find("0x364($v0)")) < t33_return.find("0x360($v0)") <
            t33_return.find("\n67:")):
        fail("T34 array read is not guarded by the natural nonzero count")
    if t33_return.count("beqz    $t1, 67f") != 2:
        fail("T34 mode/count bypasses do not share the exact skip label")
    for scalar in ("CollectionEnabled", "CountSnapshot", "ArraySnapshot",
            "ArrayReadHits"):
        if ("zeroCtrlPostMinusOneVCall64" + scalar) not in t33_return:
            fail("T34 wrapper lacks diagnostic scalar " + scalar)
    for field in ("post_minus_one_vcall64_collection_enabled_addr",
            "post_minus_one_vcall64_count_snapshot_addr",
            "post_minus_one_vcall64_array_snapshot_addr",
            "post_minus_one_vcall64_array_read_hits_addr"):
        if ("CHECK_POST_SCALAR(" + field + ")") not in kernel:
            fail("T34 registration does not range-validate " + field)
    for initialization in (
            "_sw(bsman->post_vcall64_collection_enabled ? 1 : 0,",
            "_sw(0xFFFFFFFF, bsman->post_minus_one_vcall64_count_snapshot_addr)",
            "_sw(0, bsman->post_minus_one_vcall64_array_snapshot_addr)",
            "_sw(0, bsman->post_minus_one_vcall64_array_read_hits_addr)"):
        if initialization not in bsman_install:
            fail("T34 transaction lacks initialization " + initialization)
    if "[post-vcall64-collection]" not in writer:
        fail("T34 deferred diagnostic is missing")
    if "PSP1000CollectionPafFCF265D8Trace = Disabled" not in sample_config or \
            '"PSP1000CollectionPafFCF265D8Trace", "Disabled"' not in kernel:
        fail("T35 trace is not default-disabled")
    t35_gate = kernel[kernel.find("collection_paf_fcf265d8_enabled ="):
        kernel.find(";", kernel.find("collection_paf_fcf265d8_enabled ="))]
    if "post_vcall64_collection_enabled" not in t35_gate or \
            'strcmp(psp1000CollectionPafFCF265D8Trace, "Enabled") == 0' not in t35_gate:
        fail("T35 does not depend on the complete T34 gate")
    t35 = assembly[assembly.find("zeroCtrlCollectionPafFCF265D8Trace:"):
        assembly.find("zeroCtrlCollectionPafFCF265D8TraceEnd:")]
    for token in ("sw      $a0, %lo(zeroCtrlCollectionPafFCF265D8LastItem)",
            "sw      $v0, %lo(zeroCtrlCollectionPafFCF265D8NaturalResult)",
            "beqz    $v0, 68f", "addiu   $ra, $ra, -0x12C", "\n68:"):
        if token not in t35:
            fail("T35 decision tracer lacks " + token)
    if t35.count("$v0") != 2 or t35.count("$a0") != 1 or \
            any(token in t35 for token in ("jal ", "jalr", "$gp", "sceIo",
                "Alloc", "malloc")):
        fail("T35 tracer transforms inputs or performs a call/I/O/allocation")
    for token in ("collection_paf_fcf265d8_original[0] != 0x1440FFB6",
            "collection_paf_fcf265d8_original[1] != 0x02002021",
            "bsman->activation_addr + 0x170"):
        if token not in bsman_install:
            fail("T35 transaction lacks " + token)
    commit = bsman_install[bsman_install.find("/* Transaction commit"):]
    if commit.count("_sw(bsman->collection_paf_fcf265d8_replacement,") != 1 or \
            "bsman->activation_addr + 0x168" in commit or \
            "bsman->activation_addr + 0x174" in commit:
        fail("T35 patches the PAF call/delay slot or has multiple owners")
    if "[collection-paf-fcf265d8]" not in writer:
        fail("T35 deferred diagnostic is missing")
    for field in ("collection_paf_fcf265d8_last_item_addr",
            "collection_paf_fcf265d8_natural_result_addr",
            "collection_paf_fcf265d8_hits_addr",
            "collection_paf_fcf265d8_nonzero_hits_addr"):
        if ("CHECK_POST_SCALAR(" + field + ")") not in kernel:
            fail("T35 registration does not range-validate " + field)
    if "zeroCtrlRegistrationLeafValid(helper,\n                copied.collection_paf_fcf265d8_leaf_addr" not in kernel:
        fail("T35 registration does not validate its helper leaf range")
    if "PSP1000CollectionPaf9A285882Trace = Disabled" not in sample_config or \
            '"PSP1000CollectionPaf9A285882Trace", "Disabled"' not in kernel:
        fail("T36 trace is not default-disabled")
    t36_gate = kernel[kernel.find("collection_paf_9a285882_enabled ="):
        kernel.find(";", kernel.find("collection_paf_9a285882_enabled ="))]
    if "collection_paf_fcf265d8_enabled" not in t36_gate or \
            'strcmp(psp1000CollectionPaf9A285882Trace, "Enabled") == 0' not in t36_gate:
        fail("T36 does not require T35 and explicit opt-in")
    t36 = assembly[assembly.find("zeroCtrlCollectionPaf9A285882Trace:"):
        assembly.find("zeroCtrlCollectionPaf9A285882TraceEnd:")]
    for token in ("sw      $s0, %lo(zeroCtrlCollectionPaf9A285882LastItem)",
            "sw      $v0, %lo(zeroCtrlCollectionPaf9A285882NaturalResult)",
            "beqz    $v0, 69f", "jr      $t0", "lw      $t0, -8($sp)"):
        if token not in t36:
            fail("T36 transparent decision tracer lacks " + token)
    if "$a0" in t36 or "$ra" in t36 or any(x in t36 for x in
            ("jal ", "jalr", "$gp", "sceIo", "Alloc", "malloc")):
        fail("T36 touches a0/ra or performs a call, I/O, or allocation")
    for token in ("collection_paf_9a285882_original[0] != 0x1440FFB3",
            "collection_paf_9a285882_original[1] != 0x8FBF001C",
            "(bsman->collection_paf_9a285882_replacement >> 26) != 2",
            "bsman->activation_addr + 0x188",
            "bsman->activation_addr + 0x50"):
        if token not in bsman_install:
            fail("T36 transaction lacks " + token)
    if commit.count("_sw(bsman->collection_paf_9a285882_replacement,") != 1 or \
            "bsman->activation_addr + 0x178" in commit or \
            "bsman->activation_addr + 0x17C" in commit or \
            "bsman->activation_addr + 0x184" in commit or \
            "bsman->activation_addr + 0x188" in commit:
        fail("T36 does not exclusively own activation+0x180")
    if "[collection-paf-9a285882]" not in writer:
        fail("T36 deferred diagnostic is missing")
    if "PSP1000PostCollectionPafFCF265D8Trace = Disabled" not in sample_config or \
            '"PSP1000PostCollectionPafFCF265D8Trace", "Disabled"' not in kernel:
        fail("T37 trace is not default-disabled")
    t37_gate = kernel[kernel.find("post_collection_paf_fcf265d8_enabled ="):
        kernel.find(";", kernel.find("post_collection_paf_fcf265d8_enabled ="))]
    if "collection_paf_9a285882_enabled" not in t37_gate or \
            'strcmp(psp1000PostCollectionPafFCF265D8Trace, "Enabled") == 0' not in t37_gate:
        fail("T37 does not require T36 and explicit opt-in")
    t37 = assembly[assembly.find("zeroCtrlPostCollectionPafFCF265D8Trace:"):
        assembly.find("zeroCtrlPostCollectionPafFCF265D8TraceEnd:")]
    for token in ("sw      $v0, %lo(zeroCtrlPostCollectionPafFCF265D8NaturalResult)",
            "beqz    $v0, 71f", "jr      $t0", "lw      $t0, -8($sp)"):
        if token not in t37:
            fail("T37 transparent decision tracer lacks " + token)
    if "$a0" in t37 or "$ra" in t37 or any(x in t37 for x in
            ("jal ", "jalr", "$gp", "sceIo", "Alloc", "malloc",
             "dispatcher", "context")):
        fail("T37 assumes a0/touches ra or performs forbidden work")
    for token in ("post_collection_paf_fcf265d8_original[0] & 0xFFFF0000",
            "post_collection_paf_fcf265d8_original[1] >> 26) != 3",
            "mod->text_addr + 0x2A698",
            "(bsman->post_collection_paf_fcf265d8_original[2] & 0xFFFF0000) != 0x8C440000",
            "post_collection_paf_fcf265d8_original[3] != 0x1440FFAA",
            "post_collection_paf_fcf265d8_original[4] != 0x8FBF001C",
            "(bsman->post_collection_paf_fcf265d8_replacement >> 26) != 2",
            "bsman->activation_addr + 0x1AC"):
        if token not in bsman_install:
            fail("T37 transaction lacks " + token)
    if commit.count("_sw(bsman->post_collection_paf_fcf265d8_replacement,") != 1:
        fail("T37 lacks one exact +0x1A4 patch owner")
    t37_commit = commit[commit.find(
        "if (bsman->post_collection_paf_fcf265d8_enabled) {"):]
    t37_commit = t37_commit[:t37_commit.find("\n        }")]
    if "bsman->activation_addr + 0x1A4" not in t37_commit or any(
            offset in t37_commit for offset in ("+ 0x198", "+ 0x19C",
                "+ 0x1A0", "+ 0x1A8", "+ 0x1AC")):
        fail("T37 commit writes outside its exact +0x1A4 ownership")
    t37_cache_token = """if (bsman->post_collection_paf_fcf265d8_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1A4), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1A4), 4);"""
    if t37_cache_token not in bsman_install:
        fail("T37 cache synchronization is not +0x1A4/4")
    if "[post-collection-paf-fcf265d8]" not in writer:
        fail("T37 deferred diagnostic is missing")
    t371_defs = {
        "T37_FAIL_LUI_SHAPE": "0x001",
        "T37_FAIL_CALL_OPCODE": "0x002",
        "T37_FAIL_CALL_TARGET": "0x004",
        "T37_FAIL_ARG_LOAD_WORD": "0x008",
        "T37_FAIL_DECISION_WORD": "0x010",
        "T37_FAIL_RA_DELAY_WORD": "0x020",
        "T37_FAIL_REPLACEMENT_OPCODE": "0x040",
        "T37_FAIL_REPLACEMENT_TARGET": "0x080",
        "T37_FAIL_HELPER_RANGE": "0x100",
        "T37_FAIL_PSEUDODIRECT_REGION": "0x200",
        "T37_FAIL_ARG_LOAD_TARGET": "0x400",
        "T37_FAIL_SEGMENT1_MISSING": "0x800",
    }
    for name, value in t371_defs.items():
        if ("#define " + name) not in kernel or value not in kernel[
                kernel.find("#define " + name):kernel.find("\n",
                    kernel.find("#define " + name))]:
            fail("T37.1 lacks unique failure bit " + name)
        if bsman_install.count("fail_mask |= " + name) != 1:
            fail("T37.1 failure bit is not mapped exactly once: " + name)
    t371 = bsman_install[bsman_install.find(
        "bsman->post_collection_paf_fcf265d8_guard_checked = 1;"):]
    rejection = t371.find("if (fail_mask != 0) return;")
    if rejection < 0:
        fail("T37.1 does not reject every nonzero failure mask")
    transaction_commit = t371.find("/* Transaction commit")
    if transaction_commit < 0 or rejection > transaction_commit:
        fail("T37.1 can reach the T37 patch before rejecting its failure mask")
    before_rejection = t371[:rejection]
    for index, offset in enumerate(("0x198", "0x19C", "0x1A0", "0x1A4", "0x1A8")):
        capture = "post_collection_paf_fcf265d8_original[%d]" % index
        if capture not in before_rejection or offset not in bsman_install:
            fail("T37.1 does not capture exact observed word " + offset)
    for token in ("zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x19C",
            "mod->text_addr + 0x2A698",
            "zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1A4",
            "zeroCtrlVshModuleRangeValid(helper,",
            "bsman->post_collection_paf_fcf265d8_leaf_size",
            "bsman->post_collection_paf_fcf265d8_fail_mask = fail_mask;"):
        if token not in before_rejection:
            fail("T37.1 fails to capture/check before rejection: " + token)
    if writer.find("[t37-validation]") < 0 or \
            writer.find("[t37-validation-targets]") < 0 or \
            writer.find("[t37-validation]") > writer.find(
                "[post-collection-paf-fcf265d8]"):
        fail("T37.1 deferred failure diagnostic is not outside success-only tracing")
    if "sizeof(ZeroCtrlBSManClosedRegistration) == 1012" not in bsman_header:
        fail("legacy registration ABI is not exactly 1012 bytes")
    if "post_collection_paf_fcf265d8_original[2] != 0x8C440DC4" in kernel:
        fail("T37.2 retains the invalid literal relocated LW comparison")
    t372 = bsman_install[bsman_install.rfind(
        "if (bsman->post_collection_paf_fcf265d8_enabled) {", 0,
        bsman_install.find("bsman->post_collection_paf_fcf265d8_guard_checked = 1;")):
        bsman_install.find("if (fail_mask != 0) return;")]
    for token in (
            "(bsman->post_collection_paf_fcf265d8_original[2] & 0xFFFF0000) !=",
            "0x8C440000",
            "int arg_lo = (short)(",
            "post_collection_paf_fcf265d8_original[2] & 0xFFFF",
            "post_collection_paf_fcf265d8_observed_arg_target =",
            "post_collection_paf_fcf265d8_original[0] & 0xFFFF",
            "post_collection_paf_fcf265d8_expected_arg_target =",
            "mod->nsegment >= 2 ? mod->segmentaddr[1] + 0x0DC4 : 0",
            "post_collection_paf_fcf265d8_observed_arg_target !=",
            "post_collection_paf_fcf265d8_expected_arg_target"):
        if token not in t372:
            fail("T37.2 relocation-aware argument validation lacks " + token)
    if "arg_target=0x%08X" not in writer or \
            "expected_arg_target=0x%08X" not in writer:
        fail("T37.2 deferred argument-target diagnostic is missing")
    if "PSP1000MaskedPafC59FC3D0Trace = Disabled" not in sample_config or \
            '"PSP1000MaskedPafC59FC3D0Trace", "Disabled"' not in kernel:
        fail("T38 trace is not default-disabled")
    t38_gate = kernel[kernel.find("masked_paf_c59fc3d0_enabled ="):
        kernel.find(";", kernel.find("masked_paf_c59fc3d0_enabled ="))]
    if "post_collection_paf_fcf265d8_enabled" not in t38_gate or \
            'strcmp(psp1000MaskedPafC59FC3D0Trace, "Enabled") == 0' not in t38_gate:
        fail("T38 does not require T37 and explicit opt-in")
    t38 = assembly[assembly.find("zeroCtrlMaskedPafC59FC3D0Trace:"):
        assembly.find("zeroCtrlMaskedPafC59FC3D0TraceEnd:")]
    for token in ("sw      $v0, %lo(zeroCtrlMaskedPafC59FC3D0DecisionValue)",
            "beqz    $v0, 73f", "jr      $t0", "lw      $t0, -8($sp)"):
        if token not in t38:
            fail("T38 transparent masked-decision tracer lacks " + token)
    if any(x in t38 for x in ("andi", "$a0", "$a1", "$ra", "jal ",
            "jalr", "$gp", "sceIo", "Alloc", "malloc", "dispatcher",
            "context")):
        fail("T38 transforms inputs or performs forbidden work")
    for token in ("0x1AC, 0x1B0, 0x1B4, 0x1B8, 0x1BC, 0x1C0, 0x1C4",
            "original[0] != 0x3C050300", "original[1] != 0x02202021",
            "original[2] >> 26) != 3", "mod->text_addr + 0x2A558",
            "original[3] != 0x34A50002", "original[4] != 0x304200FF",
            "original[5] != 0x1440FFA3", "original[6] != 0x8FBF001C",
            "masked_paf_c59fc3d0_replacement >> 26) != 2",
            "bsman->activation_addr + 0x1C8"):
        if token not in bsman_install:
            fail("T38 transaction lacks " + token)
    if commit.count("_sw(bsman->masked_paf_c59fc3d0_replacement,") != 1:
        fail("T38 lacks one exact +0x1C0 patch owner")
    t38_commit = commit[commit.find(
        "if (bsman->masked_paf_c59fc3d0_enabled) {"):]
    t38_commit = t38_commit[:t38_commit.find("\n        }")]
    if "bsman->activation_addr + 0x1C0" not in t38_commit or any(
            offset in t38_commit for offset in ("+ 0x1AC", "+ 0x1B0",
                "+ 0x1B4", "+ 0x1B8", "+ 0x1BC", "+ 0x1C4", "+ 0x1C8")):
        fail("T38 writes outside its exact +0x1C0 ownership")
    t38_cache = """if (bsman->masked_paf_c59fc3d0_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1C0), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1C0), 4);"""
    if t38_cache not in bsman_install or \
            "_sw(bsman->activation_addr + 0x50,\n                bsman->masked_paf_c59fc3d0_nonzero_target_addr)" not in bsman_install:
        fail("T38 cache range or dynamic natural route targets are wrong")
    if "[masked-paf-c59fc3d0]" not in writer or "decision=0x%08X" not in writer:
        fail("T38 masked-decision diagnostic is missing or ambiguous")
    if "PSP1000MaskedPafC59FC3D0SecondTrace = Disabled" not in sample_config or \
            '"PSP1000MaskedPafC59FC3D0SecondTrace", "Disabled"' not in kernel:
        fail("T39 trace is not default-disabled")
    t39_gate = kernel[kernel.find("masked_paf_c59fc3d0_second_enabled ="):
        kernel.find(";", kernel.find("masked_paf_c59fc3d0_second_enabled ="))]
    if "masked_paf_c59fc3d0_enabled" not in t39_gate or \
            'strcmp(psp1000MaskedPafC59FC3D0SecondTrace, "Enabled") == 0' not in t39_gate:
        fail("T39 does not require T38 and explicit opt-in")
    t39 = assembly[assembly.find("zeroCtrlMaskedPafC59FC3D0SecondTrace:"):
        assembly.find("zeroCtrlMaskedPafC59FC3D0SecondTraceEnd:")]
    for token in ("sw      $v0, %lo(zeroCtrlMaskedPafC59FC3D0SecondDecisionValue)",
            "beqz    $v0, 75f", "jr      $t0", "lw      $t0, -8($sp)"):
        if token not in t39:
            fail("T39 transparent masked-decision tracer lacks " + token)
    if any(x in t39 for x in ("andi", "$s0", "$a0", "$a1", "$ra", "$gp",
            "jal ", "jalr", "sceIo", "Alloc", "malloc", "dispatcher",
            "context")):
        fail("T39 transforms or references forbidden natural state")
    for token in ("0x1C8, 0x1CC, 0x1D0, 0x1D4, 0x1D8, 0x1DC, 0x1E0, 0x1E4",
            "original[0] & 0xFFFF0000", "0x3C020000",
            "original[1] &", "0x8C440000", "arg_lo = (short)(",
            "mod->segmentaddr[1] + 0x0DC0", "observed_arg_target != expected_arg_target",
            "original[2] != 0x3C050100", "original[3] >> 26) != 3",
            "mod->text_addr + 0x2A558", "original[4] != 0x34A50011",
            "original[5] != 0x304200FF", "original[6] != 0x1440FF9A",
            "original[7] != 0x00008021",
            "masked_paf_c59fc3d0_second_replacement >> 26) != 2",
            "bsman->activation_addr + 0x1E8", "bsman->activation_addr + 0x4C"):
        if token not in bsman_install:
            fail("T39 transaction lacks " + token)
    if commit.count("_sw(bsman->masked_paf_c59fc3d0_second_replacement,") != 1:
        fail("T39 lacks one exact +0x1E0 patch owner")
    t39_commit = commit[commit.find(
        "if (bsman->masked_paf_c59fc3d0_second_enabled) {"):]
    t39_commit = t39_commit[:t39_commit.find("\n        }")]
    if "bsman->activation_addr + 0x1E0" not in t39_commit or any(
            offset in t39_commit for offset in ("+ 0x1C8", "+ 0x1CC",
                "+ 0x1D0", "+ 0x1D4", "+ 0x1D8", "+ 0x1DC", "+ 0x1E4")):
        fail("T39 writes the natural call/ANDI/delay slot or another Sony word")
    t39_cache = """if (bsman->masked_paf_c59fc3d0_second_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E0), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E0), 4);"""
    if t39_cache not in bsman_install:
        fail("T39 cache synchronization is not exactly +0x1E0/4")
    if "[masked-paf-c59fc3d0-second]" not in writer or \
            "decision=0x%08X" not in writer:
        fail("T39 masked-decision diagnostic is missing or ambiguous")
    for record in ("[vsh-capability-predicate]", "[vsh-paf-capability-mask]"):
        if record not in writer:
            fail("T27 deferred diagnostic is missing " + record)
    if "zeroCtrlInstallCapabilityMaskTraces();" not in vsh_record:
        fail("T27 transaction is not installed at the bounded early VSH point")
    t27_install = kernel[kernel.find("static void zeroCtrlInstallCapabilityMaskTraces(void) {"):
        kernel.find("static void zeroCtrlInstall6F84ConsumerTraces(void) {")]
    for token in ("0x14014", "0x1402C", "0x14038", "0x1404C",
            "0x6F44", "0x6FC4", "0x7004", "0x3F778",
            "0x0062800B", "0x27B10030", "vsh->text_size != 0x556C0"):
        if token not in t27_install:
            fail("T27 transaction lacks validated constant " + token)
    t27_commit = t27_install.find("_sw(replacement[i], callsite[i])")
    t27_validation = t27_install.find("capability_validation[i] = 1")
    if t27_install.count("_sw(replacement[i], callsite[i])") != 1 or \
            not 0 <= t27_validation < t27_commit:
        fail("T27 callsites are not an all-or-none four-word transaction")
    for initialization in (
            "_sw(bsman->paf_mask_compat_enabled ? 1 : 0, bsman->paf_mask_compat_mode_addr)",
            "_sw(0xFFFFFFFF, bsman->paf_mask_effective_addr)",
            "_sw(0, bsman->paf_mask_substitution_hits_addr)"):
        position = t27_install.find(initialization)
        if position < t27_validation or position > t27_commit:
            fail("T28 scalar initialization is outside the all-or-none transaction")
    if "value_scalar[3] = bsman->paf_mask_natural_addr" not in t27_install or \
            "_sw(0xFFFFFFFF, value_scalar[i])" not in t27_install or \
            "_sw(0, hits_scalar[i])" not in t27_install or \
            "_sw(target[i], target_scalar[i])" not in t27_install:
        fail("T28 natural/hits/target initialization is incomplete")
    for field in ("paf_mask_natural_addr", "paf_mask_compat_mode_addr",
            "paf_mask_effective_addr", "paf_mask_substitution_hits_addr"):
        if ("copied." + field) not in kernel[kernel.find(
                "void zeroCtrlRegisterBSManClosedShim"):kernel.find(
                "void zeroCtrlRecordVshSlideTarget")]:
            fail("T28 registration does not validate/copy " + field)
    mask_source = assembly[assembly.find("zeroCtrlPafCapabilityMaskTrace:"):
        assembly.find("zeroCtrlPafCapabilityMaskTraceEnd:")]
    mask_source_tokens = ("sw      $a0, %lo(zeroCtrlPafCapabilityMaskNatural)",
        "lw      $t1, %lo(zeroCtrlPafCapabilityMaskCompatMode)",
        "beqz    $t1, 64f", "bne     $a0, $t2, 64f",
        "addiu   $a0, $zero, 0x1E9",
        "zeroCtrlPafCapabilityMaskSubstitutionHits", "\n64:",
        "sw      $a0, %lo(zeroCtrlPafCapabilityMaskEffective)",
        "lw      $t2, %lo(zeroCtrlPafCapabilityMaskTarget)", "jr      $t2")
    if any(token not in mask_source for token in mask_source_tokens) or \
            not (mask_source.find("beqz    $t1, 64f") <
                mask_source.find("bne     $a0, $t2, 64f") <
                mask_source.find("addiu   $a0, $zero, 0x1E9") <
                mask_source.find("\n64:") <
                mask_source.find("zeroCtrlPafCapabilityMaskEffective")) or \
            any(token in mask_source for token in ("$v0", "$gp", "$sp", "$ra",
                "$s0", "$s1", "jal", "sceIo", "Alloc")):
        fail("T28 mask tail wrapper does not implement exact guarded substitution")
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
        if stub == "zeroCtrlTrigger58D4":
            if counter not in assembly or "zeroCtrlTrigger58D4Request" not in \
                    assembly or "zeroCtrlTrigger58D4OriginalTarget" not in assembly:
                fail("functional 58D4 trigger lacks counter/request/target state")
            continue
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


def relocation_bound_to_instruction(body, scalar, instruction):
    """Return whether an instruction owns the scalar's following LO16 relocation."""
    pattern = (instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
               re.escape(scalar) + r"\b")
    return re.search(pattern, body) is not None


def check_t22_consumer_semantics(body, symbol):
    """Prove the assembled T23 wrapper captures but preserves natural v0."""
    forbidden = r"\b(?:at|v1|a[0-3]|t[3-9]|s[0-7]|k[01]|gp|fp)\b"
    if re.search(forbidden, body) or re.search(r"\bjal\b", body):
        fail(symbol + " uses a forbidden register or direct function call")
    ordered = (
        r"\baddiu\s+sp,\s*sp,\s*-16\b",
        r"\bsw\s+t0,\s*0\(sp\)",
        r"\bsw\s+t1,\s*4\(sp\)",
        r"\bsw\s+t2,\s*8\(sp\)",
        r"\bsw\s+ra,\s*12\(sp\)",
        r"\blui\s+t0,",
        r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b",
        r"\bsw\s+t1,",
        r"\blui\s+t0,",
        r"\blw\s+t2,",
        r"\bjalr\s+t2\b",
        r"\bnop\b",
        r"\blui\s+t0,",
        r"\bsw\s+v0,",
        r"\blw\s+t2,\s*8\(sp\)",
        r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)",
        r"\blw\s+ra,\s*12\(sp\)",
        r"\baddiu\s+sp,\s*sp,\s*16\b",
        r"\bjr\s+ra\b",
        r"\bnop\b",
    )
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered transparent operation " + pattern)
        cursor += match.end()
    if len(re.findall(r"\baddiu\s+sp,\s*sp,", body)) != 2 or \
            len(re.findall(r"\bjalr\s+t2\b", body)) != 1 or \
            len(re.findall(r"\bjr\s+ra\b", body)) != 1:
        fail(symbol + " has unexpected stack adjustment or control transfer")
    if len(re.findall(r"\blw\s+", body)) != 6 or \
            len(re.findall(r"\bsw\s+", body)) != 6:
        fail(symbol + " has unexpected memory accesses")
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]):
        fail(symbol + " transforms or uses natural v0 beyond one store")


def check_selective_consumer_semantics(body, symbol):
    """Prove a selective consumer preserves nonzero v0 and substitutes zero."""
    forbidden = r"\b(?:at|v1|a[0-3]|t[3-9]|s[0-7]|k[01]|gp|fp)\b"
    set_v0_one = r"\b(?:li\s+v0,\s*1|addiu\s+v0,\s*zero,\s*1)\b"
    if re.search(forbidden, body) or re.search(r"\bjal\b", body):
        fail(symbol + " uses a forbidden register or direct function call")
    ordered = (
        r"\baddiu\s+sp,\s*sp,\s*-16\b",
        r"\bsw\s+t0,\s*0\(sp\)", r"\bsw\s+t1,\s*4\(sp\)",
        r"\bsw\s+t2,\s*8\(sp\)", r"\bsw\s+ra,\s*12\(sp\)",
        r"\blui\s+t0,", r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1\b",
        r"\bsw\s+t1,", r"\blui\s+t0,", r"\blw\s+t2,",
        r"\bjalr\s+t2\b", r"\bnop\b", r"\blui\s+t0,",
        r"\bsw\s+v0,", r"\blui\s+t0,", r"\blw\s+t1,",
        r"\bbeqz\s+t1,", r"\bbnez\s+v0,",
        set_v0_one, r"\blui\s+t0,", r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b", r"\bsw\s+t1,",
        r"\blui\s+t0,", r"\bsw\s+v0,",
        r"\blw\s+t2,\s*8\(sp\)", r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)", r"\blw\s+ra,\s*12\(sp\)",
        r"\baddiu\s+sp,\s*sp,\s*16\b", r"\bjr\s+ra\b", r"\bnop\b",
    )
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered T24 operation " + pattern)
        cursor += match.end()
    if len(re.findall(set_v0_one, body)) != 1 or \
            len(re.findall(r"\baddiu\s+sp,\s*sp,", body)) != 2 or \
            len(re.findall(r"\bjalr\s+t2\b", body)) != 1 or \
            len(re.findall(r"\bjr\s+ra\b", body)) != 1:
        fail(symbol + " has an extra substitution, call, return, or stack adjustment")
    if len(re.findall(r"\blw\s+", body)) != 8 or \
            len(re.findall(r"\bsw\s+", body)) != 8:
        fail(symbol + " does not have exactly eight loads and eight stores")
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    expected_v0 = (r"\bsw\s+v0,", r"\bbnez\s+v0,", set_v0_one,
                   r"\bsw\s+v0,")
    if len(v0_lines) != 4 or any(not re.search(pattern, line)
            for pattern, line in zip(expected_v0, v0_lines)):
        fail(symbol + " has a v0 use outside natural store/test/substitute/effective store")


def check_t27_mask_semantics(body):
    """Prove exact T28 mask substitution and transparent tail transfer."""
    symbol = "zeroCtrlPafCapabilityMaskTrace"
    forbidden = r"\b(?:at|v[01]|a[1-3]|t[3-9]|s[0-7]|k[01]|gp|sp|fp|ra)\b"
    set_t2_two = r"\b(?:li\s+t2,\s*2|addiu\s+t2,\s*zero,\s*2)\b"
    set_a0_mask = (r"\b(?:li\s+a0,\s*(?:0x0*1e9|489)|"
                   r"addiu\s+a0,\s*zero,\s*(?:0x0*1e9|489))\b")
    if re.search(forbidden, body) or re.search(r"\bjalr?\b", body):
        fail(symbol + " uses a forbidden register, frame, or call")
    ordered = (r"\bsw\s+a0,", r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b", r"\bsw\s+t1,",
        r"\blw\s+t1,", r"\bbeqz\s+t1,", set_t2_two,
        r"\bbne\s+a0,\s*t2,", set_a0_mask, r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b", r"\bsw\s+t1,",
        r"\bsw\s+a0,", r"\blw\s+t2,", r"\bjr\s+t2\b", r"\bnop\b")
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered tail-transfer operation " + pattern)
        cursor += match.end()
    a0_lines = [line for line in body.splitlines() if re.search(r"\ba0\b", line)]
    expected_a0 = (r"\bsw\s+a0,", r"\bbne\s+a0,\s*t2,", set_a0_mask,
                   r"\bsw\s+a0,")
    if len(a0_lines) != 4 or any(not re.search(pattern, line, re.I)
            for pattern, line in zip(expected_a0, a0_lines)) or \
            len(re.findall(set_a0_mask, body, re.I)) != 1 or \
            len(re.findall(r"\blw\s+", body)) != 4 or \
            len(re.findall(r"\bsw\s+", body)) != 4 or \
            len(re.findall(r"\bjr\s+t2\b", body)) != 1:
        fail(symbol + " has an unintended a0, memory, or control operation")


def check_t30_state_zero_return_semantics(body):
    """Prove the existing return owner performs only exact 15-to-14 compat."""
    symbol = "zeroCtrlStateZeroVReturnTrace"
    set_v0_14 = r"\b(?:li\s+v0,\s*14|addiu\s+v0,\s*zero,\s*14)\b"
    set_t1_15 = r"\b(?:li\s+t1,\s*15|addiu\s+t1,\s*zero,\s*15)\b"
    forbidden = r"\b(?:at|v1|a[0-3]|t[2-9]|s[0-7]|k[01]|gp|fp)\b"
    if re.search(forbidden, body) or re.search(r"\bjalr?\b", body):
        fail(symbol + " uses a forbidden register or call")
    ordered = (r"\baddiu\s+sp,\s*sp,\s*-8\b", r"\bsw\s+t0,",
        r"\bsw\s+t1,", r"\bsw\s+v0,", r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b", r"\bsw\s+t1,",
        r"\blw\s+t1,", r"\bbeqz\s+t1,", set_t1_15,
        r"\bbne\s+v0,\s*t1,", set_v0_14, r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1\b", r"\bsw\s+t1,",
        r"\bsw\s+v0,", r"\blw\s+t1,", r"\bori\s+t1,",
        r"\bsw\s+t1,", r"\blw\s+ra,", r"\blw\s+t1,",
        r"\blw\s+t0,", r"\baddiu\s+sp,\s*sp,\s*8\b",
        r"\bjr\s+ra\b", r"\bnop\b")
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered T30 operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    expected_v0 = (r"\bsw\s+v0,", r"\bbne\s+v0,\s*t1,", set_v0_14,
                   r"\bsw\s+v0,")
    if len(v0_lines) != 4 or any(not re.search(pattern, line, re.I)
            for pattern, line in zip(expected_v0, v0_lines)) or \
            len(re.findall(set_v0_14, body, re.I)) != 1 or \
            len(re.findall(r"\blw\s+", body)) != 7 or \
            len(re.findall(r"\bsw\s+", body)) != 7 or \
            len(re.findall(r"\baddiu\s+sp,\s*sp,", body)) != 2 or \
            len(re.findall(r"\bjr\s+ra\b", body)) != 1:
        fail(symbol + " has unintended T30 result/frame/memory semantics")


def check_t301_class_input(body, symbol, relocatable=False, expected_addr=None):
    """Prove Class15/Class17 route from the T30 effective-result slot."""
    natural = "zeroCtrlStateZeroVCallResult"
    effective = "zeroCtrlStateZero15To14EffectiveResult"
    if natural in body:
        fail(symbol + " references the natural diagnostic slot")
    if relocatable:
        if len(re.findall(r"R_MIPS_HI16\s+" + effective + r"\b", body)) != 1 or \
                len(re.findall(r"R_MIPS_LO16\s+" + effective + r"\b", body)) != 1 or \
                not re.search(r"\blw\s+t2,[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                    effective + r"\b", body):
            fail(symbol + " lacks exact effective-result input relocations")
    elif expected_addr is not None:
        match = re.search(r"[0-9a-f]+:\s+([0-9a-f]{8})\s+"
                r"lui\s+t0,.*?[0-9a-f]+:\s+([0-9a-f]{8})\s+"
                r"lw\s+t2,", body, re.I | re.S)
        if not match:
            fail(symbol + " lacks linked LUI/LW classification input")
        lui_word = int(match.group(1), 16)
        lw_word = int(match.group(2), 16)
        upper = (lui_word & 0xFFFF) << 16
        low = lw_word & 0xFFFF
        if low > 0x7FFF:
            low -= 0x10000
        if ((upper + low) & 0xFFFFFFFF) != expected_addr:
            fail(symbol + " linked classification input is not the effective slot")


def check_t31_vsh_return_semantics(body):
    """Prove only the exact impose argument/result pair can become zero."""
    symbol = "zeroCtrlPostVshReturnTrace"
    set_v0_zero = r"\b(?:move\s+v0,\s*zero|addu\s+v0,\s*zero,\s*zero)\b"
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b", body):
        fail(symbol + " uses gp, a frame, or a call")
    ordered = (r"\bsw\s+v0,", r"\blw\s+t1,", r"\bbeqz\s+t1,",
        r"\blw\s+t1,", r"\blui\s+t2,\s*0x8000", r"\bori\s+t2,.*0xd",
        r"\bbne\s+t1,\s*t2,", r"\blui\s+t2,\s*0x8000",
        r"\bori\s+t2,.*0x107", r"\bbne\s+v0,\s*t2,", set_v0_zero,
        r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\bsw\s+v0,", r"\blw\s+ra,", r"\bjr\s+ra\b", r"\bnop\b")
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail(symbol + " lacks ordered T31 operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    expected_v0 = (r"\bsw\s+v0,", r"\bbne\s+v0,\s*t2,", set_v0_zero,
                   r"\bsw\s+v0,")
    if len(v0_lines) != 4 or any(not re.search(pattern, line, re.I)
            for pattern, line in zip(expected_v0, v0_lines)) or \
            len(re.findall(set_v0_zero, body, re.I)) != 1 or \
            len(re.findall(r"\bjr\s+ra\b", body)) != 1:
        fail(symbol + " has an unintended v0 substitution or return")


def check_t32_vcall_semantics(call, returned):
    """Prove T32 transparently calls the captured v0 target and returns it."""
    call_order = (r"\baddiu\s+sp,\s*sp,\s*-8", r"\bsw\s+t0,",
        r"\bsw\s+t1,", r"\bsw\s+v0,", r"\bsw\s+ra,",
        r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\blw\s+t1,", r"\blw\s+t0,", r"\baddiu\s+sp,\s*sp,\s*8",
        r"\bjr\s+v0\b", r"\bnop\b")
    cursor = 0
    for pattern in call_order:
        match = re.search(pattern, call[cursor:], re.I)
        if not match:
            fail("T32 call wrapper lacks ordered operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in call.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 2 or not re.search(r"\bsw\s+v0,", v0_lines[0]) or \
            not re.search(r"\bjr\s+v0\b", v0_lines[1]):
        fail("T32 call wrapper transforms its v0 target")
    return_order = (r"\baddiu\s+sp,\s*sp,\s*-8", r"\bsw\s+t0,\s*0\(sp\)",
        r"\bsw\s+t1,\s*4\(sp\)", r"\bsw\s+v0,", r"\blw\s+t1,",
        r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\blw\s+ra,", r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)", r"\baddiu\s+sp,\s*sp,\s*8",
        r"\bjr\s+ra\b", r"\bnop\b")
    cursor = 0
    for pattern in return_order:
        match = re.search(pattern, returned[cursor:], re.I)
        if not match:
            fail("T32 return wrapper lacks ordered operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in returned.splitlines() if re.search(r"\bv0\b", line)]
    sp_adjusts = re.findall(r"\baddiu\s+sp,\s*sp,\s*(-?\d+)", returned)
    frame_ops = {
        "save_t0": len(re.findall(r"\bsw\s+t0,\s*0\(sp\)", returned)),
        "save_t1": len(re.findall(r"\bsw\s+t1,\s*4\(sp\)", returned)),
        "restore_t1": len(re.findall(r"\blw\s+t1,\s*4\(sp\)", returned)),
        "restore_t0": len(re.findall(r"\blw\s+t0,\s*0\(sp\)", returned)),
    }
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]) or \
            sp_adjusts != ["-8", "8"] or any(count != 1 for count in frame_ops.values()) or \
            re.search(r"\bgp\b|\bjalr?\b", returned):
        fail("T32 return wrapper transforms v0 or has an invalid private frame/call")


def mips_immediate_pattern(value):
    """Match an objdump immediate in equivalent decimal or 0x-prefixed hex."""
    return rf"(?:0x0*{value:x}|{value:d})"


def check_mips_immediate_patterns():
    """Self-test strict numeric equivalence for T34 objdump offsets."""
    for value, accepted, rejected in (
            (0x364, ("868", "0x364", "0x0364", "0x00000364"), ("364",)),
            (0x360, ("864", "0x360", "0x0360", "0x00000360"), ("360",))):
        pattern = re.compile(rf"^(?:{mips_immediate_pattern(value)})$", re.I)
        if any(not pattern.fullmatch(text) for text in accepted) or \
                any(pattern.fullmatch(text) for text in rejected):
            fail("MIPS immediate pattern does not preserve numeric equivalence")


def check_t34_vcall_semantics(call, returned):
    """Prove T33 transparency plus T34's conditional natural collection reads."""
    count_offset = mips_immediate_pattern(0x364)
    array_offset = mips_immediate_pattern(0x360)
    call_v0 = [line for line in call.splitlines() if re.search(r"\bv0\b", line)]
    if len(call_v0) != 2 or not re.search(r"\bsw\s+v0,", call_v0[0]) or \
            not re.search(r"\bjr\s+v0\b", call_v0[1]):
        fail("T34 call wrapper transforms its v0 target")
    ordered = (r"\baddiu\s+sp,\s*sp,\s*-8", r"\bsw\s+t0,\s*0\(sp\)",
        r"\bsw\s+t1,\s*4\(sp\)", r"\bsw\s+v0,", r"\blw\s+t1,",
        r"\bbeqz\s+t1,", rf"\blw\s+t1,\s*{count_offset}\(v0\)",
        r"\bsw\s+t1,", r"\bbeqz\s+t1,",
        rf"\blw\s+t1,\s*{array_offset}\(v0\)", r"\bsw\s+t1,",
        r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\blw\s+ra,", r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)", r"\baddiu\s+sp,\s*sp,\s*8",
        r"\bjr\s+ra\b", r"\bnop\b")
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, returned[cursor:], re.I)
        if not match:
            fail("T34 return wrapper lacks ordered operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in returned.splitlines() if re.search(r"\bv0\b", line)]
    allowed = (r"\bsw\s+v0,", rf"\blw\s+t1,\s*{count_offset}\(v0\)",
               rf"\blw\s+t1,\s*{array_offset}\(v0\)")
    if len(v0_lines) != 3 or any(not re.search(pattern, line, re.I)
            for pattern, line in zip(allowed, v0_lines)) or \
            re.search(r"\bgp\b|\bjalr?\b", returned):
        fail("T34 return wrapper transforms v0 or performs a call")


def check_t35_decision_semantics(body):
    """Prove the natural FCF265D8 result controls only Sony's original routes."""
    nonzero_delta = r"(?:-0x0*12c|-300)"
    ordered = (r"\baddiu\s+sp,\s*sp,\s*-8", r"\bsw\s+t0,\s*0\(sp\)",
        r"\bsw\s+t1,\s*4\(sp\)", r"\bsw\s+a0,", r"\bsw\s+v0,",
        r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1", r"\bsw\s+t1,",
        r"\bbeqz\s+v0,", r"\blw\s+t1,", r"\baddiu\s+t1,\s*t1,\s*1",
        r"\bsw\s+t1,", r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)", r"\baddiu\s+sp,\s*sp,\s*8",
        rf"\baddiu\s+ra,\s*ra,\s*{nonzero_delta}", r"\bjr\s+ra\b",
        r"\bnop\b", r"\blw\s+t1,\s*4\(sp\)",
        r"\blw\s+t0,\s*0\(sp\)", r"\baddiu\s+sp,\s*sp,\s*8",
        r"\bjr\s+ra\b", r"\bnop\b")
    cursor = 0
    for pattern in ordered:
        match = re.search(pattern, body[cursor:], re.I)
        if not match:
            fail("T35 tracer lacks ordered operation " + pattern)
        cursor += match.end()
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    a0_lines = [line for line in body.splitlines() if re.search(r"\ba0\b", line)]
    if len(v0_lines) != 2 or not re.search(r"\bsw\s+v0,", v0_lines[0]) or \
            not re.search(r"\bbeqz\s+v0,", v0_lines[1]) or len(a0_lines) != 1 or \
            not re.search(r"\bsw\s+a0,", a0_lines[0]) or \
            len(re.findall(r"\bjr\s+ra\b", body)) != 2 or \
            re.search(r"\bgp\b|\bjalr?\b", body):
        fail("T35 tracer transforms a0/v0 or performs a call")


def linked_instructions(body):
    """Return final linked instruction addresses/words, excluding relocations."""
    instructions = []
    for line in body.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+", line, re.I)
        if match:
            instructions.append((int(match.group(1), 16),
                                 int(match.group(2), 16)))
    return instructions


def linked_scalar_uses(body, symbol, expected_addr, uses):
    """Bind linked LW/SW uses to a symbol via decoded HI16/signed-LO16."""
    instructions = linked_instructions(body)
    matches = []
    latest_lui = {}
    for pc, word in instructions:
        opcode = word >> 26
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        if opcode == 0x0F:
            latest_lui[rt] = word & 0xFFFF
        if opcode in (0x23, 0x2B) and rs in latest_lui:
            low = word & 0xFFFF
            if low & 0x8000:
                low -= 0x10000
            address = ((latest_lui[rs] << 16) + low) & 0xFFFFFFFF
            if address == expected_addr:
                matches.append((pc, opcode, rt, rs))
    expected = [(0x23 if mnemonic == "lw" else 0x2B, rt, base)
                for mnemonic, rt, base in uses]
    actual = [(opcode, rt, base) for _pc, opcode, rt, base in matches]
    if actual != expected:
        fail(symbol + " linked scalar uses do not match " + repr(expected))
    return [pc for pc, _opcode, _rt, _base in matches]


def check_t311_linked(disassembly, symbol_addresses):
    """Independently prove T31 linked scalar addresses and guard topology."""
    call = function_body(disassembly, "zeroCtrlPostVshCallTrace")
    linked_scalar_uses(call, "zeroCtrlPostVshArgument",
            symbol_addresses["zeroCtrlPostVshArgument"], [("sw", 4, 8)])
    call_words = linked_instructions(call)
    if sum(1 for _pc, word in call_words if ((word >> 26) == 0x2B and
            ((word >> 16) & 0x1F) == 4)) != 1:
        fail("T31 linked call wrapper has an unintended a0 store")

    body = function_body(disassembly, "zeroCtrlPostVshReturnTrace")
    use_specs = (
        ("zeroCtrlPostVshNaturalResult", [("sw", 2, 8)]),
        ("zeroCtrlPostVshCompatMode", [("lw", 9, 8)]),
        ("zeroCtrlPostVshArgument", [("lw", 9, 8)]),
        ("zeroCtrlPostVshSubstitutionHits", [("lw", 9, 8), ("sw", 9, 8)]),
        ("zeroCtrlPostVshEffectiveResult", [("sw", 2, 8)]),
        ("zeroCtrlPostVshSavedRA", [("lw", 31, 8)]),
    )
    use_pcs = {}
    for scalar, uses in use_specs:
        use_pcs[scalar] = linked_scalar_uses(body, scalar,
                symbol_addresses[scalar], uses)
    instructions = linked_instructions(body)
    constant_pairs = []
    for index, (_pc, word) in enumerate(instructions[:-1]):
        next_word = instructions[index + 1][1]
        if word == 0x3C0A8000 and (next_word & 0xFFFF0000) == 0x354A0000:
            constant_pairs.append(next_word & 0xFFFF)
    if constant_pairs != [0x000D, 0x0107]:
        fail("T31 linked exact argument/result constants are not 0x8000000D/0x80000107")
    branches = []
    zero_pcs = []
    for pc, word in instructions:
        opcode = word >> 26
        rs, rt = (word >> 21) & 0x1F, (word >> 16) & 0x1F
        if (opcode, rs, rt) in ((4, 9, 0), (5, 9, 10), (5, 2, 10)):
            imm = word & 0xFFFF
            if imm & 0x8000:
                imm -= 0x10000
            branches.append((pc, (pc + 4 + (imm << 2)) & 0xFFFFFFFF))
        if word == 0x00001021:
            zero_pcs.append(pc)
    if len(branches) != 3 or len({target for _pc, target in branches}) != 1 or \
            len(zero_pcs) != 1:
        fail("T31 linked guards do not share one bypass around one v0=0")
    bypass = branches[0][1]
    zero_pc = zero_pcs[0]
    effective_lui_pc = use_pcs["zeroCtrlPostVshEffectiveResult"][0] - 4
    if bypass != effective_lui_pc or not branches[-1][0] < zero_pc < bypass:
        fail("T31 linked bypass does not enter immediately before effective store")
    if not (use_pcs["zeroCtrlPostVshNaturalResult"][0] < branches[0][0] and
            use_pcs["zeroCtrlPostVshSavedRA"][0] >
            use_pcs["zeroCtrlPostVshEffectiveResult"][0]):
        fail("T31 linked natural/effective/saved-RA order is invalid")
    if sum(1 for _pc, word in instructions if word == 0x03E00008) != 1:
        fail("T31 linked return wrapper does not have exactly one jr ra")


def check_t32_linked(disassembly, symbol_addresses):
    """Independently prove T32 scalar resolution and transparent RA routing."""
    call = function_body(disassembly, "zeroCtrlPostImposeVCallTrace")
    returned = function_body(disassembly, "zeroCtrlPostImposeVCallReturnTrace")
    linked_scalar_uses(call, "zeroCtrlPostImposeVCallTarget",
            symbol_addresses["zeroCtrlPostImposeVCallTarget"], [("sw", 2, 8)])
    linked_scalar_uses(call, "zeroCtrlPostImposeVCallSavedRA",
            symbol_addresses["zeroCtrlPostImposeVCallSavedRA"], [("sw", 31, 8)])
    linked_scalar_uses(call, "zeroCtrlPostImposeVCallHits",
            symbol_addresses["zeroCtrlPostImposeVCallHits"],
            [("lw", 9, 8), ("sw", 9, 8)])
    linked_scalar_uses(returned, "zeroCtrlPostImposeVCallNaturalResult",
            symbol_addresses["zeroCtrlPostImposeVCallNaturalResult"],
            [("sw", 2, 8)])
    linked_scalar_uses(returned, "zeroCtrlPostImposeVCallReturnHits",
            symbol_addresses["zeroCtrlPostImposeVCallReturnHits"],
            [("lw", 9, 8), ("sw", 9, 8)])
    linked_scalar_uses(returned, "zeroCtrlPostImposeVCallSavedRA",
            symbol_addresses["zeroCtrlPostImposeVCallSavedRA"], [("lw", 31, 8)])
    words = linked_instructions(call)
    return_addr = symbol_addresses["zeroCtrlPostImposeVCallReturnTrace"]
    routed = []
    for index, (pc, word) in enumerate(words[:-1]):
        next_word = words[index + 1][1]
        if (word >> 26) == 0x0F and ((word >> 16) & 0x1F) == 31 and \
                (next_word >> 26) == 0x09 and \
                ((next_word >> 21) & 0x1F) == 31 and \
                ((next_word >> 16) & 0x1F) == 31:
            low = next_word & 0xFFFF
            if low & 0x8000:
                low -= 0x10000
            routed.append((((word & 0xFFFF) << 16) + low) & 0xFFFFFFFF)
    if routed != [return_addr] or sum(1 for _pc, word in words
            if word == 0x00400008) != 1:
        fail("T32 linked call wrapper does not route RA then jr untouched v0")
    if sum(1 for _pc, word in linked_instructions(returned)
            if word == 0x03E00008) != 1:
        fail("T32 linked return wrapper does not return once through saved RA")
    return_words = [word for _pc, word in linked_instructions(returned)]
    expected_frame = (0x27BDFFF8, 0xAFA80000, 0xAFA90004)
    expected_restore = (0x8FA90004, 0x8FA80000, 0x27BD0008, 0x03E00008,
                        0x00000000)
    if tuple(return_words[:3]) != expected_frame or \
            tuple(return_words[-5:]) != expected_restore or \
            return_words.count(0x27BDFFF8) != 1 or \
            return_words.count(0x27BD0008) != 1:
        fail("T32 linked return wrapper does not preserve t0/t1 in one balanced frame")



def check_t32_linked_pair(disassembly, symbol_addresses, prefix):
    """Prove a T32.1-style transparent pair using its final linked words."""
    call = function_body(disassembly, prefix + "Trace")
    returned = function_body(disassembly, prefix + "ReturnTrace")
    linked_scalar_uses(call, prefix + "Target", symbol_addresses[prefix + "Target"],
            [("sw", 2, 8)])
    linked_scalar_uses(call, prefix + "SavedRA", symbol_addresses[prefix + "SavedRA"],
            [("sw", 31, 8)])
    linked_scalar_uses(call, prefix + "Hits", symbol_addresses[prefix + "Hits"],
            [("lw", 9, 8), ("sw", 9, 8)])
    linked_scalar_uses(returned, prefix + "NaturalResult",
            symbol_addresses[prefix + "NaturalResult"], [("sw", 2, 8)])
    linked_scalar_uses(returned, prefix + "ReturnHits",
            symbol_addresses[prefix + "ReturnHits"], [("lw", 9, 8), ("sw", 9, 8)])
    linked_scalar_uses(returned, prefix + "SavedRA",
            symbol_addresses[prefix + "SavedRA"], [("lw", 31, 8)])
    call_words = [word for _pc, word in linked_instructions(call)]
    return_words = [word for _pc, word in linked_instructions(returned)]
    frame = (0x27BDFFF8, 0xAFA80000, 0xAFA90004)
    call_tail = (0x8FA90004, 0x8FA80000, 0x27BD0008, 0x00400008, 0)
    return_tail = (0x8FA90004, 0x8FA80000, 0x27BD0008, 0x03E00008, 0)
    if tuple(call_words[:3]) != frame or tuple(call_words[-5:]) != call_tail or \
            tuple(return_words[:3]) != frame or tuple(return_words[-5:]) != return_tail:
        fail(prefix + " linked wrappers do not preserve transparent frames")
    return_addr = symbol_addresses[prefix + "ReturnTrace"]
    routed = []
    for first, second in zip(call_words, call_words[1:]):
        if first >> 26 == 0x0F and (first >> 16) & 0x1F == 31 and \
                second >> 26 == 0x09 and (second >> 21) & 0x1F == 31 and \
                (second >> 16) & 0x1F == 31:
            low = second & 0xFFFF
            if low & 0x8000: low -= 0x10000
            routed.append((((first & 0xFFFF) << 16) + low) & 0xFFFFFFFF)
    if routed != [return_addr]:
        fail(prefix + " does not route RA to its linked return tracer")


def check_t34_linked_collection(disassembly, symbol_addresses):
    """Prove final T34 scalar addresses and conditional pointer reads."""
    prefix = "zeroCtrlPostMinusOneVCall64"
    body = function_body(disassembly, prefix + "ReturnTrace")
    uses = {}
    for suffix, expected in (
            ("CollectionEnabled", [("lw", 9, 8)]),
            ("CountSnapshot", [("sw", 9, 8)]),
            ("ArraySnapshot", [("sw", 9, 8)]),
            ("ArrayReadHits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("ReturnHits", [("lw", 9, 8), ("sw", 9, 8)])):
        symbol = prefix + suffix
        uses[suffix] = linked_scalar_uses(body, symbol,
                symbol_addresses[symbol], expected)
    instructions = linked_instructions(body)
    count_loads = [(pc, word) for pc, word in instructions
        if word >> 26 == 0x23 and (word >> 21) & 0x1F == 2 and
        (word >> 16) & 0x1F == 9 and (word & 0xFFFF) == 0x364]
    array_loads = [(pc, word) for pc, word in instructions
        if word >> 26 == 0x23 and (word >> 21) & 0x1F == 2 and
        (word >> 16) & 0x1F == 9 and (word & 0xFFFF) == 0x360]
    if len(count_loads) != 1 or len(array_loads) != 1 or \
            not count_loads[0][0] < array_loads[0][0]:
        fail("T34 linked wrapper lacks exact ordered v0+0x364/v0+0x360 reads")
    if any(word >> 26 == 0x2B and (word >> 21) & 0x1F == 2
            for _pc, word in instructions):
        fail("T34 linked wrapper stores through the natural v0 pointer")
    branches = []
    for pc, word in instructions:
        if word >> 26 == 4 and (word >> 21) & 0x1F == 9 and \
                (word >> 16) & 0x1F == 0:
            imm = word & 0xFFFF
            if imm & 0x8000:
                imm -= 0x10000
            branches.append((pc, pc + 4 + (imm << 2)))
    bypass = uses["ReturnHits"][0] - 4
    if len(branches) != 2 or branches[0][1] != branches[1][1] or \
            branches[0][1] != bypass or \
            not branches[1][0] < array_loads[0][0] < bypass:
        fail("T34 linked array read is not exclusively on nonzero-count fall-through")


def check_t35_linked(disassembly, symbol_addresses):
    """Prove final T35 scalar bindings and exact natural-result routing."""
    body = function_body(disassembly, "zeroCtrlCollectionPafFCF265D8Trace")
    prefix = "zeroCtrlCollectionPafFCF265D8"
    linked_scalar_uses(body, prefix + "LastItem",
            symbol_addresses[prefix + "LastItem"], [("sw", 4, 8)])
    linked_scalar_uses(body, prefix + "NaturalResult",
            symbol_addresses[prefix + "NaturalResult"], [("sw", 2, 8)])
    linked_scalar_uses(body, prefix + "Hits", symbol_addresses[prefix + "Hits"],
            [("lw", 9, 8), ("sw", 9, 8)])
    linked_scalar_uses(body, prefix + "NonzeroHits",
            symbol_addresses[prefix + "NonzeroHits"],
            [("lw", 9, 8), ("sw", 9, 8)])
    words = linked_instructions(body)
    branches = [(pc, word) for pc, word in words if word >> 26 == 4 and
        (word >> 21) & 0x1F == 2 and (word >> 16) & 0x1F == 0]
    adjust_ra = [(pc, word) for pc, word in words if word >> 26 == 9 and
        (word >> 21) & 0x1F == 31 and (word >> 16) & 0x1F == 31 and
        (word & 0xFFFF) == 0xFED4]
    restores = [pc for pc, word in words if word == 0x8FA90004]
    if len(branches) == 1:
        imm = branches[0][1] & 0xFFFF
        if imm & 0x8000:
            imm -= 0x10000
        zero_target = branches[0][0] + 4 + (imm << 2)
    else:
        zero_target = -1
    if len(branches) != 1 or len(adjust_ra) != 1 or len(restores) != 2 or \
            zero_target != restores[1] or \
            sum(word == 0x03E00008 for _pc, word in words) != 2:
        fail("T35 linked tracer lacks exact v0 branch/-0x12C/two-return routing")
    for word, count in ((0x27BDFFF8, 1), (0xAFA80000, 1), (0xAFA90004, 1),
            (0x8FA90004, 2), (0x8FA80000, 2), (0x27BD0008, 2)):
        if sum(candidate == word for _pc, candidate in words) != count:
            fail("T35 linked tracer has an unbalanced temporary frame")
    v0_text = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    a0_text = [line for line in body.splitlines() if re.search(r"\ba0\b", line)]
    if len(v0_text) != 2 or len(a0_text) != 1:
        fail("T35 linked tracer modifies natural v0/a0")


def check_t36_linked(disassembly, symbol_addresses):
    """Prove T36 final scalar addresses and transparent dynamic routing."""
    body = function_body(disassembly, "zeroCtrlCollectionPaf9A285882Trace")
    prefix = "zeroCtrlCollectionPaf9A285882"
    for suffix, uses in (("LastItem", [("sw", 16, 8)]),
            ("NaturalResult", [("sw", 2, 8)]),
            ("Hits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("NonzeroHits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("ZeroResumeTarget", [("lw", 8, 8)]),
            ("NonzeroTarget", [("lw", 8, 8)])):
        linked_scalar_uses(body, prefix + suffix,
                symbol_addresses[prefix + suffix], uses)
    words = linked_instructions(body)
    raw = [word for _pc, word in words]
    if sum(word >> 26 == 4 and (word >> 21) & 0x1F == 2 for word in raw) != 1:
        fail("T36 linked tracer does not have one natural-result branch")
    if any(word >> 26 == 3 or (word & 0xFC00003F) == 9 for word in raw):
        fail("T36 linked tracer contains JAL/JALR")
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 2 or any(re.search(r"\bra\b", line)
            for line in body.splitlines()):
        fail("T36 linked tracer assigns v0 or ra")
    tail = [0x8FA90004, 0x27BD0008, 0x01000008, 0x8FA8FFF8]
    if not any(raw[i:i + 4] == tail for i in range(len(raw) - 3)):
        fail("T36 linked tracer lacks JR-before-delay-slot-t0-restore tail")
    if raw.count(0x27BDFFF8) != 1 or raw.count(0x27BD0008) != 1:
        fail("T36 linked tracer private frame is unbalanced")


def check_t37_linked(disassembly, symbol_addresses):
    """Prove T37 final scalars and transparent natural-result routing."""
    body = function_body(disassembly, "zeroCtrlPostCollectionPafFCF265D8Trace")
    prefix = "zeroCtrlPostCollectionPafFCF265D8"
    for suffix, uses in (("NaturalResult", [("sw", 2, 8)]),
            ("Hits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("NonzeroHits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("ZeroResumeTarget", [("lw", 8, 8)]),
            ("NonzeroTarget", [("lw", 8, 8)])):
        linked_scalar_uses(body, prefix + suffix,
                symbol_addresses[prefix + suffix], uses)
    raw = [word for _pc, word in linked_instructions(body)]
    if sum(word >> 26 == 4 and (word >> 21) & 0x1F == 2
            for word in raw) != 1:
        fail("T37 linked tracer lacks one natural v0 branch")
    if any(word >> 26 == 3 or (word & 0xFC00003F) == 9 for word in raw):
        fail("T37 linked tracer contains JAL/JALR")
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 2 or any(re.search(r"\bra\b", line)
            for line in body.splitlines()):
        fail("T37 linked tracer assigns v0 or references ra")
    tail = [0x8FA90004, 0x27BD0008, 0x01000008, 0x8FA8FFF8]
    if not any(raw[i:i + 4] == tail for i in range(len(raw) - 3)):
        fail("T37 linked tracer lacks its exact transparent tail")
    if raw.count(0x27BDFFF8) != 1 or raw.count(0x27BD0008) != 1:
        fail("T37 linked tracer private frame is unbalanced")


def check_t38_linked(disassembly, symbol_addresses):
    """Prove T38 final scalars and transparent masked-result routing."""
    body = function_body(disassembly, "zeroCtrlMaskedPafC59FC3D0Trace")
    prefix = "zeroCtrlMaskedPafC59FC3D0"
    for suffix, uses in (("DecisionValue", [("sw", 2, 8)]),
            ("Hits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("NonzeroHits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("ZeroResumeTarget", [("lw", 8, 8)]),
            ("NonzeroTarget", [("lw", 8, 8)])):
        linked_scalar_uses(body, prefix + suffix,
                symbol_addresses[prefix + suffix], uses)
    raw = [word for _pc, word in linked_instructions(body)]
    if sum(word >> 26 == 4 and (word >> 21) & 0x1F == 2
            for word in raw) != 1:
        fail("T38 linked tracer lacks one masked-v0 decision branch")
    if any(word >> 26 == 3 or (word & 0xFC00003F) == 9 for word in raw):
        fail("T38 linked tracer contains JAL/JALR")
    v0_lines = [line for line in body.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 2 or any(re.search(r"\bra\b", line)
            for line in body.splitlines()):
        fail("T38 linked tracer transforms v0 or references ra")
    tail = [0x8FA90004, 0x27BD0008, 0x01000008, 0x8FA8FFF8]
    if not any(raw[i:i + 4] == tail for i in range(len(raw) - 3)):
        fail("T38 linked tracer lacks its exact transparent tail")
    if raw.count(0x27BDFFF8) != 1 or raw.count(0x27BD0008) != 1:
        fail("T38 linked tracer private frame is unbalanced")


def check_t39_linked(disassembly, symbol_addresses):
    """Prove T39 final scalars and transparent masked-result routing."""
    body = function_body(disassembly, "zeroCtrlMaskedPafC59FC3D0SecondTrace")
    prefix = "zeroCtrlMaskedPafC59FC3D0Second"
    for suffix, uses in (("DecisionValue", [("sw", 2, 8)]),
            ("Hits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("NonzeroHits", [("lw", 9, 8), ("sw", 9, 8)]),
            ("ZeroResumeTarget", [("lw", 8, 8)]),
            ("NonzeroTarget", [("lw", 8, 8)])):
        linked_scalar_uses(body, prefix + suffix,
                symbol_addresses[prefix + suffix], uses)
    raw = [word for _pc, word in linked_instructions(body)]
    if sum(word >> 26 == 4 and (word >> 21) & 0x1F == 2
            for word in raw) != 1:
        fail("T39 linked tracer lacks one masked-v0 decision branch")
    if any(word >> 26 == 3 or (word & 0xFC00003F) == 9 for word in raw):
        fail("T39 linked tracer contains JAL/JALR")
    for register in ("v0", "s0", "ra"):
        lines = [line for line in body.splitlines() if re.search(
            r"\b" + register + r"\b", line)]
        expected = 2 if register == "v0" else 0
        if len(lines) != expected:
            fail("T39 linked tracer changes or references " + register)
    tail = [0x8FA90004, 0x27BD0008, 0x01000008, 0x8FA8FFF8]
    if not any(raw[i:i + 4] == tail for i in range(len(raw) - 3)):
        fail("T39 linked tracer lacks its exact transparent tail")
    if raw.count(0x27BDFFF8) != 1 or raw.count(0x27BD0008) != 1:
        fail("T39 linked tracer private frame is unbalanced")

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
            "zeroCtrlPostVshNaturalResult",
            "zeroCtrlStateZero15To14CompatMode",
            "zeroCtrlStateZero15To14EffectiveResult",
            "zeroCtrlStateZero15To14SubstitutionHits",
            "zeroCtrlPostVshArgument", "zeroCtrlPostVshCompatMode",
            "zeroCtrlPostVshEffectiveResult", "zeroCtrlPostVshSubstitutionHits"):
        if not re.search(r"^[0-9a-fA-F]+\s+\w\s+" + symbol + r"$", nm, re.M):
            fail("missing Sony module_start wrapper symbol " + symbol)
    symbol_addresses = {}
    for line in nm.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+\w\s+(\S+)$", line)
        if match:
            symbol_addresses[match.group(2)] = int(match.group(1), 16)
    for start, end, counter, result in T22_CONSUMER_WRAPPERS:
        for symbol in (start, end, counter, result):
            if symbol not in symbol_addresses:
                fail("missing linked T22 symbol " + symbol)
        if symbol_addresses[end] <= symbol_addresses[start]:
            fail(start + " has an empty or reversed linked range")
    if T22_CONSUMER_TARGET not in symbol_addresses:
        fail("missing linked T22 natural-target symbol")
    for symbol in T24_SCALARS + T25_SCALARS:
        if symbol not in symbol_addresses:
            fail("missing linked T24 scalar " + symbol)
    for wrapper in T27_PREDICATE_WRAPPERS:
        for symbol in wrapper:
            if symbol not in symbol_addresses:
                fail("missing linked T27 predicate symbol " + symbol)
    for symbol in T27_MASK_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T27 mask symbol " + symbol)
    for symbol in T32_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T32 symbol " + symbol)
    for symbol in T33_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T33 symbol " + symbol)
    for symbol in T35_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T35 symbol " + symbol)
    for symbol in T36_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T36 symbol " + symbol)
    for symbol in T37_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T37 symbol " + symbol)
    for symbol in T38_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T38 symbol " + symbol)
    for symbol in T39_SYMBOLS:
        if symbol not in symbol_addresses:
            fail("missing linked T39 symbol " + symbol)
    disassembly = subprocess.check_output(["psp-objdump", "-dr", str(elf)], text=True)
    check_t311_linked(disassembly, symbol_addresses)
    check_t32_linked(disassembly, symbol_addresses)
    effective_addr = symbol_addresses["zeroCtrlStateZero15To14EffectiveResult"]
    for symbol in ("zeroCtrlStateZeroClass15Trace",
            "zeroCtrlStateZeroClass17Trace"):
        check_t301_class_input(function_body(disassembly, symbol), symbol,
                expected_addr=effective_addr)
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
        if symbol == "zeroCtrlPostPafReturnTrace":
            expected_count = 2
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
    for symbol in ("zeroCtrlConsumer13F6CTrace",
            "zeroCtrlConsumer14020Trace"):
        check_selective_consumer_semantics(function_body(disassembly, symbol), symbol)
    for symbol, _end, _counter, _result, _target in T27_PREDICATE_WRAPPERS:
        check_t22_consumer_semantics(function_body(disassembly, symbol), symbol)
    check_t27_mask_semantics(function_body(disassembly,
        "zeroCtrlPafCapabilityMaskTrace"))
    check_t30_state_zero_return_semantics(function_body(disassembly,
        "zeroCtrlStateZeroVReturnTrace"))
    check_t31_vsh_return_semantics(function_body(disassembly,
        "zeroCtrlPostVshReturnTrace"))
    check_t32_vcall_semantics(function_body(disassembly,
        "zeroCtrlPostImposeVCallTrace"), function_body(disassembly,
        "zeroCtrlPostImposeVCallReturnTrace"))
    check_t34_vcall_semantics(function_body(disassembly,
        "zeroCtrlPostMinusOneVCall64Trace"), function_body(disassembly,
        "zeroCtrlPostMinusOneVCall64ReturnTrace"))
    check_t32_linked_pair(disassembly, symbol_addresses,
        "zeroCtrlPostMinusOneVCall64")
    check_t34_linked_collection(disassembly, symbol_addresses)
    t35 = function_body(disassembly, "zeroCtrlCollectionPafFCF265D8Trace")
    check_t35_decision_semantics(t35)
    check_t35_linked(disassembly, symbol_addresses)
    check_t36_linked(disassembly, symbol_addresses)
    check_t37_linked(disassembly, symbol_addresses)
    check_t38_linked(disassembly, symbol_addresses)
    check_t39_linked(disassembly, symbol_addresses)


def check_stub_object(stub_object):
    disassembly = subprocess.check_output(
        ["psp-objdump", "-dr", str(stub_object)], text=True
    )
    for symbol in ("zeroCtrlStateZeroClass15Trace",
            "zeroCtrlStateZeroClass17Trace"):
        check_t301_class_input(function_body(disassembly, symbol), symbol,
                relocatable=True)
    post_impose_call = function_body(disassembly, "zeroCtrlPostImposeVCallTrace")
    post_impose_return = function_body(disassembly,
            "zeroCtrlPostImposeVCallReturnTrace")
    check_t32_vcall_semantics(post_impose_call, post_impose_return)
    t32_relocations = (
        (post_impose_call, "zeroCtrlPostImposeVCallTarget", 1, 1, r"\bsw\s+v0,"),
        (post_impose_call, "zeroCtrlPostImposeVCallSavedRA", 1, 1, r"\bsw\s+ra,"),
        (post_impose_call, "zeroCtrlPostImposeVCallHits", 1, 2, None),
        (post_impose_return, "zeroCtrlPostImposeVCallNaturalResult", 1, 1,
            r"\bsw\s+v0,"),
        (post_impose_return, "zeroCtrlPostImposeVCallReturnHits", 1, 2, None),
        (post_impose_return, "zeroCtrlPostImposeVCallSavedRA", 1, 1, r"\blw\s+ra,"),
    )
    for body, scalar, hi_count, lo_count, instruction in t32_relocations:
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", body)) != hi_count or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", body)) != lo_count:
            fail("T32 wrapper has wrong exact relocation counts for " + scalar)
        if instruction and not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                scalar + r"\b", body):
            fail("T32 wrapper does not bind relocation for " + scalar)
    for body, counter in ((post_impose_call, "zeroCtrlPostImposeVCallHits"),
            (post_impose_return, "zeroCtrlPostImposeVCallReturnHits")):
        for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                    counter + r"\b", body):
                fail("T32 wrapper does not bind counter relocation for " + counter)
    if len(re.findall(r"R_MIPS_HI16\s+zeroCtrlPostImposeVCallReturnTrace\b",
            post_impose_call)) != 1 or len(re.findall(
            r"R_MIPS_LO16\s+zeroCtrlPostImposeVCallReturnTrace\b",
            post_impose_call)) != 1:
        fail("T32 call wrapper does not bind its dedicated return tracer")
    t33_call = function_body(disassembly, "zeroCtrlPostMinusOneVCall64Trace")
    t33_return = function_body(disassembly, "zeroCtrlPostMinusOneVCall64ReturnTrace")
    check_t34_vcall_semantics(t33_call, t33_return)
    for body, scalar, hi, lo, op in (
        (t33_call, "zeroCtrlPostMinusOneVCall64Target", 1, 1, r"\bsw\s+v0,"),
        (t33_call, "zeroCtrlPostMinusOneVCall64SavedRA", 1, 1, r"\bsw\s+ra,"),
        (t33_call, "zeroCtrlPostMinusOneVCall64Hits", 1, 2, None),
        (t33_return, "zeroCtrlPostMinusOneVCall64NaturalResult", 1, 1, r"\bsw\s+v0,"),
        (t33_return, "zeroCtrlPostMinusOneVCall64ReturnHits", 1, 2, None),
        (t33_return, "zeroCtrlPostMinusOneVCall64SavedRA", 1, 1, r"\blw\s+ra,")):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", body)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", body)) != lo:
            fail("T33 wrapper has wrong relocation counts for " + scalar)
        if op and not relocation_bound_to_instruction(body, scalar, op):
            fail("T33 wrapper does not bind relocation for " + scalar)
    for body, scalar, hi, lo, op in (
        (t33_return, "zeroCtrlPostMinusOneVCall64CollectionEnabled", 1, 1,
            r"\blw\s+t1,"),
        (t33_return, "zeroCtrlPostMinusOneVCall64CountSnapshot", 1, 1,
            r"\bsw\s+t1,"),
        (t33_return, "zeroCtrlPostMinusOneVCall64ArraySnapshot", 1, 1,
            r"\bsw\s+t1,"),
        (t33_return, "zeroCtrlPostMinusOneVCall64ArrayReadHits", 1, 2, None)):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", body)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", body)) != lo:
            fail("T34 wrapper has wrong relocation counts for " + scalar)
        if op and not relocation_bound_to_instruction(body, scalar, op):
            fail("T34 wrapper does not bind relocation for " + scalar)
    for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
        if not relocation_bound_to_instruction(t33_return,
                "zeroCtrlPostMinusOneVCall64ArrayReadHits", instruction):
            fail("T34 wrapper does not bind array-read counter " + instruction)
    for body, counter in (
            (t33_call, "zeroCtrlPostMinusOneVCall64Hits"),
            (t33_return, "zeroCtrlPostMinusOneVCall64ReturnHits")):
        for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(body, counter, instruction):
                fail("T33 wrapper does not bind " + instruction +
                     " to counter " + counter)
    if len(re.findall(r"R_MIPS_HI16\s+zeroCtrlPostMinusOneVCall64ReturnTrace\b",
            t33_call)) != 1 or len(re.findall(
            r"R_MIPS_LO16\s+zeroCtrlPostMinusOneVCall64ReturnTrace\b",
            t33_call)) != 1:
        fail("T33 call wrapper does not bind its return tracer")
    t35 = function_body(disassembly, "zeroCtrlCollectionPafFCF265D8Trace")
    check_t35_decision_semantics(t35)
    for scalar, hi, lo, op in (
            ("zeroCtrlCollectionPafFCF265D8LastItem", 1, 1, r"\bsw\s+a0,"),
            ("zeroCtrlCollectionPafFCF265D8NaturalResult", 1, 1, r"\bsw\s+v0,"),
            ("zeroCtrlCollectionPafFCF265D8Hits", 1, 2, None),
            ("zeroCtrlCollectionPafFCF265D8NonzeroHits", 1, 2, None)):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", t35)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", t35)) != lo:
            fail("T35 tracer has wrong relocation counts for " + scalar)
        if op and not relocation_bound_to_instruction(t35, scalar, op):
            fail("T35 tracer does not bind relocation for " + scalar)
    for counter in ("zeroCtrlCollectionPafFCF265D8Hits",
            "zeroCtrlCollectionPafFCF265D8NonzeroHits"):
        for op in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(t35, counter, op):
                fail("T35 tracer does not bind counter operation for " + counter)
    t36 = function_body(disassembly, "zeroCtrlCollectionPaf9A285882Trace")
    for scalar, hi, lo, op in (
            ("zeroCtrlCollectionPaf9A285882LastItem", 1, 1, r"\bsw\s+s0,"),
            ("zeroCtrlCollectionPaf9A285882NaturalResult", 1, 1, r"\bsw\s+v0,"),
            ("zeroCtrlCollectionPaf9A285882Hits", 1, 2, None),
            ("zeroCtrlCollectionPaf9A285882NonzeroHits", 1, 2, None),
            ("zeroCtrlCollectionPaf9A285882ZeroResumeTarget", 1, 1, r"\blw\s+t0,"),
            ("zeroCtrlCollectionPaf9A285882NonzeroTarget", 1, 1, r"\blw\s+t0,")):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", t36)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", t36)) != lo:
            fail("T36 tracer has wrong exact relocations for " + scalar)
        if op and not relocation_bound_to_instruction(t36, scalar, op):
            fail("T36 tracer does not bind relocation for " + scalar)
    for counter in ("zeroCtrlCollectionPaf9A285882Hits",
            "zeroCtrlCollectionPaf9A285882NonzeroHits"):
        for op in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(t36, counter, op):
                fail("T36 tracer does not bind t1 counter operation")
    t37 = function_body(disassembly, "zeroCtrlPostCollectionPafFCF265D8Trace")
    for scalar, hi, lo, op in (
            ("zeroCtrlPostCollectionPafFCF265D8NaturalResult", 1, 1, r"\bsw\s+v0,"),
            ("zeroCtrlPostCollectionPafFCF265D8Hits", 1, 2, None),
            ("zeroCtrlPostCollectionPafFCF265D8NonzeroHits", 1, 2, None),
            ("zeroCtrlPostCollectionPafFCF265D8ZeroResumeTarget", 1, 1, r"\blw\s+t0,"),
            ("zeroCtrlPostCollectionPafFCF265D8NonzeroTarget", 1, 1, r"\blw\s+t0,")):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", t37)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", t37)) != lo:
            fail("T37 tracer has wrong exact relocations for " + scalar)
        if op and not relocation_bound_to_instruction(t37, scalar, op):
            fail("T37 tracer does not bind relocation for " + scalar)
    for counter in ("zeroCtrlPostCollectionPafFCF265D8Hits",
            "zeroCtrlPostCollectionPafFCF265D8NonzeroHits"):
        for op in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(t37, counter, op):
                fail("T37 tracer does not bind t1 counter operation")
    t38 = function_body(disassembly, "zeroCtrlMaskedPafC59FC3D0Trace")
    for scalar, hi, lo, op in (
            ("zeroCtrlMaskedPafC59FC3D0DecisionValue", 1, 1, r"\bsw\s+v0,"),
            ("zeroCtrlMaskedPafC59FC3D0Hits", 1, 2, None),
            ("zeroCtrlMaskedPafC59FC3D0NonzeroHits", 1, 2, None),
            ("zeroCtrlMaskedPafC59FC3D0ZeroResumeTarget", 1, 1, r"\blw\s+t0,"),
            ("zeroCtrlMaskedPafC59FC3D0NonzeroTarget", 1, 1, r"\blw\s+t0,")):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", t38)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", t38)) != lo:
            fail("T38 tracer has wrong exact relocations for " + scalar)
        if op and not relocation_bound_to_instruction(t38, scalar, op):
            fail("T38 tracer does not bind relocation for " + scalar)
    for counter in ("zeroCtrlMaskedPafC59FC3D0Hits",
            "zeroCtrlMaskedPafC59FC3D0NonzeroHits"):
        for op in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(t38, counter, op):
                fail("T38 tracer does not bind t1 counter operation")
    t39 = function_body(disassembly, "zeroCtrlMaskedPafC59FC3D0SecondTrace")
    for scalar, hi, lo, op in (
            ("zeroCtrlMaskedPafC59FC3D0SecondDecisionValue", 1, 1, r"\bsw\s+v0,"),
            ("zeroCtrlMaskedPafC59FC3D0SecondHits", 1, 2, None),
            ("zeroCtrlMaskedPafC59FC3D0SecondNonzeroHits", 1, 2, None),
            ("zeroCtrlMaskedPafC59FC3D0SecondZeroResumeTarget", 1, 1, r"\blw\s+t0,"),
            ("zeroCtrlMaskedPafC59FC3D0SecondNonzeroTarget", 1, 1, r"\blw\s+t0,")):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", t39)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", t39)) != lo:
            fail("T39 tracer has wrong exact relocations for " + scalar)
        if op and not relocation_bound_to_instruction(t39, scalar, op):
            fail("T39 tracer does not bind relocation for " + scalar)
    for counter in ("zeroCtrlMaskedPafC59FC3D0SecondHits",
            "zeroCtrlMaskedPafC59FC3D0SecondNonzeroHits"):
        for op in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(t39, counter, op):
                fail("T39 tracer does not bind t1 counter operation")
    for symbol, counter in zip(STUBS, COUNTERS):
        if symbol == "zeroCtrlTrigger58D4":
            continue
        body = function_body(disassembly, symbol)
        if len(re.findall(r"R_MIPS_HI16\s+" + counter + r"\b", body)) != 1 or \
                len(re.findall(r"R_MIPS_LO16\s+" + counter + r"\b", body)) != 2:
            fail(symbol + " has wrong simple-trigger counter relocations")
        for operation in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not relocation_bound_to_instruction(body, counter, operation):
                fail(symbol + " does not bind its simple counter " + operation)
    trigger58 = function_body(disassembly, "zeroCtrlTrigger58D4")
    for scalar, hi_count, lo_count in (
            ("zeroCtrlTrigger58D4FunctionalMode", 1, 1),
            ("zeroCtrlTrigger58D4Request", 1, 2),
            ("zeroCtrlTrigger58D4OriginalTarget", 1, 1),
            ("zeroCtrlTrigger58D4Hits", 2, 4)):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b",
                trigger58)) != hi_count or len(re.findall(
                r"R_MIPS_LO16\s+" + scalar + r"\b", trigger58)) != lo_count:
            fail("zeroCtrlTrigger58D4 has wrong relocations for " + scalar)
    for scalar, operation in (
            ("zeroCtrlTrigger58D4FunctionalMode", r"\blw\s+t1,"),
            ("zeroCtrlTrigger58D4Request", r"\blw\s+t1,"),
            ("zeroCtrlTrigger58D4Request", r"\bsw\s+zero,"),
            ("zeroCtrlTrigger58D4OriginalTarget", r"\blw\s+t0,")):
        if not relocation_bound_to_instruction(trigger58, scalar, operation):
            fail("zeroCtrlTrigger58D4 does not bind " + scalar + " to " + operation)
    for operation in (r"\blw\s+t1,", r"\bsw\s+t1,"):
        if len(re.findall(operation + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlTrigger58D4Hits\b", trigger58)) != 2:
            fail("zeroCtrlTrigger58D4 lacks two exact counter " + operation +
                    " sequences")
    if not re.search(r"\blw\s+t0,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
            r"zeroCtrlTrigger58D4OriginalTarget\b[\s\S]*?\bjr\s+t0\b[\s\S]*?"
            r"\bnop\b", trigger58):
        fail("zeroCtrlTrigger58D4 natural target is not tail-jumped through t0")
    if re.search(r"\b(?:k0|k1|sp|gp)\b|\bjalr?\b", trigger58):
        fail("zeroCtrlTrigger58D4 uses reserved/stateful registers or nested calls")
    for symbol, _end, counter, result in T22_CONSUMER_WRAPPERS:
        body = function_body(disassembly, symbol)
        check_selective_consumer_semantics(body, symbol)
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
        if len(re.findall(r"R_MIPS_HI16\s+" + result + r"\b", body)) != 1 or \
                len(re.findall(r"R_MIPS_LO16\s+" + result + r"\b", body)) != 1 or \
                not re.search(r"\bsw\s+v0,[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                    result + r"\b", body):
            fail(symbol + " lacks the unique natural-result store relocation")
        if symbol.endswith("14020Trace"):
            scalar_prefix = "zeroCtrlConsumer14020"
        else:
            scalar_prefix = "zeroCtrlConsumer13F6C"
        if symbol.endswith(("14020Trace", "13F6CTrace")):
            expected_relocations = {
                scalar_prefix + "CompatMode": (1, 1),
                scalar_prefix + "EffectiveResult": (1, 1),
                scalar_prefix + "SubstitutionHits": (1, 2),
            }
            for scalar, (hi_count, lo_count) in expected_relocations.items():
                if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", body)) != hi_count or \
                        len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", body)) != lo_count:
                    fail(symbol + " has wrong exact relocation counts for " + scalar)
            relocation_uses = (
                (r"\blw\s+t1,", scalar_prefix + "CompatMode", 1),
                (r"\bsw\s+v0,", scalar_prefix + "EffectiveResult", 1),
                (r"\blw\s+t1,", scalar_prefix + "SubstitutionHits", 1),
                (r"\bsw\s+t1,", scalar_prefix + "SubstitutionHits", 1),
            )
            for instruction, scalar, count in relocation_uses:
                tied = instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" + scalar + r"\b"
                if len(re.findall(tied, body)) != count:
                    fail(symbol + " does not tie " + scalar + " to " + instruction)
    for symbol, _end, counter, result, target in T27_PREDICATE_WRAPPERS:
        body = function_body(disassembly, symbol)
        check_t22_consumer_semantics(body, symbol)
        expected = ((counter, 1, 2), (result, 1, 1), (target, 1, 1))
        for scalar, hi_count, lo_count in expected:
            if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", body)) != hi_count or \
                    len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", body)) != lo_count:
                fail(symbol + " has wrong exact relocation counts for " + scalar)
        if not re.search(r"\bsw\s+v0,[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                result + r"\b", body) or not re.search(
                r"\blw\s+t2,[^\n]*\n[^\n]*R_MIPS_LO16\s+" + target + r"\b", body):
            fail(symbol + " does not bind natural result/target relocations")
    mask_body = function_body(disassembly, "zeroCtrlPafCapabilityMaskTrace")
    check_t27_mask_semantics(mask_body)
    mask_relocations = (
        ("zeroCtrlPafCapabilityMaskNatural", 1, 1, r"\bsw\s+a0,"),
        ("zeroCtrlPafCapabilityMaskHits", 1, 2, None),
        ("zeroCtrlPafCapabilityMaskCompatMode", 1, 1, r"\blw\s+t1,"),
        ("zeroCtrlPafCapabilityMaskSubstitutionHits", 1, 2, None),
        ("zeroCtrlPafCapabilityMaskEffective", 1, 1, r"\bsw\s+a0,"),
        ("zeroCtrlPafCapabilityMaskTarget", 1, 1, r"\blw\s+t2,"),
    )
    for scalar, hi_count, lo_count, instruction in mask_relocations:
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", mask_body)) != hi_count or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", mask_body)) != lo_count:
            fail("T27 mask wrapper has wrong exact relocation counts for " + scalar)
        if instruction and not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                scalar + r"\b", mask_body):
            fail("T27 mask wrapper does not bind relocation for " + scalar)
    for counter in ("zeroCtrlPafCapabilityMaskHits",
            "zeroCtrlPafCapabilityMaskSubstitutionHits"):
        for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
            if not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                    counter + r"\b", mask_body):
                fail("T28 mask wrapper does not bind counter relocation for " + counter)
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
    check_t30_state_zero_return_semantics(state_vreturn)
    require_result_store_relocation(state_vreturn,
            "zeroCtrlStateZeroVReturnTrace", "zeroCtrlStateZeroVCallResult")
    if not re.search(r"R_MIPS_HI16\s+zeroCtrlStateZeroVCallRA\b",
            state_vreturn) or not re.search(r"\bjr\s+ra\b", state_vreturn):
        fail("T30 virtual return does not preserve the Sony ra")
    t30_relocations = (
        ("zeroCtrlStateZero15To14CompatMode", 1, 1, r"\blw\s+t1,"),
        ("zeroCtrlStateZero15To14EffectiveResult", 1, 1, r"\bsw\s+v0,"),
        ("zeroCtrlStateZero15To14SubstitutionHits", 1, 2, None),
    )
    for scalar, hi_count, lo_count, instruction in t30_relocations:
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", state_vreturn)) != hi_count or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", state_vreturn)) != lo_count:
            fail("T30 virtual return has wrong relocation counts for " + scalar)
        if instruction and not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                scalar + r"\b", state_vreturn):
            fail("T30 virtual return does not bind relocation for " + scalar)
    for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
        if not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlStateZero15To14SubstitutionHits\b", state_vreturn):
            fail("T30 virtual return does not bind substitution counter")
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
    check_t31_vsh_return_semantics(post_vsh_return)
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
    t31_relocations = (
        ("zeroCtrlPostVshCompatMode", 1, 1, r"\blw\s+t1,"),
        ("zeroCtrlPostVshEffectiveResult", 1, 1, r"\bsw\s+v0,"),
        ("zeroCtrlPostVshSubstitutionHits", 1, 2, None),
    )
    for scalar, hi_count, lo_count, instruction in t31_relocations:
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", post_vsh_return)) != hi_count or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", post_vsh_return)) != lo_count:
            fail("T31 return has wrong exact relocation counts for " + scalar)
        if instruction and not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+" +
                scalar + r"\b", post_vsh_return):
            fail("T31 return does not bind relocation for " + scalar)
    for instruction in (r"\blw\s+t1,", r"\bsw\s+t1,"):
        if not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlPostVshSubstitutionHits\b", post_vsh_return):
            fail("T31 return does not bind substitution counter")
    post_vsh_call = function_body(disassembly, "zeroCtrlPostVshCallTrace")
    if len(re.findall(r"R_MIPS_HI16\s+zeroCtrlPostVshArgument\b",
            post_vsh_call)) != 1 or len(re.findall(
            r"R_MIPS_LO16\s+zeroCtrlPostVshArgument\b", post_vsh_call)) != 1 or \
            not re.search(r"\bsw\s+a0,[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlPostVshArgument\b", post_vsh_call):
        fail("T31 call wrapper does not bind the exact argument capture")
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
    check_mips_immediate_patterns()
    check_sources(args.source_root.resolve())
    if args.user_elf:
        check_elf(args.user_elf)
    if args.stub_object:
        check_stub_object(args.stub_object)
    print("verified PSP-1000 static safety invariants")


if __name__ == "__main__":
    main()
