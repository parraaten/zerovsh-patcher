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
    logger = (root / "kernel/logger.c").read_text()
    logger_header = (root / "kernel/logger.h").read_text()
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
    if "PSP_EXPORT_FUNC_NID(zeroCtrlRegisterPsp1000FunctionalBridge, 0x13373581)" \
            not in kernel_exports or \
            "STUB_FUNC 0x13373581, zeroCtrlRegisterPsp1000FunctionalBridge" \
            not in user_imports:
        fail("functional bridge registration import/export is missing")
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
    vsh58_end = kernel.find("static void zeroCtrlWriteVsh589cWindow(",
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
    scan_end = kernel.find("static void zeroCtrlInstallVsh589CCallTrace(void)",
            scan_start)
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
    structure_start = kernel.find(
            "static void zeroCtrlWriteFunctionalCallbackStructure(void)")
    metadata_declaration = kernel.find(
            "static int zeroCtrlLoadedModuleMetadataValid(SceModule2 *mod);")
    metadata_definition = kernel.find(
            "static int zeroCtrlLoadedModuleMetadataValid(SceModule2 *mod) {")
    if not 0 <= metadata_declaration < structure_start < metadata_definition:
        fail("loaded-module metadata declaration does not precede VSH +589C capture")
    structure_end = kernel.find("static int zeroCtrlVsh589cA0Definition(",
            structure_start)
    structure = kernel[structure_start:structure_end]
    for token in ('sceKernelFindModuleByName("vsh_module")', "model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "!slide_diag.functional_enabled",
            "!zeroCtrlLoadedModuleMetadataValid(vsh)",
            'strcmp(vsh->modname, "vsh_module") != 0',
            "vsh->modid != slide_diag.vsh_modid",
            "vsh->text_addr != slide_diag.vsh_text_addr",
            "vsh->text_size != slide_diag.vsh_text_size",
            "vsh->text_addr > 0xFFFFFFFFU - 0x5894",
            "zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x5894,",
            "0x5C", "words=23",
            "for (offset = 0x5894; offset <= 0x58EC; offset += 4)",
            "word = _lw(pc)", "opcode = word >> 26",
            'class_name = "SPECIAL"', 'class_name = "J"',
            'class_name = "JAL"', 'class_name = "JR"',
            'class_name = "JALR"', 'class_name = "REGIMM"',
            'class_name = "BEQ"', 'class_name = "BNE"',
            'class_name = "BLEZ"', 'class_name = "BGTZ"',
            'class_name = "BEQL"', 'class_name = "BNEL"',
            'class_name = "BLEZL"', 'class_name = "BGTZL"',
            "zeroCtrlMipsJumpTarget(pc, word) - vsh->text_addr",
            "opcode >= 0x14 && opcode <= 0x17",
            "pc + 4 + displacement * 4 - vsh->text_addr",
            "[psp1000-vsh589c-structure] validation=1",
            "[psp1000-vsh589c-word] off=0x%05X word=0x%08X",
            "class=%s op=%u rs=%u rt=%u rd=%u sa=%u fn=%u ",
            "target=0x%05X"):
        if token not in structure:
            fail("VSH +589C structural capture lacks " + token)
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL", "MAKE_JUMP",
            "hook_import", "zeroCtrlRedir", "zeroCtrlTrigger58D4(",
            "zeroCtrlSetSlideState", "Alloc", "malloc"):
        if forbidden in structure:
            fail("VSH +589C structural capture is not read-only: " + forbidden)
    structure_range = structure.find(
            "zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x5894,")
    structure_read = structure.find("word = _lw(pc)")
    if not 0 <= structure_range < structure_read:
        fail("VSH +589C capture reads before validating its complete 0x5C-byte range")
    if "zeroCtrlWriteFunctionalCallbackStructure();" in writer:
        fail("retired VSH +589C structural capture is still emitted automatically")
    install_start = kernel.find("static void zeroCtrlInstallVsh589CCallTrace(void)")
    install_end = kernel.find("static int zeroCtrlResolveVshCtrlPeekImport(",
            install_start)
    vsh589c_install = kernel[install_start:install_end]
    for token in ("!slide_diag.minimal_memory_test",
            "vsh->modid != slide_diag.vsh_modid",
            "vsh->text_addr != slide_diag.vsh_text_addr",
            "vsh->text_size != slide_diag.vsh_text_size",
            "(_lw(text + 0x589C) & 0xFFFF0000) != 0x3C020000",
            "_lw(text + 0x58A0) != 0x27BDFFF0",
            "(_lw(text + 0x58A4) & 0xFFFF0000) != 0xAC440000",
            "_lw(text + 0x58A8) != 0xAFBF0000",
            "owner = text + 0x58AC", "_lw(text + 0x58B0) != 0",
            "original_target != text + 0x5C98",
            "trace_helper = storage_pending->stub_addr + 24",
            "zeroCtrlVshModuleRangeValid(helper, trace_helper, 80)",
            "trace_tail = trace_helper + 72", "owner + 8",
            "_sw(0, storage_total->counter_addr)",
            "_sw(0, storage_pending->counter_addr)",
            "_sw(tail_replacement, trace_tail)", "_sw(replacement, owner)"):
        if token not in vsh589c_install:
            fail("VSH +58AC diagnostic transaction lacks " + token)
    tail_write = vsh589c_install.find("_sw(tail_replacement, trace_tail)")
    tail_icache = vsh589c_install.find("sceKernelIcacheInvalidateRange(", tail_write)
    owner_write = vsh589c_install.find("_sw(replacement, owner)", tail_icache)
    owner_icache = vsh589c_install.find("sceKernelIcacheInvalidateRange(", owner_write)
    if not 0 <= tail_write < tail_icache < owner_write < owner_icache or \
            vsh589c_install.count("_sw(") != 4:
        fail("VSH +58AC diagnostic does not commit tail/counters before sole owner")
    if "zeroCtrlInstallVsh589CCallTrace();" in writer:
        fail("retired VSH +58AC diagnostic installer remains active")
    if "zeroCtrlWriteFunctionalVshRequestCallers();" in kernel:
        fail("superseded VSH +589C/+57B0 scan is still emitted automatically")
    vsh3_start = kernel.find(
            "static void zeroCtrlWriteFunctionalVsh3f568Analysis(void)")
    vsh3_end = kernel.find("static int zeroCtrlWriteSlideDiagnostics(", vsh3_start)
    if vsh3_start < 0 or vsh3_end < 0:
        fail("VSH +3F568 implementation analysis is missing")
    vsh3 = kernel[vsh3_start:vsh3_end]
    for token in ("model != 0", "sceKernelDevkitVersion() != 0x06060110",
            "slide_diag.functional_enabled", "!slide_diag.minimal_memory_test",
            "zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x3F568, 8)",
            "word_56fc = _lw(text + 0x56FC)",
            "word_5700 = _lw(text + 0x5700)",
            "word_5704 = _lw(text + 0x5704)",
            "word_5708 = _lw(text + 0x5708)",
            "decoded_a1 != text + 0x589C", "(word_5704 >> 26) != 3",
            "zeroCtrlMipsJumpTarget(text + 0x5704, word_5704)",
            "((word_5708 >> 11) & 0x1F) != 4",
            "[vsh3f568-callsite] validation=1 caller=0x05704",
            "thunk_word = _lw(stub)", "(thunk_word >> 26) != 2",
            "_lw(stub + 4) != 0", "[vsh3f568-thunk] validation=1",
            "resolved = zeroCtrlMipsJumpTarget(stub, thunk_word)",
            "table_addr = (unsigned int)vsh->stub_top",
            "table_size = vsh->stub_size",
            "zeroCtrlVshModuleRangeValid(vsh, table_addr, table_size)",
            "entry->len == 0", "entry->stubcount > 0xFFFFFFFFU / 8",
            "zeroCtrlVshModuleRangeValid(vsh, stubtable, functions_size)",
            "zeroCtrlVshModuleRangeValid(vsh, nidtable, nids_size)",
            "stubtable + i * 8 != stub", "matches != 1",
            "zeroCtrlCopyVshImportLibrary(vsh, entry->libname",
            "[vsh3f568-import] validation=1",
            "import_nid != 0xA989A2C4", 'strcmp(import_library, "scePaf")',
            'strcmp(owner->modname, "scePaf_Module")',
            "sceKernelFindModuleByAddress(resolved)",
            "zeroCtrlLoadedModuleMetadataValid(owner)",
            "zeroCtrlVshModuleRangeValid(owner, resolved, sizeof(wrapper))",
            "zeroCtrlMipsMove(wrapper[1], 2, 4)",
            "zeroCtrlMipsMove(wrapper[4], 6, 5)",
            "zeroCtrlMipsMove(wrapper[7], 5, 2)",
            "inner = zeroCtrlMipsJumpTarget(resolved + 0x18, wrapper[6])",
            "context_slot = ((wrapper[0] & 0xFFFF) << 16) +",
            "(int)(short)(wrapper[2] & 0xFFFF)",
            "[paf-a989-wrapper] validation=1", "callback_reg=6",
            "descriptor_reg=5 context_reg=4", "[paf-a989-context-slot]",
            "zeroCtrlModuleContainingSegment(owner, inner",
            "zeroCtrlVshModuleRangeValid(owner, inner, 4)",
            "inner - owner->text_addr < owner->text_size",
            "[paf-a989-inner] validation=1", "inner_remaining > 0x200",
            "zeroCtrlWritePafA989Inner(owner, inner, inner_size",
            "[paf-a989-summary] wrapper_valid=1 inner_valid=1"):
        if token not in vsh3:
            fail("PAF A989 inner analysis lacks " + token)
    inner_start = kernel.find("static void zeroCtrlWritePafA989Inner(")
    inner_end = kernel.find("static void zeroCtrlWriteVsh3f568ImplFlow(", inner_start)
    inner = kernel[inner_start:inner_end]
    for token in ("unsigned int tracked_callback = 6", "map_size > 0x200",
            "zeroCtrlVshModuleRangeValid(paf, target, map_size)",
            "[paf-a989-inner-map]", "row += 0x20", "unsigned int words[8]",
            '"J"', '"JAL"', '"JR"', '"JALR"', '"BEQ"', '"BNE"',
            '"BLEZ"', '"BGTZ"', '"REGIMM"', '"BRANCH_LIKELY"',
            '"STACK_ALLOC"', '"STACK_FREE"', '"SAVE_RA"',
            '"RESTORE_RA"', "class=RETURN", "[paf-a989-callback] status=STORED",
            "[paf-a989-callback-store]", "[paf-a989-storage-base]",
            "source_input=%s", "status=COPIED", "status=USED_IMMEDIATELY",
            "status=PASSED_TO_CALL", "callback_argument == 0",
            "map_size < 8 || offset > map_size - 8",
            "zeroCtrlVshModuleRangeValid(paf, target + offset + 4, 4)",
            "delay = _lw(target + offset + 4)",
            "zeroCtrlMipsGprWriteDestination(delay)",
            "(unsigned int)delay_destination == tracked_callback",
            "status=OVERWRITTEN_IN_DELAY_SLOT",
            "zeroCtrlMipsMove(delay,", "callback_argument = delay_copy",
            "function == 9 && rs == tracked_callback", "[paf-a989-next]",
            "next_remaining > 0x100", "[paf-a989-next-map]",
            "input_source[4] = 1", "input_source[5] = 2",
            'input_source[rs] == 2 ? "descriptor" : "context"'):
        if token not in inner:
            fail("PAF A989 callback/structural flow lacks " + token)
    copy_start = inner.find("unsigned int callback_copy =")
    provenance_clear = inner.find("input_source[callback_copy] = 0", copy_start)
    tracked_update = inner.find("tracked_callback = callback_copy", copy_start)
    copy_continue = inner.find("continue;", tracked_update)
    if not 0 <= copy_start < provenance_clear < tracked_update < copy_continue:
        fail("callback copy does not invalidate stale input provenance first")
    delay_range = inner.find("map_size < 8 || offset > map_size - 8")
    delay_owner_range = inner.find(
            "zeroCtrlVshModuleRangeValid(paf, target + offset + 4, 4)")
    delay_read = inner.find("delay = _lw(target + offset + 4)")
    delay_check = inner.find("zeroCtrlMipsGprWriteDestination(delay)")
    unknown_handling = inner.find("if (delay_destination < 0)", delay_check)
    overwrite_check = inner.find(
            "(unsigned int)delay_destination == tracked_callback", unknown_handling)
    overwritten_status = inner.find("status=OVERWRITTEN_IN_DELAY_SLOT", overwrite_check)
    delay_forward = inner.find("zeroCtrlMipsMove(delay,", overwritten_status)
    delay_argument = inner.find("callback_argument = delay_copy", delay_forward)
    jalr_use = inner.find("function == 9 && rs == tracked_callback", delay_argument)
    used = inner.find("status=USED_IMMEDIATELY", jalr_use)
    argument_gate = inner.find("callback_argument == 0", used)
    passed = inner.find("status=PASSED_TO_CALL", argument_gate)
    if not 0 <= delay_range < delay_owner_range < delay_read < delay_check < \
            unknown_handling < overwrite_check < overwritten_status < \
            delay_forward < delay_argument < jalr_use < used < argument_gate < passed:
        fail("PAF A989 delay-slot forwarding/classification ordering is unsafe")
    inner_decode = vsh3.find(
            "inner = zeroCtrlMipsJumpTarget(resolved + 0x18, wrapper[6])")
    wrapper_text_lower = vsh3.find("inner >= owner->text_addr", inner_decode)
    wrapper_text_upper = vsh3.find(
            "inner - owner->text_addr < owner->text_size", wrapper_text_lower)
    wrapper_text_flag = vsh3.find("inner_in_text=1 inner_off=0x%X", wrapper_text_upper)
    wrapper_outside = vsh3.find(
            "inner_in_text=0 inner_off=OUTSIDE_TEXT", wrapper_text_flag)
    if not 0 <= inner_decode < wrapper_text_lower < wrapper_text_upper < \
            wrapper_text_flag < wrapper_outside:
        fail("wrapper inner_off lacks two-bound text classification")
    if "inner >= owner->text_addr ? inner - owner->text_addr" in vsh3:
        fail("wrapper inner_off still uses a lower-bound-only calculation")
    next_target = inner.find("unsigned int next = zeroCtrlMipsJumpTarget(pc, word)")
    next_segment = inner.find("zeroCtrlModuleContainingSegment(paf, next", next_target)
    next_text_lower = inner.find("next >= paf->text_addr", next_segment)
    next_text_upper = inner.find(
            "next - paf->text_addr < paf->text_size", next_text_lower)
    next_in_text = inner.find(
            "target_in_text=1 \"\n                                \"target_off=0x%X callback_arg_reg=%u",
            next_text_upper)
    next_outside = inner.find(
            "target_in_text=0 \"\n                                \"target_off=OUTSIDE_TEXT callback_arg_reg=%u",
            next_in_text)
    next_map_range = inner.find(
            "zeroCtrlVshModuleRangeValid(paf, next, next_size)", next_outside)
    if not 0 <= next_target < next_segment < next_text_lower < next_text_upper < \
            next_in_text < next_outside < next_map_range:
        fail("next PAF target lacks two-bound text classification after segment validation")
    if "next >= paf->text_addr ? next - paf->text_addr" in inner:
        fail("next PAF target still uses a lower-bound-only offset")
    if "tracked_reg=%u" in inner[next_target:next_map_range]:
        fail("next PAF target mislabels the proven callback argument register")
    container_start = kernel.find(
            "static void zeroCtrlWritePafA989ContainerStructure(")
    container_end = kernel.find(
            "static void zeroCtrlWriteVsh3f568ImplFlow(", container_start)
    if container_start < 0 or container_end < 0:
        fail("secondary PAF A989 container analysis is missing")
    container = kernel[container_start:container_end]
    for token in ("inner_size < sizeof(words)",
            "zeroCtrlVshModuleRangeValid(paf, inner, sizeof(words))",
            "words[i] = _lw(inner + i * 4)",
            "zeroCtrlMipsMove(words[0x14 / 4], 17, 4)",
            "((words[0x20 / 4] >> 16) & 0x1F) != 20",
            "zeroCtrlMipsMove(words[0x24 / 4], 20, 6)",
            "zeroCtrlMipsMove(words[0x2C / 4], 19, 5)",
            "(words[0x40 / 4] >> 26) != 3",
            "words[0x44 / 4] != 0x24040010",
            "!zeroCtrlMipsMove(words[0x50 / 4], 16, 2)",
            "(words[0x54 / 4] >> 26) != 3",
            "(short)(words[0x58 / 4] & 0xFFFF) != 4",
            "zeroCtrlMipsMove(words[0x5C / 4], 17, 2)",
            "zeroCtrlMipsMove(words[0x60 / 4], 4, 2)",
            "zeroCtrlMipsMove(words[0x68 / 4], 5, 19)",
            "(short)(words[0x6C / 4] & 0xFFFF) != 8",
            "(short)(words[0x78 / 4] & 0xFFFF) != 12",
            "zeroCtrlMipsMove(words[0x7C / 4], 6, 16)",
            "(words[0x90 / 4] >> 26) != 3",
            "zeroCtrlMipsMove(words[0x94 / 4], 4, 0)",
            "[paf-a989-container] validation=1",
            "base_origin=CALL_RETURN", "base_call_off=0x40",
            "base_call_arg0=0x10",
            "off=0x48 field_off=0x0 source=context",
            "off=0x58 field_off=0x4 source=zero",
            "delay_slot_of=0x54",
            "off=0x6C field_off=0x8",
            "source=second_call_return",
            "off=0x78 field_off=0xC source=callback",
            "status=STORED_ON_NORMAL_FALLTHROUGH",
            "[paf-a989-container-forward] off=0x7C container_reg=16 arg_reg=6",
            "zeroCtrlMipsJumpTarget(inner + 0x40",
            "zeroCtrlMipsJumpTarget(inner + 0x54",
            "first_target == second_target",
            "consumer_target = zeroCtrlMipsJumpTarget(inner + 0x90",
            "zeroCtrlModuleContainingSegment(paf, consumer_target",
            "consumer_remaining > 0x100", "consumer_size &= ~3U",
            "zeroCtrlVshModuleRangeValid(paf, consumer_target, consumer_size)",
            "consumer_target >= paf->text_addr &&",
            "consumer_target - paf->text_addr < paf->text_size",
            "container_arg_reg=6 target_in_text=1 target_off=0x%X",
            "container_arg_reg=6 target_in_text=0",
            "target_off=OUTSIDE_TEXT segment=%u",
            "[paf-a989-container-consumer-map]", "row < consumer_size"):
        if token not in container:
            fail("secondary PAF A989 container analysis lacks " + token)
    first_guard = container.find("if (!zeroCtrlMipsMove(words[0x14 / 4]")
    delay_store_guard = container.find(
            "(short)(words[0x58 / 4] & 0xFFFF) != 4", first_guard)
    second_return_guard = container.find(
            "zeroCtrlMipsMove(words[0x5C / 4], 17, 2)", delay_store_guard)
    validated_output = container.find("[paf-a989-container] validation=1")
    if not 0 <= first_guard < delay_store_guard < second_return_guard < validated_output:
        fail("PAF container conclusions precede full structure/delay validation")
    for index, reg in ((0x70, 5), (0x74, 9)):
        if f"words[0x{index:X} / 4]" not in container:
            fail(f"constructed PAF address lacks loaded LUI at +0x{index:X}")
    for index in (0x80, 0x84):
        if f"(int)(short)(words[0x{index:X} / 4] & 0xFFFF)" not in container:
            fail(f"constructed PAF address lacks signed low half at +0x{index:X}")
    for absolute in ("0x08860910", "0x08860958", "0x088FBF74"):
        if absolute in container:
            fail("secondary PAF analysis hardcodes hardware address " + absolute)
    segment_check = container.find(
            "zeroCtrlModuleContainingSegment(paf, consumer_target")
    full_range = container.find(
            "zeroCtrlVshModuleRangeValid(paf, consumer_target, consumer_size)",
            segment_check)
    first_consumer_read = container.find("_lw(consumer_target", full_range)
    if not 0 <= segment_check < full_range < first_consumer_read:
        fail("PAF consumer map reads before segment/full-range validation")
    secondary_call = vsh3.find(
            "zeroCtrlWritePafA989ContainerStructure(owner, inner, inner_size)")
    primary_call = vsh3.find("zeroCtrlWritePafA989Inner(owner, inner, inner_size")
    primary_summary = vsh3.find("callback_flow=%s", secondary_call)
    if not 0 <= primary_call < secondary_call < primary_summary or \
            "callback_flow" in container:
        fail("secondary PAF analysis alters the conservative primary result")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in container:
            fail("secondary PAF container analysis is not read-only: " + forbidden)
    for semantic in ("allocator", "dispatcher", "event manager",
            "callback manager", "registration"):
        if semantic in container.lower():
            fail("secondary PAF output invents semantics: " + semantic)
    consumer_start = kernel.find(
            "static void zeroCtrlWritePafA989ConsumerStructure(",
            container_start + 1)
    consumer_end = kernel.find(
            "static void zeroCtrlWriteVsh3f568ImplFlow(", consumer_start)
    if consumer_start < 0 or consumer_end < 0:
        fail("PAF A989 downstream consumer capture is missing")
    consumer = kernel[consumer_start:consumer_end]
    for token in ("zeroCtrlVshModuleRangeValid(paf, consumer, sizeof(words))",
            "words[i] = _lw(consumer + i * 4)",
            "zeroCtrlMipsMove(words[0x08 / 4], 23, 4)",
            "zeroCtrlMipsMove(words[0x10 / 4], 22, 8)",
            "zeroCtrlMipsMove(words[0x18 / 4], 21, 6)",
            "zeroCtrlMipsMove(words[0x20 / 4], 20, 9)",
            "zeroCtrlMipsMove(words[0x28 / 4], 19, 7)",
            "zeroCtrlMipsMove(words[0x30 / 4], 18, 5)",
            "(words[0x3C / 4] >> 26) != 3",
            "zeroCtrlMipsGprWriteDestination(words[0x40 / 4])",
            "(words[0x44 / 4] >> 26) != 0x0A",
            "((words[0x44 / 4] >> 21) & 0x1F) != 19",
            "((words[0x44 / 4] >> 16) & 0x1F) != 3",
            "(short)(words[0x44 / 4] & 0xFFFF) != 20",
            "(words[0x48 / 4] >> 26) != 0x0E",
            "((words[0x48 / 4] >> 21) & 0x1F) != 3",
            "((words[0x48 / 4] >> 16) & 0x1F) != 3",
            "(words[0x48 / 4] & 0xFFFF) != 1",
            "(words[0x4C / 4] >> 26) != 0x0B",
            "((words[0x4C / 4] >> 21) & 0x1F) != 18",
            "((words[0x4C / 4] >> 16) & 0x1F) != 4",
            "(words[0x4C / 4] & 0xFFFF) != 1",
            "(words[0x50 / 4] & 0x3F) != 0x25",
            "((words[0x50 / 4] >> 11) & 0x1F) != 4",
            "(words[0x54 / 4] >> 26) != 4",
            "((words[0x54 / 4] >> 21) & 0x1F) != 2",
            "zeroCtrlMipsBranchTarget(consumer + 0x54", "consumer + 0xD0",
            "zeroCtrlMipsMove(words[0x58 / 4], 3, 0)",
            "(words[0x5C / 4] >> 26) != 5",
            "((words[0x5C / 4] >> 21) & 0x1F) != 4",
            "zeroCtrlMipsBranchTarget(consumer + 0x5C", "consumer + 0xD4",
            "words[0x60 / 4] != 0x8FBF0020",
            "(words[0x64 / 4] >> 26) != 4",
            "((words[0x64 / 4] >> 21) & 0x1F) != 20",
            "zeroCtrlMipsBranchTarget(consumer + 0x64",
            "words[0x68 / 4] != 0x24040028",
            "words[0x70 / 4] != 0",
            "zeroCtrlMipsMove(words[0x74 / 4], 17, 2)",
            "zeroCtrlMipsMove(words[0x7C / 4], 4, 2)",
            "(words[0x80 / 4] >> 26) != 4",
            "((words[0x80 / 4] >> 21) & 0x1F) != 2",
            "zeroCtrlMipsBranchTarget(consumer + 0x80",
            "zeroCtrlMipsMove(words[0x84 / 4], 3, 0)",
            "words[0x88 / 4] != 0xAC520008",
            "zeroCtrlMipsMove(words[0x8C / 4], 5, 16)",
            "words[0x90 / 4] != 0xAE150004",
            "words[0x94 / 4] != 0xAE130008",
            "words[0x98 / 4] != 0xAE16000C",
            "words[0x9C / 4] != 0xAE140014",
            "words[0xA4 / 4] != 0xAE000018",
            "(words[0xA8 / 4] >> 26) != 0x0F",
            "((words[0xA8 / 4] >> 21) & 0x1F) != 0",
            "((words[0xA8 / 4] >> 16) & 0x1F) != 2",
            "(words[0xAC / 4] >> 26) != 0x23",
            "((words[0xAC / 4] >> 21) & 0x1F) != 2",
            "((words[0xAC / 4] >> 16) & 0x1F) != 4",
            "(words[0xB0 / 4] & 0x3F) != 0",
            "((words[0xB0 / 4] >> 21) & 0x1F) != 0",
            "((words[0xB0 / 4] >> 16) & 0x1F) != 23",
            "((words[0xB0 / 4] >> 11) & 0x1F) != 3",
            "((words[0xB0 / 4] >> 6) & 0x1F) != 3",
            "zeroCtrlMipsMove(words[0xB4 / 4], 5, 17)",
            "(words[0xBC / 4] & 0x3F) != 0x21",
            "((words[0xBC / 4] >> 21) & 0x1F) != 4",
            "((words[0xBC / 4] >> 16) & 0x1F) != 3",
            "((words[0xBC / 4] >> 11) & 0x1F) != 4",
            "zeroCtrlMipsMove(words[0xC4 / 4], 4, 23)",
            "zeroCtrlMipsMove(words[0xC8 / 4], 3, 0)",
            "(words[0xCC / 4] & 0x3F) != 0x0B",
            "zeroCtrlMipsMove(words[0xF4 / 4], 2, 3)",
            "words[0xF8 / 4] != 0x03E00008",
            "words[0xFC / 4] != 0x27BD0030",
            "constructed[0] == 0 || constructed[1] == 0",
            "[paf-a989-consumer-structure] validation=1",
            "container_saved_reg=21", "first_call_off=0x3C",
            "first_call_container_arg_reg=6", "a2_source=inner_container",
            "field_off=0x00 store_off=0x88 source=constructed_0",
            "field_off=0x04 store_off=0x90 source=inner_container",
            "field_off=0x08 store_off=0x94 source=minus_one",
            "field_off=0x0C store_off=0x98 source=minus_one",
            "field_off=0x14 store_off=0x9C source=constructed_1",
            "field_off=0x18 store_off=0xA4 source=zero", "delay_slot_of=0xA0",
            "[paf-a989-consumer-known-branch] off=0x5C outcome=NOT_TAKEN",
            "[paf-a989-consumer-known-branch] off=0x64 outcome=NOT_TAKEN",
            "source=caller_known_values",
            "call_offsets[5]", "0x3C, 0x6C, 0xA0, 0xB8, 0xC0",
            "zeroCtrlMipsJumpTarget(", "consumer + call_offsets[i]",
            "zeroCtrlModuleContainingSegment(paf, call_targets[i]",
            "remaining > 0x100 ? 0x100", "map_size &= ~3U",
            "zeroCtrlVshModuleRangeValid(paf,", "call_targets[i], map_size",
            "call_targets[i] >= paf->text_addr &&",
            "call_targets[i] - paf->text_addr < paf->text_size",
            "[paf-a989-consumer-call]", "container_direct_arg=%u",
            "[paf-a989-consumer-call-map]", "row < map_size",
            "remaining > (i == 0 ? 0x80 : 0x100)",
            "(i == 0 ? 0x80 : 0x100)", "[paf-a989-constructed-map]",
            "mapped[j] = _lw(constructed[i] + row + j * 4)",
            "slot = ((words[0xA8 / 4] & 0xFFFF) << 16) +",
            "(int)(short)(words[0xAC / 4] & 0xFFFF)",
            "zeroCtrlModuleContainingSegment(paf, slot",
            "zeroCtrlVshModuleRangeValid(paf, slot, 4)",
            "[paf-a989-consumer-slot]", "value=0x%08X"):
        if token not in consumer:
            fail("PAF A989 downstream consumer capture lacks " + token)
    consumer_guard = consumer.find("if (!zeroCtrlMipsMove(words[0x08 / 4]")
    entry_liveness = consumer.find("for (i = 0; i < 0x3C / 4; i++)")
    validated_consumer = consumer.find(
            "[paf-a989-consumer-structure] validation=1")
    if not 0 <= consumer_guard < entry_liveness < validated_consumer:
        fail("consumer provenance/shape is not validated before conclusions")
    exact_branch_dataflow = consumer.find("(words[0x44 / 4] >> 26) != 0x0A")
    exact_5c = consumer.find("(words[0x5C / 4] >> 26) != 5", exact_branch_dataflow)
    exact_64 = consumer.find("(words[0x64 / 4] >> 26) != 4", exact_5c)
    branch_output_5c = consumer.find(
            "[paf-a989-consumer-known-branch] off=0x5C", exact_64)
    branch_output_64 = consumer.find(
            "[paf-a989-consumer-known-branch] off=0x64", branch_output_5c)
    if not 0 <= exact_branch_dataflow < exact_5c < exact_64 < \
            validated_consumer < branch_output_5c < branch_output_64:
        fail("known consumer branch output precedes exact dataflow validation")
    exact_a8 = consumer.find("((words[0xA8 / 4] >> 16) & 0x1F) != 2")
    exact_ac = consumer.find("((words[0xAC / 4] >> 16) & 0x1F) != 4", exact_a8)
    exact_b0 = consumer.find("((words[0xB0 / 4] >> 11) & 0x1F) != 3", exact_ac)
    exact_bc = consumer.find("(words[0xBC / 4] & 0x3F) != 0x21", exact_b0)
    if not 0 <= exact_a8 < exact_ac < exact_b0 < exact_bc < validated_consumer:
        fail("consumer tail register dataflow is not proven before validation")
    if "((words[0xAC / 4] >> 21) & 0x1F) !=\n                ((words[0xA8 / 4] >> 16) & 0x1F)" in consumer:
        fail("consumer slot still relies on generic LUI/LW base equality")
    for mistaken in ("(words[0x80 / 4] >> 26) != 0x2B",
            "zeroCtrlMipsMove(words[0x84 / 4], 5, 16)",
            "words[0x88 / 4] != 0xAE150004"):
        if mistaken in consumer:
            fail("consumer validator retains mistaken outer-block offset: " + mistaken)
    if "off=0x54 outcome=" in consumer or "off=0x80 outcome=" in consumer:
        fail("consumer validator claims a call-return-dependent branch outcome")
    target_segment = consumer.find(
            "zeroCtrlModuleContainingSegment(paf, call_targets[i]")
    target_range = consumer.find("call_targets[i], map_size", target_segment)
    target_read = consumer.find("_lw(call_targets[i]", target_range)
    if not 0 <= target_segment < target_range < target_read:
        fail("consumer call map reads before segment/full-range validation")
    constructed_segment = consumer.find(
            "zeroCtrlModuleContainingSegment(paf, constructed[i]")
    constructed_cap = consumer.find(
            "remaining > (i == 0 ? 0x80 : 0x100)", constructed_segment)
    constructed_range = consumer.find("constructed[i], map_size", constructed_cap)
    constructed_read = consumer.find("_lw(constructed[i]", constructed_range)
    if not 0 <= constructed_segment < constructed_cap < constructed_range < \
            constructed_read or "(i == 0 ? 0x80 : 0x100)" not in consumer:
        fail("constructed-address map lacks segment/range/per-address cap ordering")
    slot_reconstruct = consumer.find(
            "slot = ((words[0xA8 / 4] & 0xFFFF) << 16) +")
    slot_segment_check = consumer.find(
            "zeroCtrlModuleContainingSegment(paf, slot", slot_reconstruct)
    slot_range = consumer.find(
            "zeroCtrlVshModuleRangeValid(paf, slot, 4)", slot_segment_check)
    slot_read = consumer.find("_lw(slot)", slot_range)
    if not 0 <= slot_reconstruct < slot_segment_check < slot_range < slot_read:
        fail("consumer slot is read before signed reconstruction/four-byte validation")
    if "field_off=0x10" in consumer:
        fail("consumer capture invents an outer-block +0x10 value")
    if "zeroCtrlWritePafA989ConsumerStructure(paf, consumer_target, constructed);" \
            not in container:
        fail("validated container does not feed the downstream capture")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in consumer:
            fail("PAF A989 consumer capture is not read-only: " + forbidden)
    for semantic in ("allocator", "validator", "registrar", "registration",
            "dispatcher", "event manager", "callback manager", "factory",
            "constructor", "vtable", "handler"):
        if semantic in consumer.lower():
            fail("PAF A989 consumer output invents semantics: " + semantic)
    constructed_flow_start = kernel.find(
            "static void zeroCtrlWritePafA989ConstructedFlows(",
            consumer_start + 1)
    constructed_flow_end = kernel.find(
            "static int zeroCtrlPafA989ValidateCodeRange(", constructed_flow_start)
    if constructed_flow_start < 0 or constructed_flow_end < 0:
        fail("constructed-address structural flow analysis is missing")
    constructed_flow = kernel[constructed_flow_start:constructed_flow_end]
    for token in ("constructed[1]", "remaining < 0xBC",
            "zeroCtrlVshModuleRangeValid(paf, constructed[1], 0xBC)",
            "_lw(constructed[1]) == 0x27BDFFF0",
            "_lw(constructed[1] + 4) == 0xAFBF0008",
            "_lw(constructed[1] + 8) == 0xAFB00000",
            "zeroCtrlMipsMove(_lw(constructed[1] + 0x0C), 16, 5)",
            "load = _lw(constructed[1] + 0x40)",
            "(short)(load & 0xFFFF) == 12",
            "constructed[1] + 0xB4",
            "jalr_delay = _lw(constructed[1] + 0xB8)",
            "(short)(jalr_delay & 0xFFFF) == 4",
            "[paf-a989-constructed1-indirect] validation=1",
            "base_arg_reg=5 target_field_off=0x0C",
            "arg0_field_off=0x04 jalr_off=0xB4",
            "[paf-a989-callback-adapter] validation=1",
            "adapter_off=0x34658 base_arg=a1 callback_field=0x0C",
            "[paf-a989-constructed0-write] validation=1",
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)",
            "typedef struct", "ZeroCtrlOuterProvenance",
            "unsigned int kind;", "unsigned int id;",
            "OUTER_PROV_UNKNOWN", "OUTER_PROV_BASE",
            "OUTER_PROV_PLUS04", "OUTER_PROV_PLUS14",
            "prefix_floor = offset > 0x80 ? offset - 0x80 : 0",
            "prefix_start = prefix_floor",
            "boundary_scan = prefix_floor >= 4 ? prefix_floor - 4 : 0",
            "prefix_start = boundary_scan + 8",
            "if (prefix_start > offset) continue",
            "for (reg = 1; reg < 32; reg++)",
            "provenance[reg].id = next_opaque_id++",
            "for (look = prefix_start; look <= offset + 0x80",
            "if (look == offset)",
            "provenance[base].kind != OUTER_PROV_BASE",
            "candidate_outer_id = provenance[base].id",
            "provenance[target].kind = OUTER_PROV_PLUS14",
            "provenance[target].id = candidate_outer_id",
            "provenance[rd] = provenance[rs]",
            "provenance[rd] = provenance[rt]",
            "provenance[rt] = provenance[rs]",
            "provenance[delay_rd] = provenance[delay_rs]",
            "provenance[delay_rd] = provenance[delay_rt]",
            "provenance[delay_rt] = provenance[delay_rs]",
            "provenance[delay_rs].kind == OUTER_PROV_BASE",
            "OUTER_PROV_PLUS04 : OUTER_PROV_PLUS14",
            "provenance[delay_rt].id = provenance[delay_rs].id",
            "provenance[rs].kind == OUTER_PROV_BASE",
            "provenance[rt].id = provenance[rs].id",
            "provenance[destination].kind = OUTER_PROV_UNKNOWN",
            "provenance[delay_destination].kind = OUTER_PROV_UNKNOWN",
            "unsigned int delay_supported = 1",
            "if (!delay_supported)",
            "JALR consumes rs before its architectural delay slot",
            "a1 observes the delay slot; the captured target does not",
            "target_value_before_delay = provenance[rs]",
            "a1_value_after_delay = provenance[5]",
            "target_value_before_delay.kind != OUTER_PROV_PLUS14",
            "target_value_before_delay.id != candidate_outer_id",
            "a1_value_after_delay.kind != OUTER_PROV_PLUS04",
            "a1_value_after_delay.id != candidate_outer_id",
            "exact_header_link_proven = 0",
            "exact_header_link_proven ? \"PARTIALLY_LINKED\" : \"UNKNOWN\"",
            "[paf-a989-outer14-exact-check]",
            "target_kind=%s target_id=%u", "a1_kind=%s a1_id=%u",
            'terminal_result = "MATCH"', 'terminal_result = "DIFFERENT_BASE"',
            'terminal_result = "A1_UNKNOWN"',
            'terminal_result = "CONTROL_FLOW"',
            'terminal_result = "OVERWRITTEN"',
            "[paf-a989-outer14-a1-origin]",
            "a1_origin_reported < 8",
            "reported < 16", "if (matched)",
            "[paf-a989-exact-dispatch]", "same_outer=1",
            "[paf-a989-exact-dispatch-function]",
            "STACK_FRAME_AND_SAVED_RA", "offset - search <= 0x100",
            "[paf-a989-exact-dispatch-caller]", "caller_reported < 16",
            "[paf-a989-exact-dispatch-arg]",
            "[paf-a989-root-slot]", "root_slot - paf->segmentaddr[root_segment]",
            "[paf-a989-exact-dispatch-root]",
            "[paf-a989-dispatch-chain] validation=1",
            "exact_dispatches && exact_same_outer && adapter_valid",
            "if (exact_same_outer)",
            "[paf-a989-outer14-dispatch-shape] validation=1"):
        if token not in constructed_flow:
            fail("constructed/OUTER+0x14 symbolic search lacks " + token)
    c1_range = constructed_flow.find(
            "zeroCtrlVshModuleRangeValid(paf, constructed[1], 0xBC)")
    c1_read = constructed_flow.find("_lw(constructed[1]", c1_range)
    outer_text_range = constructed_flow.find(
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)")
    outer_scan_read = constructed_flow.find("_lw(paf->text_addr + offset)",
            outer_text_range)
    if not 0 <= c1_range < c1_read < outer_text_range < outer_scan_read:
        fail("constructed/OUTER+0x14 analysis reads before range validation")
    if "unsigned char source[32]" in constructed_flow or \
            "if (source[5])" in constructed_flow:
        fail("exact OUTER dispatch still uses boolean source[5] provenance")
    exact_gate = constructed_flow.find("if (matched)", outer_scan_read)
    origin_scan = constructed_flow.find("while (back > back_start)", exact_gate)
    exact_output = constructed_flow.find("[paf-a989-exact-dispatch]", origin_scan)
    chain_gate = constructed_flow.find(
            "exact_dispatches && exact_same_outer && adapter_valid", exact_output)
    if not 0 <= exact_gate < origin_scan < exact_output < chain_gate:
        fail("exact dispatch origin/chain work is not gated by SAME_OUTER")
    if "exact_dispatches && adapter_valid && closure" in constructed_flow or \
            "if (closure)" in constructed_flow:
        fail("broad closure still controls exact dispatch decisions")
    prefix_replay = constructed_flow.find("for (look = prefix_start",
            outer_scan_read)
    anchor = constructed_flow.find("if (look == offset)", prefix_replay)
    parent_id = constructed_flow.find(
            "candidate_outer_id = provenance[base].id", anchor)
    target_snapshot = constructed_flow.find(
            "target_value_before_delay = provenance[rs]", parent_id)
    unrelated_gate = constructed_flow.find(
            "target_value_before_delay.id != candidate_outer_id",
            target_snapshot)
    delay_read = constructed_flow.find(
            "delay = _lw(paf->text_addr + look + 4)", unrelated_gate)
    delay_apply = constructed_flow.find(
            "provenance[delay_rt].id = provenance[delay_rs].id", delay_read)
    a1_snapshot = constructed_flow.find(
            "a1_value_after_delay = provenance[5]", delay_apply)
    id_compare = constructed_flow.find(
            "a1_value_after_delay.id != candidate_outer_id", a1_snapshot)
    if not 0 <= prefix_replay < anchor < parent_id < target_snapshot < \
            unrelated_gate < delay_read < delay_apply < a1_snapshot < \
            id_compare < exact_gate:
        fail("prefix replay or JALR target/a1 timing is not fail-closed")
    if constructed_flow.find("target_value_before_delay = provenance[rs]",
            delay_read) != -1:
        fail("current JALR target provenance is reassigned after its delay slot")
    if "candidate_id = offset / 4 + 1" in constructed_flow:
        fail("candidate identity still comes from its instruction offset")
    fresh_load = constructed_flow.find(
            "provenance[rt].id = next_opaque_id++", prefix_replay)
    if fresh_load < 0:
        fail("ordinary LW results do not receive fresh opaque identities")
    candidate_count = constructed_flow.find("candidates++;", delay_read)
    if not unrelated_gate < delay_read < candidate_count:
        fail("unrelated JALR can enter outer14 candidate accounting")
    weak_header = re.search(
            r'definition_opcode == 0x23[\s\S]{0,240}'
            r'definition_rs >= 4[\s\S]{0,160}HEADER_PLUS_04',
            constructed_flow)
    if weak_header:
        fail("LW +4 from an entry argument is treated as proven A989 header")
    root_gate = constructed_flow.find(
            'exact_header_link_proven ? "PARTIALLY_LINKED" : "UNKNOWN"',
            exact_output)
    if root_gate < 0:
        fail("root-link status lacks an explicit independent header proof")
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL", "MAKE_JUMP",
            "REDIRECT_FUNCTION", "hook_import"):
        if forbidden in constructed_flow:
            fail("exact OUTER dispatch analysis is not read-only: " + forbidden)
    # The longest exact-dispatch format plus maximal substituted fields remains
    # below the fixed 256-byte local diagnostics line buffer.
    exact_formats = re.findall(r'"(\[paf-a989-(?:outer14-exact-check|outer14-a1-origin|exact-dispatch)[^"\n]*)"',
            constructed_flow)
    if not exact_formats or any(len(fmt) + 96 >= 256 for fmt in exact_formats):
        fail("exact-dispatch diagnostic format exceeds line-buffer allowance")
    c0_frame = constructed_flow.find(
            "_lw(constructed[0]) == 0x27BDFFF0")
    c0_save_s1 = constructed_flow.find(
            "_lw(constructed[0] + 0x04) == 0xAFB10004", c0_frame)
    c0_base = constructed_flow.find(
            "zeroCtrlMipsMove(_lw(constructed[0] + 0x08), 17, 4)")
    c0_arg = constructed_flow.find(
            "_lw(constructed[0] + 0x0C) == 0x240401D8", c0_base)
    c0_save_ra = constructed_flow.find(
            "_lw(constructed[0] + 0x10) == 0xAFBF0008", c0_arg)
    c0_first_call = constructed_flow.find(
            "(first_call_word >> 26) == 3", c0_save_ra)
    c0_first_target = constructed_flow.find(
            "zeroCtrlModuleContainingSegment(paf, first_call_target",
            c0_first_call)
    c0_save_s0 = constructed_flow.find(
            "_lw(constructed[0] + 0x18) == 0xAFB00000", c0_first_target)
    c0_return = constructed_flow.find(
            "zeroCtrlMipsMove(_lw(constructed[0] + 0x1C), 16, 2)", c0_save_s0)
    c0_load_a1 = constructed_flow.find(
            "_lw(constructed[0] + 0x20) == 0x8E250008", c0_return)
    c0_second_call = constructed_flow.find(
            "(second_call_word >> 26) == 3", c0_load_a1)
    c0_second_target = constructed_flow.find(
            "zeroCtrlModuleContainingSegment(paf, second_call_target",
            c0_second_call)
    c0_delay = constructed_flow.find(
            "zeroCtrlMipsMove(_lw(constructed[0] + 0x28), 4, 2)",
            c0_second_target)
    c0_store = constructed_flow.find(
            "_lw(constructed[0] + 0x2C) == 0xAE300004", c0_delay)
    c0_output = constructed_flow.find(
            "[paf-a989-constructed0-write] validation=1", c0_store)
    if not 0 <= c0_frame < c0_save_s1 < c0_base < c0_arg < c0_save_ra < \
            c0_first_call < c0_first_target < c0_save_s0 < c0_return < c0_load_a1 < \
            c0_second_call < c0_second_target < c0_delay < c0_store < c0_output:
        fail("constructed_0 write lacks exact local liveness proof")
    generic_shape = constructed_flow.find(
            "[paf-a989-outer14-dispatch-shape] validation=1")
    conditional_identity = constructed_flow.find("if_base_is_a989_outer=1",
            generic_shape)
    if not 0 <= generic_shape < conditional_identity or \
            "outer14-exact-chain] validation=1" in constructed_flow:
        fail("generic OUTER+0x14 shape overstates exact A989 object identity")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in constructed_flow:
            fail("constructed/OUTER+0x14 analysis is not read-only: " + forbidden)
    nearby_apply_start = kernel.find(
            "static int zeroCtrlPafA989ApplyNearbyInstruction(")
    nearby_apply_end = kernel.find(
            "static int zeroCtrlModuleContainingSegment(", nearby_apply_start)
    nearby_start = kernel.find(
            "static void zeroCtrlWritePafA989NearbyFlows(SceModule2 *paf) {",
            constructed_flow_start)
    nearby_end = kernel.find(
            "static int zeroCtrlPafA989ValidateCodeRange(", nearby_start)
    if min(nearby_apply_start, nearby_apply_end, nearby_start, nearby_end) < 0:
        fail("targeted A989 nearby-function provenance analysis is missing")
    nearby_apply = kernel[nearby_apply_start:nearby_apply_end]
    nearby = kernel[nearby_start:nearby_end]
    for token in ("ZERO_PAF_NEARBY_UNKNOWN", "ZERO_PAF_NEARBY_ENTRY_ARG",
            "ZERO_PAF_NEARBY_COPY_ENTRY_ARG", "ZERO_PAF_NEARBY_LW_ENTRY_ARG",
            "ZERO_PAF_NEARBY_LW_SAVED_ARG",
            "zeroCtrlMipsGprWriteDestination(word)",
            "if (destination < 0) return 0",
            "zeroCtrlMipsMove(word, rd, rs)",
            "opcode == 9 && (short)(word & 0xFFFF) == 0",
            "opcode == 0x23", "source[destination].origin = ZERO_PAF_NEARBY_UNKNOWN"):
        if token not in nearby_apply:
            fail("nearby provenance transfer is not conservative: " + token)
    for token in ("0xCFA38, 0xCFB30, 0xCFBF4", "index < 3",
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)",
            "candidate_off > paf->text_size - 4",
            "zeroCtrlVshModuleRangeValid(paf, candidate, 4)",
            "search_start = candidate_off > 0x100",
            "(prologue >> 26) != 9", "(short)(prologue & 0xFFFF) >= 0",
            "save <= entry_off + 0x20", "((save_word >> 16) & 0x1F) == 31",
            "_lw(paf->text_addr + entry_off - 8) == 0x03E00008",
            "_lw(paf->text_addr + entry_off - 4)",
            "previous_jr_ra = 1",
            "caller_opcode == 2 || caller_opcode == 3",
            "zeroCtrlMipsJumpTarget(paf->text_addr + cursor",
            "if (caller_opcode == 3)", "direct_jal_callers++",
            "direct_j_refs++",
            "candidate_off - entry_off + 4",
            "[paf-a989-nearby-function]", "entry_off=UNKNOWN status=UNKNOWN",
            "entry_off=0x%X status=VALID entry_evidence=%s",
            "PREVIOUS_JR_RA_AND_DIRECT_JAL", "PREVIOUS_JR_RA", "DIRECT_JAL",
            "DIRECT_J_ONLY", "PROLOGUE_ONLY", "NO_BOUNDARY",
            "INVALID_CANDIDATE",
            "strong_entry = structural_entry &&",
            "previous_jr_ra || direct_jal_callers != 0",
            "if (!strong_entry)", "caller_reported < 16",
            "[paf-a989-nearby-caller]", "kind=%s",
            "source[cursor].origin = ZERO_PAF_NEARBY_ENTRY_ARG",
            "opcode == 1 || (opcode >= 4 && opcode <= 7)",
            "opcode == 0 && function == 9", "((word >> 11) & 0x1F) != 31",
            "zeroCtrlPafA989ApplyNearbyInstruction(delay, source)",
            "for (reg = 2; reg <= 15; reg++)",
            "source[24].origin = ZERO_PAF_NEARBY_UNKNOWN",
            "source[25].origin = ZERO_PAF_NEARBY_UNKNOWN",
            "saved_mask & (1U << (reg - 16))",
            "zeroCtrlPafA989ApplyNearbyInstruction(word, source)",
            "if (cursor == candidate_off)", "ENTRY_A0", "ENTRY_A1",
            "ENTRY_A2", "ENTRY_A3", "COPY_OF_ENTRY_ARG",
            "LW_FROM_ENTRY_ARG", "LW_FROM_SAVED_ARG",
            "cursor != candidate_off ||",
            "source[base].origin == ZERO_PAF_NEARBY_UNKNOWN",
            "source[base].entry_reg = 0", "source[base].disp = 0",
            "[paf-a989-nearby-base-flow]", "origin=%s source_reg=%u disp=%d"):
        if token not in nearby:
            fail("targeted A989 nearby provenance lacks " + token)
    nearby_range = nearby.find(
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)")
    nearby_first_read = nearby.find("_lw(", nearby_range)
    nearby_local_range = nearby.find(
            "candidate_off - entry_off + 4", nearby_first_read)
    nearby_valid_output = nearby.find("entry_off=0x%X status=VALID",
            nearby_local_range)
    nearby_strong_gate = nearby.find(
            "strong_entry = structural_entry &&", nearby_local_range)
    nearby_jal_condition = nearby.find(
            "previous_jr_ra || direct_jal_callers != 0", nearby_strong_gate)
    nearby_weak_reject = nearby.find("if (!strong_entry)", nearby_jal_condition)
    nearby_weak_continue = nearby.find("continue;", nearby_weak_reject)
    nearby_arg_init = nearby.find(
            "source[cursor].origin = ZERO_PAF_NEARBY_ENTRY_ARG",
            nearby_valid_output)
    nearby_trace = nearby.find("for (cursor = entry_off; cursor < candidate_off",
            nearby_arg_init)
    nearby_delay = nearby.find(
            "zeroCtrlPafA989ApplyNearbyInstruction(delay, source)", nearby_trace)
    nearby_call_clear = nearby.find(
            "for (reg = 2; reg <= 15; reg++)", nearby_delay)
    nearby_saved_guard = nearby.find(
            "saved_mask & (1U << (reg - 16))", nearby_call_clear)
    nearby_result = nearby.find("[paf-a989-nearby-base-flow]",
            nearby_saved_guard)
    if not 0 <= nearby_range < nearby_first_read < nearby_local_range < \
            nearby_strong_gate < nearby_jal_condition < nearby_weak_reject < \
            nearby_weak_continue < nearby_valid_output < nearby_arg_init < \
            nearby_trace < nearby_delay < \
            nearby_call_clear < nearby_saved_guard < nearby_result:
        fail("nearby function provenance reads or reports before validation")
    if nearby.count("0xCFA38") != 1 or nearby.count("0xCFB30") != 1 or \
            nearby.count("0xCFBF4") != 1 or "outer14-exact-chain" in nearby:
        fail("nearby analysis broadens candidates or overstates A989 identity")
    if "entry_valid = 1" in nearby or \
            "direct_j_refs != 0);" in nearby[nearby_strong_gate:nearby_weak_reject]:
        fail("plain J reference can still authorize entry-argument provenance")
    if "look <= offset + 0x80" not in constructed_flow:
        fail("symbolic OUTER+0x14 search is not bounded to 32 instructions")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in nearby_apply or forbidden in nearby:
            fail("nearby provenance analysis is not read-only: " + forbidden)
    call_clear_start = kernel.find(
            "static void zeroCtrlPafA989ClearCallArgSource(")
    call_apply_start = kernel.find(
            "static int zeroCtrlPafA989ApplyCallArgInstruction(")
    call_apply_end = kernel.find(
            "static int zeroCtrlModuleContainingSegment(", call_apply_start)
    call_args_start = kernel.find(
            "static void zeroCtrlWritePafA989NearbyCallArgs(SceModule2 *paf) {",
            nearby_start)
    unknown_call_start = kernel.find(
            "static void zeroCtrlWritePafA989UnknownCallArgs(", nearby_start)
    call_args_end = kernel.find(
            "static int zeroCtrlPafA989ValidateCodeRange(", call_args_start)
    if min(call_clear_start, call_apply_start, call_apply_end, unknown_call_start,
            call_args_start, call_args_end) < 0:
        fail("four-site A989 caller argument capture is missing")
    call_clear = kernel[call_clear_start:call_apply_start]
    call_apply = kernel[call_apply_start:call_apply_end]
    unknown_call = kernel[unknown_call_start:call_args_start]
    call_args = kernel[call_args_start:call_args_end]
    for token in ("source->kind = ZERO_PAF_CALL_ARG_UNKNOWN",
            "source->parent_reg = 0", "source->disp = 0", "source->value = 0"):
        if token not in call_clear:
            fail("call argument UNKNOWN clearing omits " + token)
    for token in ("ZERO_PAF_CALL_ARG_UNKNOWN", "ZERO_PAF_CALL_ARG_COPY",
            "ZERO_PAF_CALL_ARG_LW", "ZERO_PAF_CALL_ARG_ADDIU",
            "ZERO_PAF_CALL_ARG_CONSTANT", "zeroCtrlMipsGprWriteDestination(word)",
            "if (destination < 0) return 0", "zeroCtrlMipsMove(word, rd, rs)",
            "opcode == 9", "opcode == 0x0F", "opcode == 0x0D",
            "opcode == 0x23",
            "zeroCtrlPafA989ClearCallArgSource(&source[destination])"):
        if token not in call_apply:
            fail("four-site call argument transfer lacks " + token)
    for token in ("call_validation=0", "flow_status=UNKNOWN",
            "a0_kind=UNKNOWN a0_parent_reg=0 a0_disp=0 a0_value=0x00000000",
            "a1_kind=UNKNOWN a1_parent_reg=0 a1_disp=0 a1_value=0x00000000",
            "a2_kind=UNKNOWN a2_parent_reg=0 a2_disp=0 a2_value=0x00000000",
            "a3_kind=UNKNOWN a3_parent_reg=0 a3_disp=0 a3_value=0x00000000"):
        if token not in unknown_call:
            fail("invalid call record can retain UNKNOWN metadata: " + token)
    for token in ("0xCFC64, 0x345B8, 0x34884, 0x344A4",
            "0xCFADC, 0xCF9A8, 0xCFB70, 0xCFB70", "index < 4",
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)",
            "zeroCtrlVshModuleRangeValid(paf, call, 8)",
            "zeroCtrlVshModuleRangeValid(paf, target, 4)",
            "(word >> 26) != 3", "zeroCtrlMipsJumpTarget(call, word) != target",
            "zeroCtrlWritePafA989UnknownCallArgs(call_off, target_off)",
            "start_off = call_off > 0x40 ? call_off - 0x40 : 0",
            "end_off = call_off + 0x24", "map_size = (end_off - start_off) & ~3U",
            "zeroCtrlVshModuleRangeValid(paf,\n                    paf->text_addr + start_off, map_size)",
            "[paf-a989-nearby-caller-map]", "row < map_size",
            "opcode == 1 || (opcode >= 4 && opcode <= 7)",
            "opcode == 0 && function == 9", "flow_valid = 0",
            "zeroCtrlPafA989ApplyCallArgInstruction(delay, source)",
            "for (reg = 2; reg <= 15; reg++)",
            "zeroCtrlPafA989ClearCallArgSource(&source[reg])",
            "zeroCtrlPafA989ClearCallArgSource(&source[24])",
            "zeroCtrlPafA989ClearCallArgSource(&source[25])",
            "zeroCtrlPafA989ClearCallArgSource(&source[31])",
            "delay = _lw(call + 4)", "if (!flow_valid ||",
            "source[reg].kind == ZERO_PAF_CALL_ARG_UNKNOWN",
            "COPY_OF_SAVED_REG", "COPY_OF_REG", '"LW"', '"ADDIU"',
            '"CONSTANT"', '"UNKNOWN"',
            "[paf-a989-nearby-call-args] call_validation=1",
            "flow_status=%s", 'flow_valid ? "VALID" : "UNKNOWN"',
            "a0_kind=%s", "a1_kind=%s", "a2_kind=%s", "a3_kind=%s",
            "execution=NOT_OBSERVED", "0xCFC44", "0x50",
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr + 0xCFC44",
            "[paf-a989-cfc64-context]"):
        if token not in call_args:
            fail("four-site caller capture lacks " + token)
    call_range = call_args.find("zeroCtrlVshModuleRangeValid(paf, call, 8)")
    call_read = call_args.find("word = _lw(call)", call_range)
    dynamic_target = call_args.find("zeroCtrlMipsJumpTarget(call, word) != target",
            call_read)
    map_range = call_args.find("paf->text_addr + start_off, map_size",
            dynamic_target)
    map_read = call_args.find("mapped[column] = _lw", map_range)
    flow_start = call_args.find("for (cursor = start_off; cursor < call_off",
            map_read)
    delay_read = call_args.find("delay = _lw(call + 4)", flow_start)
    delay_apply = call_args.find(
            "zeroCtrlPafA989ApplyCallArgInstruction(delay, source)", delay_read)
    final_clear = call_args.find(
            "zeroCtrlPafA989ClearCallArgSource(&source[reg])", delay_apply)
    kind_finalize = call_args.find("kind[arg] =", final_clear)
    result = call_args.find(
            "[paf-a989-nearby-call-args] call_validation=1", kind_finalize)
    context_range = call_args.find(
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr + 0xCFC44",
            result)
    context_read = call_args.find("mapped[column] = _lw", context_range)
    if not 0 <= call_range < call_read < dynamic_target < map_range < map_read < \
            flow_start < delay_read < delay_apply < final_clear < kind_finalize < \
            result < context_range < \
            context_read:
        fail("four-site caller capture reads or reports before validation")
    if ".kind = ZERO_PAF_CALL_ARG_UNKNOWN" in call_apply or \
            ".kind = ZERO_PAF_CALL_ARG_UNKNOWN" in call_args:
        fail("call argument UNKNOWN transition bypasses full metadata clearing")
    if call_args.count("0xCFC64") != 1 or call_args.count("0x345B8") != 1 or \
            call_args.count("0x34884") != 1 or call_args.count("0x344A4") != 1 or \
            "outer14-exact-chain" in call_args:
        fail("four-site caller capture broadens scope or asserts object identity")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in call_clear or forbidden in call_apply or \
                forbidden in unknown_call or forbidden in call_args:
            fail("four-site caller capture is not read-only: " + forbidden)
    downstream_start = kernel.find("static void zeroCtrlWritePafA989Downstream(",
            consumer_start + 1)
    downstream_end = kernel.find(
            "static void zeroCtrlWriteVsh3f568ImplFlow(", downstream_start)
    if downstream_start < 0 or downstream_end < 0:
        fail("PAF A989 immediate downstream analysis is missing")
    downstream = kernel[downstream_start:downstream_end]
    for token in ("zeroCtrlPafA989ValidateCodeRange(paf, first_target",
            "sizeof(first)", "first_size != sizeof(first)",
            "(first[0] >> 26) != 1", "((first[0] >> 21) & 0x1F) != 4",
            "zeroCtrlMipsBranchTarget(first_target, first[0])",
            "first_target + 0x1C", "first[1] != 0x24050001", "(first[2] >> 26) != 0x0F",
            "((first[2] >> 16) & 0x1F) != 3",
            "(first[3] >> 26) != 0x23",
            "((first[3] >> 21) & 0x1F) != 3",
            "((first[3] >> 16) & 0x1F) != 2",
            "(first[4] & 0x3F) != 0x2A",
            "((first[4] >> 21) & 0x1F) != 4",
            "((first[4] >> 16) & 0x1F) != 2",
            "zeroCtrlMipsBranchTarget(first_target + 0x14, first[5])",
            "first_target + 0x20",
            "first[8] != 0x03E00008", "zeroCtrlMipsMove(first[9], 2, 5)",
            "body_size=0x28", "a2_read=0 a3_read=0 container_arg_used=0",
            "bound_slot = ((first[2] & 0xFFFF) << 16) +",
            "(int)(short)(first[3] & 0xFFFF)",
            "zeroCtrlModuleContainingSegment(paf, bound_slot",
            "zeroCtrlVshModuleRangeValid(paf, bound_slot, 4)",
            "bound_value = _lw(bound_slot)", "[paf-a989-first-call-bound]",
            "[paf-a989-first-call-static-result]", "execution=NOT_OBSERVED",
            "adjacent = first_target + 0x28", "adjacent < first_target",
            "zeroCtrlPafA989ValidateCodeRange(paf,\n                adjacent, 0x100",
            "adjacent_ra_saved", "indirect_off == 0xFFFFFFFFU",
            "base_source=mem_a1_plus_0", "target_source=base_plus_0",
            "arg0_source=base_plus_4 arg1_source=base",
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)",
            "zeroCtrlMipsJumpTarget(pc, word) == adjacent",
            "caller_reported < 16", "offset >= 0x40",
            "offset + 0x40 <= paf->text_size", "0x80",
            "[paf-a989-adjacent-caller]", "[paf-a989-adjacent-caller-map]",
            "[paf-a989-adjacent-scan] direct_callers=%u",
            "paf->segmentsize[i]", "size > 0x40000 ? 0x40000",
            "zeroCtrlVshModuleRangeValid(paf, start, scan_size)",
            "address - paf->text_addr < paf->text_size",
            "_lw(address) != adjacent", "data_reported < 16",
            "[paf-a989-adjacent-data-ref]",
            "[paf-a989-adjacent-data-scan] matches=%u",
            "low_opcode == 9 || low_opcode == 0x0D",
            "address + (int)(short)(low & 0xFFFF)",
            "address | (low & 0xFFFF)",
            "[paf-a989-adjacent-address-ref]", "LUI_ADDIU", "LUI_ORI",
            "zeroCtrlPafA989ValidateCodeRange(paf, header_target, 8",
            "_lw(header_target) != 0x03E00008",
            "_lw(header_target + 4) != 0xAC850004",
            "[paf-a989-header-link] validation=1", "write_base_arg=4",
            "write_value_arg=5 field_off=4", "header_plus_4=outer_block",
            "zeroCtrlPafA989ValidateCodeRange(paf, global_target, sizeof(link)",
            "link[0] != 0x8C830004", "link[1] != 0xAC850004",
            "link[2] != 0x8C620000", "link[3] != 0xACA20000",
            "link[4] != 0x03E00008", "link[5] != 0xAC650000",
            "[paf-a989-global-link] validation=1", "caller_a0=slot_value",
            "caller_a1=allocation_return", "[paf-a989-static-chain]",
            "evidence=LOADED_CODE_NORMAL_FALLTHROUGH",
            "global_slot_to_header=STRUCTURALLY_LINKED",
            "inner_plus_C_to_vsh589c=STRUCTURALLY_STORED"):
        if token not in downstream:
            fail("PAF A989 immediate downstream analysis lacks " + token)
    first_range = downstream.find(
            "zeroCtrlPafA989ValidateCodeRange(paf, first_target")
    first_read = downstream.find("_lw(first_target", first_range)
    first_bltz_target = downstream.find(
            "zeroCtrlMipsBranchTarget(first_target, first[0])")
    first_bne_target = downstream.find(
            "zeroCtrlMipsBranchTarget(first_target + 0x14, first[5])",
            first_bltz_target)
    body_valid = downstream.find("[paf-a989-first-call-body] validation=1")
    body_size = downstream.find("body_size=0x28", body_valid)
    no_container_use = downstream.find("a2_read=0 a3_read=0 container_arg_used=0",
            body_size)
    if not 0 <= first_range < first_read < first_bltz_target < \
            first_bne_target < body_valid < body_size < no_container_use:
        fail("first-call internal branches are not proven before body conclusion")
    bound_segment = downstream.find(
            "zeroCtrlModuleContainingSegment(paf, bound_slot")
    bound_range = downstream.find(
            "zeroCtrlVshModuleRangeValid(paf, bound_slot, 4)", bound_segment)
    bound_read = downstream.find("_lw(bound_slot)", bound_range)
    if not 0 <= bound_segment < bound_range < bound_read:
        fail("first-call bound is read before four-byte validation")
    adjacent_derive = downstream.find("adjacent = first_target + 0x28")
    adjacent_range = downstream.find(
            "zeroCtrlPafA989ValidateCodeRange(paf,\n                adjacent, 0x100",
            adjacent_derive)
    adjacent_read = downstream.find("_lw(adjacent", adjacent_range)
    if not 0 <= adjacent_derive < adjacent_range < adjacent_read:
        fail("adjacent function is read before derived range validation")
    scan_range = downstream.find(
            "zeroCtrlVshModuleRangeValid(paf, paf->text_addr, paf->text_size)")
    scan_read = downstream.find("_lw(pc)", scan_range)
    if not 0 <= scan_range < scan_read:
        fail("adjacent caller/reference scan reads unvalidated PAF text")
    header_range = downstream.find(
            "zeroCtrlPafA989ValidateCodeRange(paf, header_target, 8")
    header_read = downstream.find("_lw(header_target)", header_range)
    global_range = downstream.find(
            "zeroCtrlPafA989ValidateCodeRange(paf, global_target, sizeof(link)")
    global_read = downstream.find("_lw(global_target", global_range)
    if not 0 <= header_range < header_read < global_range < global_read:
        fail("short link bodies are read before validated ranges")
    if "first_target + 0x28" not in downstream or "0xCF688" in downstream:
        fail("adjacent function is not derived dynamically")
    if "base+0x0C" in downstream and "vsh589c" in downstream.lower():
        fail("constructed-address base+0x0C is mislabeled as VSH callback")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP", "REDIRECT_FUNCTION",
            "zeroCtrlRedir", "Dcache", "Icache", "sceKernelCreateThread",
            "sceKernelStartThread", "request_function()"):
        if forbidden in downstream:
            fail("PAF A989 downstream analysis is not read-only: " + forbidden)
    for semantic in ("allocator", "validator", "registrar", "registered",
            "dispatcher", "event manager", "callback manager", "handler"):
        if semantic in downstream.lower():
            fail("PAF A989 downstream output invents semantics: " + semantic)
    if "[vsh3f568-impl-map]" in vsh3 or "[vsh3f568-use]" in vsh3:
        fail("superseded wrapper/caller output is still automatic")
    for section in (vsh3, inner):
        for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL",
                "MAKE_JUMP", "REDIRECT_FUNCTION", "zeroCtrlRedir",
                "request_function()"):
            if forbidden in section:
                fail("PAF A989 analysis is not strictly read-only: " + forbidden)
    destination_start = kernel.find(
            "static int zeroCtrlMipsGprWriteDestination(")
    destination_end = kernel.find(
            "static void zeroCtrlWriteVsh3f568CallerWindow(",
            destination_start)
    destination_decoder = kernel[destination_start:destination_end]
    sc_destination = "if (opcode == 0x38)\n        return (word >> 16) & 0x1F;"
    for token in (sc_destination,
            "(opcode >= 0x28 && opcode <= 0x2F)",
            "(opcode >= 0x20 && opcode <= 0x26) || opcode == 0x30",
            "return -1;"):
        if token not in destination_decoder:
            fail("conservative GPR destination decoder lacks " + token)
    if destination_decoder.find(sc_destination) > destination_decoder.find(
            "(opcode >= 0x28 && opcode <= 0x2F)") or \
            "opcode <= 0x2F) || opcode == 0x38" in destination_decoder:
        fail("SC is incorrectly classified as a no-destination store")
    if kernel.count("zeroCtrlWriteFunctionalVsh3f568Analysis();") != 1 or \
            "if (!vsh3f568_scan_written && slide_diag.functional_enabled" \
            not in minimal or "slide_diag.minimal_memory_test" not in minimal or \
            "vsh3f568_scan_written = 1;" not in minimal:
        fail("VSH +3F568 analysis is not a functional diagnostic one-shot")
    a989_gate_start = kernel.find(
            "static void zeroCtrlWriteFunctionalVsh3f568Analysis(void) {")
    a989_gate = kernel[a989_gate_start:kernel.find(
            'vsh = sceKernelFindModuleByName("vsh_module")', a989_gate_start)]
    if "!slide_diag.functional_enabled || !slide_diag.minimal_memory_test" \
            not in a989_gate:
        fail("A989 analysis does not require functional minimal diagnostics")
    minimal_gate = kernel[kernel.find("slide_diag.minimal_memory_test ="):
        kernel.find("slide_diag.global_predicate_enabled =")]
    for token in ("model == 0", "devkit == 0x06060110",
            'strcmp(psp1000SlidePlugin, "Enabled") == 0',
            'strcmp(psp1000Diagnostics, "Enabled") == 0'):
        if token not in minimal_gate:
            fail("minimal memory test gate lacks " + token)
    fast_memory_start = kernel.find("static void zeroCtrlWriteFastMemory(")
    fast_memory_end = kernel.find("static void zeroCtrlInstallVsh589CCallTrace(void)",
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
            "[psp1000-functional] startup_58d4_armed=1",
            "[psp1000-functional] startup_58d4_consumed=1",
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
            "zeroCtrlTrigger13F6CHits", "zeroCtrlTrigger14020Hits",
            "sw      $zero, %lo(zeroCtrlTrigger58D4Request)",
            "lw      $t0, %lo(zeroCtrlTrigger58D4OriginalTarget)($t0)",
            "jr      $t0", "jr      $ra", "addiu   $v0, $zero, 1"):
        if token not in trigger_leaf:
            fail("functional 58D4 helper lacks " + token)
    if any(token in trigger_leaf for token in
            ("$k0", "$k1", "$sp", "$gp", "jal ", "jalr")):
        fail("functional 58D4 helper uses reserved/stateful registers or calls")
    request_test = trigger_leaf.find("beqz    $t1, 1f")
    total_increment = trigger_leaf.find("zeroCtrlTrigger13F6CHits")
    request_clear = trigger_leaf.find(
            "sw      $zero, %lo(zeroCtrlTrigger58D4Request)", request_test)
    effective_true = trigger_leaf.find("addiu   $v0, $zero, 1", request_clear)
    natural_label = trigger_leaf.find("1:", effective_true)
    delegated_increment = trigger_leaf.find("zeroCtrlTrigger14020Hits",
            natural_label)
    natural_target = trigger_leaf.find(
            "lw      $t0, %lo(zeroCtrlTrigger58D4OriginalTarget)($t0)",
            natural_label)
    natural_tail = trigger_leaf.find("jr      $t0", natural_target)
    if not 0 <= total_increment < request_test < request_clear < effective_true < \
            natural_label < delegated_increment < natural_target < natural_tail:
        fail("functional 58D4 helper does not consume once or preserve natural tail")
    trace_start = assembly.find("zeroCtrlVsh589CCallTrace:")
    trace_end = assembly.find("zeroCtrlVsh589CCallTraceEnd:", trace_start)
    vsh589c_trace = assembly[trace_start:trace_end]
    trace_tokens = ("addiu   $sp, $sp, -16", "sw      $t0, 0($sp)",
            "sw      $t1, 4($sp)", "zeroCtrlTrigger13F6CHits",
            "lw      $t1, %lo(zeroCtrlTrigger58D4Request)($t0)",
            "beqz    $t1, 3f", "zeroCtrlTrigger14020Hits",
            "lw      $t1, 4($sp)", "lw      $t0, 0($sp)",
            "addiu   $sp, $sp, 16", "zeroCtrlVsh589CCallTraceTail:",
            "j       0", "nop")
    if trace_start < 0 or any(token not in vsh589c_trace for token in trace_tokens):
        fail("VSH +58AC trace helper lacks exact transparent grammar")
    for forbidden in ("sw      $zero, %lo(zeroCtrlTrigger58D4Request)",
            "CompatMode", "jal ", "jalr", "syscall", "sceIo", "Alloc", "malloc"):
        if forbidden in vsh589c_trace:
            fail("VSH +58AC trace helper mutates functional state or calls code")
    record_start = kernel.find("void zeroCtrlRecordVshSlideTarget(")
    record_end = kernel.find("int (*msIoOpen)", record_start)
    record = kernel[record_start:record_end]
    for token in ("stub_58d4_end - stub_58d4",
            "evidence->request_addr", "evidence->original_target_addr",
            "evidence->functional_mode_addr",
            "(evidence->request_addr & 3) == 0",
            "zeroCtrlVshModuleRangeValid(helper,\n                                evidence->request_addr, 4)",
            "_sw(0, request_evidence->request_addr)",
            "!zeroCtrlVshModuleRangeValid(helper, counters[1], 4)",
            "!zeroCtrlVshModuleRangeValid(helper, counters[2], 4)",
            "_sw(0, counters[1])", "_sw(0, counters[2])",
            "_sw(request_evidence->original_target",
            "_sw(slide_diag.functional_enabled ? 1 : 0",
            "sceKernelDcacheWritebackInvalidateRange("):
        if token not in record:
            fail("functional 58D4 registration lacks " + token)
    validation_pass = record[record.find("/* Validation pass"):
            record.find("/* Commit pass")]
    if "_sw(" in validation_pass:
        fail("functional 58D4 validation pass performs a partial write")
    commit_guard = record.find("if (all_selected_valid)")
    reused_counter_validation = record.find(
            "!zeroCtrlVshModuleRangeValid(helper, counters[1], 4)")
    reused_validation_guard = record.rfind(
            "if (slide_diag.functional_enabled &&", 0,
            reused_counter_validation)
    original_init = record.find("_sw(request_evidence->original_target",
            commit_guard)
    mode_init = record.find("_sw(slide_diag.functional_enabled ? 1 : 0",
            original_init)
    startup_request_zero = record.find("_sw(0, request_evidence->request_addr)",
            mode_init)
    request_sync = record.find("sceKernelDcacheWritebackInvalidateRange(\n"
            "                            (const void *)request_evidence->request_addr, 4)",
            startup_request_zero)
    counter_init_guard = record.find("if (slide_diag.functional_enabled) {",
            request_sync)
    total_zero = record.find("_sw(0, counters[1])", counter_init_guard)
    delegated_zero = record.find("_sw(0, counters[2])", total_zero)
    total_sync = record.find("(const void *)counters[1], 4", delegated_zero)
    delegated_sync = record.find("(const void *)counters[2], 4", total_sync)
    trigger_commit = record.find("_sw(evidence->replacement_word",
            delegated_sync)
    patch_dcache = record.find("sceKernelDcacheWritebackInvalidateRange(",
            trigger_commit)
    patch_icache = record.find("sceKernelIcacheInvalidateRange(", patch_dcache)
    patch_synced = record.find("evidence->cache_sync = 1", patch_icache)
    armed_record = record.find("functional_request_armed = 1", patch_synced)
    bridge_retry_guard = record.find("if (slide_diag.bridge_registered &&",
            armed_record)
    bridge_retry = record.find("zeroCtrlInstallVshCtrl314A4Bridge();",
            bridge_retry_guard)
    if not 0 <= reused_validation_guard < reused_counter_validation < commit_guard < \
            original_init < mode_init < \
            startup_request_zero < request_sync < counter_init_guard < total_zero < delegated_zero < \
            total_sync < delegated_sync < \
            trigger_commit < patch_dcache < patch_icache < patch_synced < \
            armed_record < bridge_retry_guard < bridge_retry:
        fail("functional 58D4 closed-request/install transaction is out of order")
    counter_init_end = record.find("\n                    }", delegated_sync)
    counter_init = record[counter_init_guard:counter_init_end]
    for token in ("_sw(0, counters[1])", "_sw(0, counters[2])",
            "(const void *)counters[1], 4",
            "(const void *)counters[2], 4"):
        if counter_init.count(token) != 1:
            fail("reused 58D4 counter operation escaped its functional guard: " +
                    token)
    historical_init = record[record.rfind(
            "if (slide_diag.trigger_mode & ZERO_TRIGGER_58D4)", 0,
            original_init):counter_init_guard]
    for token in ("_sw(request_evidence->original_target",
            "_sw(slide_diag.functional_enabled ? 1 : 0",
            "_sw(0, request_evidence->request_addr)"):
        if token not in historical_init:
            fail("historical 58D4 scalar initialization moved under functional guard")
    if record.count("_sw(0, request_evidence->request_addr)") != 1 or \
            "_sw(1, request_evidence->request_addr)" in record:
        fail("functional 58D4 startup request is not initialized only to zero")
    if "&slide_diag.triggers[0]" not in record:
        fail("functional 58D4 pre-arm does not use trigger zero")
    request_alignment = record.find("(evidence->request_addr & 3) == 0")
    request_range = record.find("zeroCtrlVshModuleRangeValid(helper,\n"
            "                                evidence->request_addr, 4)",
            request_alignment)
    trigger_validation = record.find("evidence->validation = 1", request_range)
    if not 0 <= request_alignment < request_range < trigger_validation < \
            commit_guard:
        fail("58D4 request scalar is not aligned/range-validated before use")
    button_start = kernel.find("void zeroCtrlReadButtons(")
    button_end = kernel.find("void zeroCtrlCreateBtnThread(", button_start)
    button = kernel[button_start:button_end]
    for token in ("ZERO_SLIDE_STOPPED", "slideStartBtn",
            "slide_diag.functional_enabled",
            "functional_runtime_request_blocked = 1", "request_ready",
            "zeroCtrlArmPsp1000FunctionalCompatFromHome()",
            "zeroCtrlRequestPsp1000FunctionalOpenFromHome()",
            "zeroCtrlSetSlideState(ZERO_SLIDE_STARTING)"):
        if token not in button:
            fail("functional StartBtn request gating lacks " + token)
    functional_block = button[button.find("if (slide_diag.functional_enabled)"):
            button.find("if (request_ready)")]
    for token in ("slide_diag.bsman.functional_validation &&",
            "slide_diag.bsman.functional_install &&",
            "slide_diag.bsman.functional_cache_sync)",
            "zeroCtrlArmPsp1000FunctionalCompatFromHome();", "else",
            "zeroCtrlRequestPsp1000FunctionalOpenFromHome();"):
        if token not in functional_block:
            fail("functional HOME two-case lifecycle lacks " + token)
    for forbidden in ("psp1000RuntimeRequestTarget",
            "zeroCtrlTrigger58D4(",
            "zeroCtrlSetSlideState(ZERO_SLIDE_STARTING)",
            "trigger->request_addr", "request_evidence->request_addr",
            "_sw(", "sceKernelDcache"):
        if forbidden in functional_block:
            fail("functional HOME arms, executes, or forces Sony flow: " +
                    forbidden)
    if "_sw(1, slide_diag.functional_runtime_request_addr)" in button:
        fail("functional HOME publishes the forbidden direct runtime request")
    home_arm_start = kernel.find(
            "static void zeroCtrlArmPsp1000FunctionalCompatFromHome(void)")
    home_arm_end = kernel.find(
            "static void zeroCtrlRequestPsp1000FunctionalOpenFromHome(void)",
            home_arm_start)
    home_arm = kernel[home_arm_start:home_arm_end]
    for token in ("slide_diag.functional_enabled", "model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "!bsman->functional_validation", "!bsman->functional_install",
            "!bsman->functional_cache_sync",
            'sceKernelFindModuleByName("ZeroVSH_Patcher_User")',
            "!zeroCtrlLoadedModuleMetadataValid(helper)",
            "address[i] == 0", "(address[i] & 3) != 0",
            "!zeroCtrlVshModuleRangeValid(helper, address[i], 4)",
            "mode[0] == 1 && mode[1] == 1 && mode[2] == 1 && mode[3] == 1",
            "mode[0] != 0 || mode[1] != 0 || mode[2] != 0 || mode[3] != 0",
            "for (i = 0; i < 4; i++) {", "_sw(1, address[i])",
            "sceKernelDcacheWritebackInvalidateRange((const void *)address[i], 4)"):
        if token not in home_arm:
            fail("functional HOME compatibility arm lacks " + token)
    address_order = tuple(home_arm.find(token) for token in (
            "address[0] = bsman->bsman_compat_mode_addr",
            "address[1] = bsman->state_zero_15to14_compat_mode_addr",
            "address[2] = bsman->post_vsh_compat_mode_addr",
            "address[3] = bsman->prefix_paf_compat_mode_addr"))
    validation_end = home_arm.find("for (i = 0; i < 4; i++) mode[i] = _lw(address[i])")
    all_one = home_arm.find("mode[0] == 1", validation_end)
    mixed = home_arm.find("mode[0] != 0", all_one)
    first_write = home_arm.find("_sw(1, address[i])")
    if min(address_order) < 0 or address_order != tuple(sorted(address_order)) or \
            not 0 <= validation_end < all_one < mixed < first_write or \
            home_arm.count("_sw(1, address[i])") != 1:
        fail("functional HOME validation/state checks/write ordering regressed")
    for forbidden in ("sceKernelIcache", "zeroCtrlSetSlideState",
            "psp1000RuntimeRequestTarget", "zeroCtrlTrigger58D4", "MAKE_CALL",
            "MAKE_JUMP", "_sw(replacement", "sceIo", "malloc", "Alloc"):
        if forbidden in home_arm:
            fail("functional HOME arm performs forbidden operation " + forbidden)
    home_request_start = home_arm_end
    home_request_end = kernel.find("void zeroCtrlReadButtons(", home_request_start)
    home_request = kernel[home_request_start:home_request_end]
    for token in ("slide_diag.functional_enabled", "model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "bsman->functional_install", "ZERO_TRIGGER_58D4",
            "!trigger->validation", "!trigger->patch_applied",
            "!trigger->cache_sync", "!zeroCtrlLoadedModuleMetadataValid(helper)",
            "trigger->request_addr == 0", "(trigger->request_addr & 3) != 0",
            "zeroCtrlVshModuleRangeValid(helper, trigger->request_addr, 4)",
            "trigger->functional_mode_addr == 0",
            "(trigger->functional_mode_addr & 3) != 0",
            "zeroCtrlVshModuleRangeValid(helper,\n                trigger->functional_mode_addr, 4)",
            "trigger->original_target_addr == 0",
            "(trigger->original_target_addr & 3) != 0",
            "zeroCtrlVshModuleRangeValid(helper,\n                trigger->original_target_addr, 4)",
            "_lw(trigger->functional_mode_addr) != 1",
            "_lw(trigger->request_addr) != 0",
            "slide_diag.functional_trigger_consumed",
            "slide_diag.functional_home_open_pending"):
        if token not in home_request:
            fail("functional HOME first-load validation lacks " + token)
    reject_reasons = (
        ("ZERO_HOME_REJECT_NONE", 0), ("ZERO_HOME_REJECT_PLATFORM", 1),
        ("ZERO_HOME_REJECT_COMPAT_INSTALLED", 2),
        ("ZERO_HOME_REJECT_TRIGGER_MODE", 3),
        ("ZERO_HOME_REJECT_TRIGGER_VALIDATION", 4),
        ("ZERO_HOME_REJECT_TRIGGER_PATCH", 5),
        ("ZERO_HOME_REJECT_TRIGGER_CACHE", 6),
        ("ZERO_HOME_REJECT_HELPER", 7),
        ("ZERO_HOME_REJECT_REQUEST_ADDRESS", 8),
        ("ZERO_HOME_REJECT_MODE_ADDRESS", 9),
        ("ZERO_HOME_REJECT_TARGET_ADDRESS", 10),
        ("ZERO_HOME_REJECT_MODE_VALUE", 11),
        ("ZERO_HOME_REJECT_REQUEST_VALUE", 12),
        ("ZERO_HOME_REJECT_CONSUMED", 13),
        ("ZERO_HOME_REJECT_PENDING", 14),
        ("ZERO_HOME_REJECT_BRIDGE", 15),
        ("ZERO_HOME_REJECT_BRIDGE_BUSY", 16),
    )
    for reason, value in reject_reasons:
        if (reason + " = %d" % value) not in kernel:
            fail("functional HOME reject mapping changed for " + reason)
    for reason, _value in reject_reasons[1:]:
        assignment = ("functional_home_first_load_reject_reason =\n"
                      "                " + reason + ";\n        return;")
        if home_request.count(assignment) != 1:
            fail("functional HOME rejection does not record/return for " + reason)
    attempt = home_request.find("functional_home_first_load_attempts++")
    first_validation = home_request.find("if (!slide_diag.functional_enabled")
    pending_write = home_request.find("functional_home_open_pending = 1")
    request_write = home_request.find("_sw(1, trigger->request_addr)")
    request_dcache = home_request.find(
            "sceKernelDcacheWritebackInvalidateRange(", request_write)
    published = home_request.find("functional_home_first_load_published++",
            request_dcache)
    success_reason = home_request.find(
            "functional_home_first_load_reject_reason = ZERO_HOME_REJECT_NONE",
            published)
    last_validation = home_request.rfind("ZERO_HOME_REJECT_BRIDGE_BUSY", 0,
            pending_write)
    attempted_reset = home_request.find("_sw(0, slide_diag.bridge_scalar[7])")
    reject_reset = home_request.find("_sw(0, slide_diag.bridge_scalar[14])")
    if not 0 <= attempt < first_validation < last_validation < \
            attempted_reset < reject_reset < pending_write < request_write < \
            request_dcache < published < success_reason or \
            home_request.count("_sw(") != 3:
        fail("functional HOME first-load publication ordering regressed")
    for forbidden in ("sceKernelIcache", "zeroCtrlSetSlideState",
            "psp1000RuntimeRequestTarget", "zeroCtrlTrigger58D4(", "MAKE_CALL",
            "MAKE_JUMP", "_sw(replacement", "sceIo", "malloc", "Alloc",
            "zeroCtrlInstallVshCtrl314A4Bridge"):
        if forbidden in home_request:
            fail("functional HOME first-load path performs forbidden operation " + forbidden)
    home_fields = ("functional_home_press_hits",
            "functional_home_first_load_attempts",
            "functional_home_first_load_published",
            "functional_home_first_load_reject_reason")
    if kernel.count("volatile int functional_home_open_pending;") != 1 or any(
            kernel.count("volatile unsigned int " + field + ";") != 1 or
            field in bsman_header for field in home_fields) or \
            "functional_home_open_pending" in bsman_header:
        fail("functional HOME evidence is not kernel-local with exact fields")
    press_branch = functional_block.find("functional_home_press_hits++")
    lifecycle_choice = functional_block.find(
            "if (slide_diag.bsman.functional_validation &&")
    if press_branch < 0 or press_branch >= lifecycle_choice or \
            kernel.count("functional_home_press_hits++") != 1:
        fail("functional HOME press evidence is outside the exact action branch")
    consumed_start = minimal.find(
            "if (slide_diag.functional_request_armed &&\n"
            "                    !slide_diag.functional_trigger_consumed)")
    consumed_range = minimal.find("zeroCtrlVshModuleRangeValid(helper,\n"
            "                            trigger->request_addr, 4)",
            consumed_start)
    consumed_hits = minimal.find("zeroCtrlReadTriggerHits(0) != 0",
            consumed_range)
    consumed_read = minimal.find(
            "*(volatile unsigned int *)trigger->request_addr == 0",
            consumed_hits)
    consumed_publish = minimal.find(
            "slide_diag.functional_trigger_consumed = 1", consumed_read)
    consumed_log = minimal.find(
            "[psp1000-functional] startup_58d4_consumed=1", consumed_publish)
    if not 0 <= consumed_start < consumed_range < consumed_hits < \
            consumed_read < consumed_publish < consumed_log:
        fail("functional 58D4 consumption marker is not range/hit validated")
    home_record_marker = minimal.find("[psp1000-functional-home] press=%u ")
    home_record_start = minimal.rfind("if (slide_diag.functional_enabled) {",
            0, home_record_marker)
    home_record = minimal[home_record_start:minimal.find(
            "if (slide_diag.functional_request_armed &&", home_record_marker)]
    helper_metadata = home_record.find("zeroCtrlLoadedModuleMetadataValid(helper)")
    request_nonzero = home_record.find("trigger->request_addr != 0", helper_metadata)
    request_aligned = home_record.find("(trigger->request_addr & 3) == 0",
            request_nonzero)
    request_range = home_record.find(
            "zeroCtrlVshModuleRangeValid(helper,\n                            trigger->request_addr, 4)",
            request_aligned)
    request_read = home_record.find("state[5] = _lw(trigger->request_addr)",
            request_range)
    changed = home_record.find("memcmp(state, observed_functional_home",
            request_read)
    output = home_record.find("zeroCtrlDiagnosticsText(line)", changed)
    for token in ("functional_home_press_hits",
            "functional_home_first_load_attempts",
            "functional_home_first_load_published",
            "functional_home_first_load_reject_reason",
            "functional_home_open_pending", "zeroCtrlReadTriggerHits(0)",
            "functional_trigger_consumed", "functional_validation",
            "functional_install", "functional_cache_sync",
            "press=%u attempt=%u ", "published=%u reject=%u pending=%u request=%u ",
            "hit=%u consumed=%u compat=%u/%u/%u"):
        if token not in home_record:
            fail("functional HOME writer record lacks " + token)
    if home_record_start < 0 or not 0 <= helper_metadata < request_nonzero < \
            request_aligned < request_range < request_read < changed < output or \
            "slide_diag.saw_request" in home_record or \
            kernel.count("[psp1000-functional-home]") != 1:
        fail("functional HOME writer validation/changed-only isolation regressed")
    for marker in ("[psp1000-vsh589c-install]", "[psp1000-vsh589c]"):
        if marker in minimal:
            fail("retired VSH +589C automatic output remains in minimal writer")
    for marker in ("[psp1000-vsh6f84-consumers-install]",
            "[psp1000-vsh6f84-consumers]"):
        if marker in minimal:
            fail("retired compact VSH consumer output remains in minimal writer")
    if "[psp1000-vsh58d4]" in minimal:
        fail("retired compact VSH +58D4 output remains in minimal writer")
    for marker in ("[psp1000-vsh57b0-map]", "[psp1000-vsh57b0-ref]",
            "[psp1000-vsh57b0-window]", "[psp1000-vsh57b0-code]"):
        if marker in minimal:
            fail("retired direct VSH +57B0 map remains in minimal writer")
    for marker in ("[psp1000-vsh57b0-materialize-map]",
            "[psp1000-vsh57b0-materialize]", "[psp1000-vsh57b0-use]",
            "[psp1000-vsh57b0-pointer-map]", "[psp1000-vsh57b0-pointer]"):
        if marker in minimal:
            fail("retired indirect VSH +57B0 map remains in minimal writer")
    for marker in ("[psp1000-vshctrl-map]", "[psp1000-vshctrl-lib]",
            "[psp1000-vshctrl-import]", "[psp1000-vshctrl-caller]",
            "[psp1000-vshctrl-window]", "[psp1000-vshctrl-code]",
            "[psp1000-vsh-import-lib]"):
        if marker in minimal:
            fail("retired static VSH controller map remains in minimal writer")
    if "zeroCtrlWriteFunctionalVshControllerMap()" in minimal:
        fail("retired static VSH controller map is still invoked")
    resolver = kernel[kernel.find("static " + ("void " if "Install" in "zeroCtrlResolveVshCtrlPeekImport" or "Request" in "zeroCtrlResolveVshCtrlPeekImport" else "int ") + "zeroCtrlResolveVshCtrlPeekImport("):kernel.find("\n}\n", kernel.find("zeroCtrlResolveVshCtrlPeekImport(")) + 3]
    for token in ('table = (unsigned int)vsh->stub_top',
            'size = vsh->stub_size', 'zeroCtrlVshModuleRangeValid(vsh, table, size)',
            'zeroCtrlVshModuleRangeValid(vsh, address, 12)', 'entry->len == 0',
            'entry_size > size - cursor',
            'zeroCtrlVshModuleRangeValid(vsh, address, entry_size)',
            'zeroCtrlVshModuleRangeValid(vsh, stubtable, functions_size)',
            'zeroCtrlVshModuleRangeValid(vsh, nidtable, nids_size)',
            'zeroCtrlCopyVshImportLibrary(vsh, entry->libname, name',
            'strcmp(name, "sceCtrl") == 0', '0x3A622550',
            'zeroCtrlVshModuleRangeValid(vsh, stub, 8)', '0x03E00008',
            '(_lw(stub + 4) & 0xFC00003F) != 0x0000000C', 'matches != 1'):
        if token not in resolver:
            fail("sceCtrl Peek import resolver lacks " + token)
    bridge_start = kernel.find(
            "static void zeroCtrlInstallVshCtrl314A4Bridge(void) {")
    bridge_end = kernel.find("void zeroCtrlRegisterPsp1000FunctionalBridge(",
            bridge_start)
    bridge = kernel[bridge_start:bridge_end]
    bridge_resolver_start = kernel.find(
            "static int zeroCtrlResolvePsp1000FunctionalBridge(")
    bridge_resolver = kernel[bridge_resolver_start:bridge_start]
    for token in ('model != 0', 'sceKernelDevkitVersion() != 0x06060110',
            '!slide_diag.functional_enabled',
            '!slide_diag.functional_request_armed',
            'zeroCtrlResolveVshCtrlPeekImport(vsh, &target)',
            'zeroCtrlResolvePsp1000FunctionalBridge(vsh, paf',
            'vsh->text_addr + 0x31494, 0x18', '0x27BDFFE0',
            '0x03A02021', '0x24050001', '0xAFBF0014',
            'owner = vsh->text_addr + 0x314A4',
            'vsh->text_addr + 0x314A8) != 0xAFB00010',
            'zeroCtrlMipsJumpTarget(owner, _lw(owner)) != target',
            'sceKernelQueryMemoryPartitionInfo(2, &info)',
            '_sw(target, slide_diag.bridge_scalar[0])',
            '_sw(root, slide_diag.bridge_scalar[1])',
            '_sw(c0, slide_diag.bridge_scalar[2])',
            '_sw(c1, slide_diag.bridge_scalar[3])',
            '_sw(callback, slide_diag.bridge_scalar[4])',
            'for (i = 7; i <= 15; i++)',
            'for (i = 0; i <= 15; i++)',
            '_sw(replacement, owner)', 'slide_diag.bridge_install = 1'):
        if token not in bridge:
            fail("functional +314A4 bridge installer lacks " + token)
    attempt_increment = bridge.find('slide_diag.bridge_install_attempts++')
    precondition_guard = bridge.find('!slide_diag.bridge_registered)')
    ctrl_resolution = bridge.find('zeroCtrlResolveVshCtrlPeekImport(vsh, &target)')
    paf_resolution = bridge.find('zeroCtrlResolvePsp1000FunctionalBridge(vsh, paf')
    if not 0 <= precondition_guard < attempt_increment < ctrl_resolution < paf_resolution:
        fail("bridge attempts are not limited to armed registered installs")
    for token in ('ZERO_BRIDGE_STAGE_INSTALL_PRECONDITIONS',
            'ZERO_BRIDGE_STAGE_CTRL_IMPORT', 'ZERO_BRIDGE_STAGE_CALLSITE_314A4',
            'ZERO_BRIDGE_STAGE_READY', 'ZERO_BRIDGE_REJECT_CTRL_IMPORT',
            'ZERO_BRIDGE_REJECT_CALLSITE_314A4'):
        if token not in bridge:
            fail("functional bridge installer staging lacks " + token)
    owner_write = bridge.find('_sw(replacement, owner)')
    owner_dcache = bridge.find(
            'sceKernelDcacheWritebackInvalidateRange((const void *)owner, 4)',
            owner_write)
    owner_icache = bridge.find(
            'sceKernelIcacheInvalidateRange((const void *)owner, 4)', owner_dcache)
    if not 0 <= owner_write < owner_dcache < owner_icache:
        fail("functional +314A4 owner commit/cache order regressed")
    if '0x13EF8' in bridge or 'minimal_memory_test' in bridge:
        fail("functional +314A4 bridge patches another caller or depends on diagnostics")
    for token in ('vtext + 0x589C', 'vtext + 0x3F568', '"scePaf"',
            '0xA989A2C4', 'strcmp(paf->modname, "scePaf_Module")',
            'resolved != ptext + 0x35978', 'inner != ptext + 0x34A24',
            '*constructed0 = ptext + 0x34610',
            '*constructed1 = ptext + 0x34658',
            'slot - paf->segmentaddr[1] != 0x1338',
            'zeroCtrlPsp1000BridgeLiveInValid(paf, vsh, *constructed1',
            '*callback)'):
        if token not in bridge_resolver:
            fail("functional PAF bridge resolver lacks " + token)
    if '0x089B5978' in bridge_resolver:
        fail("functional bridge hard-codes a boot-specific PAF root")
    stage_order = [bridge_resolver.find(token) for token in (
            'ZERO_BRIDGE_STAGE_VSH_PAF_METADATA',
            'ZERO_BRIDGE_STAGE_VSH_CALLBACK_REGISTRATION',
            'ZERO_BRIDGE_STAGE_PAF_A989_IMPORT', 'ZERO_BRIDGE_STAGE_WRAPPER',
            'ZERO_BRIDGE_STAGE_INNER_CONSUMER', 'ZERO_BRIDGE_STAGE_ROOT_SLOT',
            'ZERO_BRIDGE_STAGE_CONSTRUCTED0', 'ZERO_BRIDGE_STAGE_CONSTRUCTED1',
            'ZERO_BRIDGE_STAGE_LIVEIN_ENTERED',
            'ZERO_BRIDGE_STAGE_LIVEIN_PASSED')]
    if any(position < 0 for position in stage_order) or \
            stage_order != sorted(stage_order):
        fail("functional resolver milestones are absent or non-monotonic")
    livein_entered = bridge_resolver.find(
            'bridge_resolve_stage = ZERO_BRIDGE_STAGE_LIVEIN_ENTERED')
    livein_validate = bridge_resolver.find(
            'zeroCtrlPsp1000BridgeLiveInValid(paf, vsh, *constructed1',
            livein_entered)
    livein_passed = bridge_resolver.find(
            'bridge_resolve_stage = ZERO_BRIDGE_STAGE_LIVEIN_PASSED',
            livein_validate)
    if not 0 <= livein_entered < livein_validate < livein_passed:
        fail("live-in resolver milestones do not bracket the proof")
    livein_start = kernel.find(
            "static int zeroCtrlPsp1000BridgeLiveInValid(")
    livein_end = kernel.find("static int zeroCtrlPsp1000BridgeImportMatches(",
            livein_start)
    livein = kernel[livein_start:livein_end]
    taint_start = kernel.find(
            "static int zeroCtrlBridgeAnalyzeTaintedFunction(")
    taint = kernel[taint_start:livein_end]
    for token in ('BRIDGE_TAINT_MAX_DEPTH 3',
            'BRIDGE_TAINT_MAX_FUNCTIONS 16',
            'BRIDGE_TAINT_MAX_NODES 128',
            'BRIDGE_TAINT_MAX_INSTRUCTIONS 512',
            'call_off[4] = { 0x18, 0x24, 0x30, 0x38 }',
            'zeroCtrlMipsJumpTarget(constructed1 + call_off[i], word)',
            'zeroCtrlModuleContainingSegment(paf, target[i]',
            'ZERO_BRIDGE_LIVEIN_OVERWRITTEN',
            'ZERO_BRIDGE_LIVEIN_REQUIRED',
            'ZERO_BRIDGE_LIVEIN_IGNORED',
            'ZERO_BRIDGE_LIVEIN_UNKNOWN',
            'zeroCtrlBridgeAnalyzeTaintedFunction(paf, constructed1, 1U << 6',
            'zeroCtrlBridgeAnalyzeTaintedFunction(paf, constructed1, 1U << 7',
            'slide_diag.bridge_livein_validation = 1'):
        if token not in livein and token not in taint and token not in kernel:
            fail("constructed1 live-in proof lacks " + token)
    for token in ('SceModule2 *module', 'SceModule2 *vsh',
            'unsigned int expected_callback',
            'expected_callback != vsh->text_addr + 0x589C',
            'pc == context->constructed1 + 0xB4',
            'word == 0x0040F809',
            '_lw(context->constructed1 + 0x40) == 0x8E02000C',
            '(_lw(context->constructed1 + 0x44) >> 26) >= 4',
            '(_lw(context->constructed1 + 0x44) >> 26) <= 7',
            'context->constructed1 + 0xB4',
            '_lw(context->constructed1 + 0x48) == 0',
            '_lw(context->constructed1 + 0xB8) == 0x8E040004',
            'zeroCtrlBridgeAnalyzeTaintedFunction(context->vsh',
            'context->expected_callback, callback_input_taint',
            'zeroCtrlBridgeExecutableRange(module, pc, 4)',
            'sceKernelFindModuleByAddress(target)',
            'zeroCtrlLoadedModuleMetadataValid(owner)',
            'segment != 0'):
        if token not in livein and token not in taint and token not in kernel:
            fail("callback-aware cross-module proof lacks " + token)
    for token in ('ZERO_BRIDGE_BLOCK_REASON_RANGE',
            'ZERO_BRIDGE_BLOCK_REASON_NODE_LIMIT',
            'ZERO_BRIDGE_BLOCK_REASON_INSTRUCTION_LIMIT',
            'ZERO_BRIDGE_BLOCK_REASON_FUNCTION_LIMIT',
            'ZERO_BRIDGE_BLOCK_REASON_DEPTH_LIMIT',
            'ZERO_BRIDGE_BLOCK_REASON_UNSUPPORTED_INSTRUCTION',
            'ZERO_BRIDGE_BLOCK_REASON_OBSERVED_TAINT',
            'ZERO_BRIDGE_BLOCK_REASON_UNSUPPORTED_REGIMM',
            'ZERO_BRIDGE_BLOCK_REASON_INVALID_BRANCH_TARGET',
            'ZERO_BRIDGE_BLOCK_REASON_INVALID_DIRECT_CALL_TARGET',
            'ZERO_BRIDGE_BLOCK_REASON_INVALID_DIRECT_JUMP_TARGET',
            'ZERO_BRIDGE_BLOCK_REASON_TAINTED_INDIRECT_TARGET',
            'ZERO_BRIDGE_BLOCK_REASON_UNRESOLVED_JALR',
            'ZERO_BRIDGE_BLOCK_REASON_CALLEE_UNKNOWN',
            'context->blocker_taint = taint',
            'context->blocker_word = _lw(address)',
            'address - 4, 4)', 'address + 4, 4)'):
        if token not in kernel:
            fail("bounded taint blocker evidence lacks " + token)
    blocker_guard = kernel.find(
            'if (context->blocker_domain != ZERO_BRIDGE_BLOCKER_NONE) return;')
    blocker_write = kernel.find('context->blocker_reason = reason;', blocker_guard)
    if not 0 <= blocker_guard < blocker_write:
        fail("outer callers can overwrite the first nested taint blocker")
    for known_word in ('0x27BDFFF0', '0xAFBF0008', '0xAFB00000',
            '0x00A08021', '0xAFB10004', '0x8CA40000', '0x24840010',
            '0x8E040000', '0x26050004', '0x8E040004', '0x8E02000C'):
        if known_word not in livein:
            fail("constructed1 prefix validation lacks " + known_word)
    if re.search(r'offset\s*<=\s*0x40[\s\S]{0,400}'
            r'opcode\s*==\s*3[\s\S]{0,80}return\s+0', livein):
        fail("constructed1 validator still rejects its known direct JALs")
    for token in ('callee_input_taint = taint',
            'zeroCtrlBridgeAnalyzeTaintedFunction(owner, target',
            'depth + 1', 'context->functions >= BRIDGE_TAINT_MAX_FUNCTIONS',
            'context->instructions >= BRIDGE_TAINT_MAX_INSTRUCTIONS',
            'opcode == 0 && (function == 8 || function == 9)',
            'zeroCtrlBridgeSetBlocker(context, module, pc, original_arg,'):
        if token not in taint:
            fail("constructed1 bounded callee-taint proof lacks " + token)
    delay_apply = taint.find(
            'result = zeroCtrlBridgeApplyTaint(delay, &taint)')
    jal_link_kill = taint.rfind('taint &= ~(1U << 31)', 0, delay_apply)
    call_classify = taint.find('callee_input_taint = taint', delay_apply)
    recursive_call = taint.find(
            'zeroCtrlBridgeAnalyzeTaintedFunction(owner, target', call_classify)
    continuation = taint.find('pc += 8', recursive_call)
    if not 0 <= jal_link_kill < delay_apply < call_classify < recursive_call < \
            continuation:
        fail("direct-call link/delay/full-taint ordering regressed")
    direct_call = taint[jal_link_kill:continuation]
    if 'taint & 0xF0' in direct_call or \
            'callee_input_taint, depth + 1' not in direct_call:
        fail("direct-call recursion is still argument-only")
    forbidden_abi_kills = ('taint &= ~0x8300FFFCU',
            'taint &= ~VSH_CALLER_SAVED_GPR_MASK',
            'caller-saved values cannot carry the old incoming taint',
            'JAL means a0/a1/a2/a3/v0/v1 are destroyed')
    for token in forbidden_abi_kills:
        if token in taint:
            fail("ABI-only caller-saved taint kill returned: " + token)
    for token in ('typedef struct ZeroCtrlBridgeReturnSummary',
            'unsigned int saw_return', 'unsigned int return_taint',
            'ZeroCtrlBridgeReturnSummary *summary',
            'summary->saw_return = 0', 'summary->return_taint = 0',
            'ZeroCtrlBridgeReturnSummary callee_summary',
            'ZeroCtrlBridgeReturnSummary tail_summary',
            'ZeroCtrlBridgeReturnSummary callback_summary',
            'taint = callee_summary.return_taint',
            'callee_summary.return_taint',
            'summary->return_taint |= tail_summary.return_taint',
            'callback_summary.return_taint',
            'summary->return_taint |= taint'):
        if token not in kernel and token not in taint:
            fail("return-taint summary lacks " + token)
    no_direct_return = taint.find(
            'if (!callee_summary.saw_return) continue;', recursive_call)
    direct_replace = taint.find(
            'taint = callee_summary.return_taint', no_direct_return)
    if not 0 <= recursive_call < no_direct_return < direct_replace < continuation:
        fail("direct-call return summary does not mechanically update caller taint")
    if '(taint & ~' in direct_call:
        fail("direct-call summary retains pre-call taint outside an incomplete subset")
    jr_return = taint.find('if (function == 8 && rs == 31)')
    jalr_block = taint.rfind(
            'opcode == 0 && (function == 8 || function == 9)', 0, jr_return)
    jr_delay = taint.find(
            'zeroCtrlBridgeApplyTaint(delay, &taint)', jalr_block, jr_return)
    jr_summary = taint.find('summary->saw_return = 1', jr_return)
    jr_union = taint.find('summary->return_taint |= taint', jr_summary)
    if not 0 <= jalr_block < jr_delay < jr_return < jr_summary < jr_union:
        fail("JR ra return summary is not captured after its delay slot")
    if '&=' in taint[jr_summary:jr_union + len('summary->return_taint |= taint')]:
        fail("multiple normal return taints are intersected instead of unioned")
    tail_recurse = taint.find(
            'zeroCtrlBridgeAnalyzeTaintedFunction(owner, target', recursive_call + 1)
    tail_union = taint.find(
            'summary->return_taint |= tail_summary.return_taint', tail_recurse)
    if not 0 <= tail_recurse < tail_union:
        fail("direct tail-call return summary is not propagated")
    tail_continue = taint.find('continue;', tail_union)
    if tail_continue < tail_union or \
            'return result;' in taint[tail_union:tail_continue]:
        fail("successful tail path discards pending sibling CFG nodes")
    callback_recurse_for_summary = taint.find(
            'zeroCtrlBridgeAnalyzeTaintedFunction(context->vsh')
    callback_replace = taint.find(
            'callback_summary.return_taint', callback_recurse_for_summary)
    if not 0 <= callback_recurse_for_summary < callback_replace:
        fail("known callback return summary is not propagated")
    callback_start = taint.rfind(
            'if (function == 9 && taint != 0)', 0,
            callback_recurse_for_summary)
    callback_no_return = taint.find(
            'if (!callback_summary.saw_return) continue;',
            callback_recurse_for_summary)
    if callback_start < 0 or \
            'unsigned int callback_input_taint = taint' not in \
            taint[callback_start:callback_recurse_for_summary] or \
            'taint & 0xF0' in taint[callback_start:callback_recurse_for_summary] or \
            not callback_recurse_for_summary < callback_no_return < callback_replace:
        fail("known callback does not use full live taint/return reachability")
    jalr_start_for_link = taint.rfind(
            '} else if (opcode == 0 && (function == 8 || function == 9))',
            0, callback_start)
    target_taint_check = taint.find(
            'if (taint & (1U << rs))', jalr_start_for_link, callback_start)
    jalr_link_kill = taint.find(
            'if (function == 9 && rd != 0) taint &= ~(1U << rd)',
            target_taint_check, callback_start)
    jalr_delay_apply = taint.find(
            'zeroCtrlBridgeApplyTaint(delay, &taint)', jalr_link_kill,
            callback_start)
    if not 0 <= target_taint_check < jalr_link_kill < jalr_delay_apply:
        fail("JALR target/link/delay ordering is not architectural")
    analyzer = kernel[taint_start:livein_start]
    if analyzer.count('return 0;') != 1 or not analyzer.rstrip().endswith('}'):
        fail("path-local safe exits can terminate the whole taint traversal")
    if '0x36AB0' in kernel or '0x36A64' in kernel:
        fail("hardware blocker/callee was hard-coded into the taint proof")
    for offset in ('0x18', '0x24', '0x30', '0x38'):
        if offset not in livein:
            fail("constructed1 call is not reachable to live-in proof: +" + offset)
    branch_start = taint.find(
            '} else if (opcode == 1 || (opcode >= 4 && opcode <= 7) ||')
    branch_end = taint.find('} else if (opcode == 2)', branch_start)
    branch = taint[branch_start:branch_end]
    for token in ('opcode >= 0x14 && opcode <= 0x17',
            'unsigned int taken_taint = taint',
            'unsigned int fallthrough_taint = taint',
            'rt == 2 || rt == 3 || rt == 18 || rt == 19',
            'rt != 0 && rt != 1 && rt != 16 && rt != 17',
            'if (taint != 0) return 2',
            'rt == 16 || rt == 17 || rt == 18 || rt == 19',
            'link && (taint & (1U << 31))',
            'taken_taint &= ~(1U << 31)',
            'fallthrough_taint &= ~(1U << 31)',
            'zeroCtrlBridgeApplyTaint(delay, &taken_taint)',
            'if (!likely) fallthrough_taint = taken_taint',
            'queue[tail++].taint = taken_taint',
            'queue[tail++].taint = fallthrough_taint'):
        if token not in branch:
            fail("branch-likely taint semantics lack " + token)
    delay_apply = branch.find(
            'zeroCtrlBridgeApplyTaint(delay, &taken_taint)')
    normal_merge = branch.find(
            'if (!likely) fallthrough_taint = taken_taint', delay_apply)
    target_enqueue = branch.find(
            'queue[tail++].taint = taken_taint', normal_merge)
    fallthrough_enqueue = branch.find(
            'queue[tail++].taint = fallthrough_taint', target_enqueue)
    if not 0 <= delay_apply < normal_merge < target_enqueue < fallthrough_enqueue:
        fail("branch successor taint ordering regressed")
    jalr_start = taint.find(
            'opcode == 0 && (function == 8 || function == 9)')
    jalr_end = taint.find('} else {', jalr_start)
    jalr = taint[jalr_start:jalr_end]
    jalr_delay = jalr.find('zeroCtrlBridgeApplyTaint(delay, &taint)')
    trusted_check = jalr.find('int known_callback =', jalr_delay)
    callback_recurse = jalr.find(
            'zeroCtrlBridgeAnalyzeTaintedFunction(context->vsh', trusted_check)
    generic_reject = jalr.find('if (!known_callback)', trusted_check)
    if not 0 <= jalr_delay < trusted_check < generic_reject < callback_recurse:
        fail("constructed1 callback exception weakens JALR or delay-slot checks")
    if 'return 2;' not in jalr[generic_reject:callback_recurse]:
        fail("ordinary tainted JALR no longer fails closed")
    livein_call = bridge_resolver.find(
            'zeroCtrlPsp1000BridgeLiveInValid(paf, vsh, *constructed1')
    root_pair = bridge_resolver.find('words[0xA8 / 4] >> 16')
    for token in ('((words[0xA8 / 4] >> 16) & 0x1F) != 2',
            '((words[0xAC / 4] >> 21) & 0x1F) != 2',
            '((words[0xAC / 4] >> 16) & 0x1F) != 4'):
        if token not in bridge_resolver:
            fail("PAF root LUI/LW pair lacks register validation: " + token)
    if livein_call < 0 or root_pair < 0:
        fail("functional bridge resolver omits live-in/root validation")
    resolve_pos = kernel.find("static int zeroCtrlResolvePsp1000FunctionalBridge(")
    for signature in (
            "static int zeroCtrlMipsMove(unsigned int word, unsigned int destination,",
            "static int zeroCtrlModuleContainingSegment(SceModule2 *mod,"):
        declaration = kernel.find(signature)
        if declaration < 0 or declaration > resolve_pos:
            fail("functional bridge uses helper before static declaration: " +
                    signature)
    armed_pos = kernel.find('slide_diag.functional_request_armed = 1')
    installer_declaration = kernel.find(
            'static void zeroCtrlInstallVshCtrl314A4Bridge(void);')
    if not 0 <= installer_declaration < armed_pos < bridge_start:
        fail("+314A4 installer is used before its static declaration")
    register_start = kernel.find("void zeroCtrlRegisterPsp1000FunctionalBridge(")
    register_end = kernel.find("static int zeroCtrlReadVshCtrl314A4Telemetry",
            register_start)
    registration = kernel[register_start:register_end]
    for token in ('ZeroCtrlPsp1000BridgeRegistration copied',
            'zeroCtrlVshModuleRangeValid(helper, (unsigned int)registration',
            'copied.helper_end_addr - copied.helper_addr',
            'zeroCtrlVshModuleRangeValid(helper, copied.scalar_addr[i], 4)',
            'slide_diag.bridge_registered = 1',
            'zeroCtrlInstallVshCtrl314A4Bridge();'):
        if token not in registration:
            fail("functional bridge registration lacks " + token)
    if 'for (i = 0; i < 16; i++)' not in registration:
        fail("functional bridge registration does not validate all 16 scalars")
    module_start = kernel[kernel.find("int OnModuleStart(SceModule2 *mod)"):
            kernel.find("int zeroCtrlLoadStartModule(")]
    if 'slide_diag.bridge_registered &&' not in module_start or \
            '!slide_diag.bridge_install' not in module_start or \
            'zeroCtrlInstallVshCtrl314A4Bridge();' not in module_start:
        fail("OnModuleStart no longer retries functional bridge installation")
    helper_start = assembly.find("zeroCtrlVsh314A4FunctionalBridge:")
    helper_end = assembly.find("zeroCtrlVsh314A4FunctionalBridgeEnd:", helper_start)
    helper = assembly[helper_start:helper_end]
    if hashlib.sha256(helper.encode()).hexdigest() != \
            '5ebfd32c79869490087322aede621485d6d63dba204ea5fcfc988a1dc5be7192':
        fail("functional +314A4 bridge assembly changed")
    controller_call = helper.find("jalr    $t9")
    result_save = helper.find("sw      $v0, 32($sp)", controller_call)
    request_read = helper.find("%lo(zeroCtrlTrigger58D4Request)", result_save)
    request_zero = helper.find("beqz    $t1, 9f", request_read)
    milestone_read = helper.find("%lo(zeroCtrlVsh314A4Milestone)", request_zero)
    milestone_ack_read = helper.find("%lo(zeroCtrlVsh314A4MilestoneAck)",
            milestone_read)
    request_stage = helper.find(".L314A4RequestObserved:", milestone_ack_read)
    busy_gate = helper.find("%lo(zeroCtrlVsh314A4Busy)", request_stage)
    attempted_gate = helper.find("%lo(zeroCtrlVsh314A4Attempted)", busy_gate)
    request_seen = helper.find("BRIDGE_INC zeroCtrlVsh314A4RequestSeen",
            attempted_gate)
    request_milestone = helper.find(
            "sw      $t1, %lo(zeroCtrlVsh314A4Milestone)($t0)", request_seen)
    request_return = helper.find("b       9f", request_milestone)
    validation_gate = helper.find(".L314A4ValidationGate:", request_return)
    validation_ack = helper.find("bne     $t5, $t4, 9f", validation_gate)
    first_retained = helper.find("%hi(zeroCtrlPafA989DependencyDirectValid)",
            validation_ack)
    result_restore = helper.rfind("lw      $v0, 32($sp)")
    if not 0 <= controller_call < result_save < request_read < request_zero < \
            milestone_read < milestone_ack_read < request_stage < busy_gate < \
            attempted_gate < request_seen < request_milestone < request_return < \
            validation_gate < validation_ack < first_retained < result_restore or \
            helper.count("zeroCtrlVsh314A4OriginalController") != 2 or \
            helper.count("jalr    $t9") != 3:
        fail("bridge controller/request ordering or Sony call count regressed")
    if helper.count('zeroCtrlVsh314A4MilestoneAck') != 2 or \
            helper.count('bne     $t5, $t4, 9f') != 5 or \
            'zeroCtrlVsh314A4ShadowProbeDone' in helper:
        fail("bridge milestone ACK dispatch or retired probe ownership regressed")
    for value in range(1, 8):
        if helper.count('addiu   $t1, $zero, %d' % value) < 1:
            fail("bridge does not publish milestone %d" % value)
    if any(token in helper for token in
            ('zeroCtrlDiagnostics', 'sceIoOpen', 'sceIoWrite',
             'sceKernelDelayThread')):
        fail("functional bridge performs I/O, logging, or waiting")
    for token in ('lw      $t1, 0x14($t0)',
            'addiu   $a0, $zero, 0x1D8', 'addiu   $t1, $zero, 13'):
        if token in helper:
            fail("completed allocator-only probe remains in functional bridge")
    if 'zeroCtrlPafA989NaturalGp' in assembly or \
            'zeroCtrlVsh314A4RequestGp' in assembly or \
            'addiu   $t1, $zero, 12' in helper:
        fail("completed GP probe remains in the constructed0 experiment")
    for token in ('addiu   $sp, $sp, -64', 'sw      $ra, 28($sp)',
            'sw      $s0, 0($sp)', 'sw      $s1, 4($sp)',
            'sw      $s2, 8($sp)', 'sw      $s3, 12($sp)',
            'sw      $s4, 16($sp)', 'sw      $s5, 20($sp)',
            'sw      $gp, 24($sp)', 'lw      $v0, 32($sp)',
            'lw      $gp, 24($sp)', 'lw      $ra, 28($sp)',
            'jr      $ra', 'addiu   $sp, $sp, 64'):
        if token not in helper:
            fail("functional bridge transparency lacks " + token)
    pre_request = helper[:request_zero]
    if any(token in pre_request for token in
            ('zeroCtrlPafA989Dependency', 'zeroCtrlPafA989W28',
             'zeroCtrlPafA989Pair', 'zeroCtrlPafA989Shadow',
             'zeroCtrlVsh314A4Milestone')):
        fail("request-zero bridge path accesses retained or shadow state")
    for forbidden_old in ('zeroCtrlVsh314A4RootSlot',
            'zeroCtrlPafA989TargetNode', 'zeroCtrlPafA989TargetOuter',
            'zeroCtrlPafA989TargetInner', 'zeroCtrlPafA989TargetDependencySync',
            'zeroCtrlPafA989Pair00Ptr', 'zeroCtrlPafA989Pair0CPtr'):
        if forbidden_old in helper:
            fail("functional bridge still uses ephemeral state: " + forbidden_old)
    validity_symbols = ('zeroCtrlPafA989DependencyDirectValid',
            'zeroCtrlPafA989W28BytesValid', 'zeroCtrlPafA989Pair00Valid',
            'zeroCtrlPafA989Pair0CValid')
    validity_positions = [helper.find('%hi(' + symbol + ')', first_retained)
            for symbol in validity_symbols]
    scalar_specs = (('W2C', 'addiu   $t2, $zero, 0x27'),
            ('W34', 'bnez    $t1, 2f'),
            ('W3C', 'bnez    $t1, 2f'), ('W40', 'bnez    $t1, 2f'),
            ('W54', 'bnez    $t1, 2f'), ('W68', 'bnez    $t1, 2f'),
            ('W6C', 'bnez    $t1, 2f'),
            ('W20', 'bnez    $t1, 2f'),
            ('W38', 'addiu   $t2, $zero, 0x32'),
            ('W64', 'addiu   $t2, $zero, 0x0C'))
    scalar_positions = []
    for suffix, check in scalar_specs:
        load = helper.find('%hi(zeroCtrlPafA989Dependency' + suffix + ')',
                validity_positions[-1])
        check_pos = helper.find(check, load)
        if load < 0 or check_pos < load:
            fail("functional bridge lacks selected-route scalar check " + suffix)
        scalar_positions.append(load)
    shape_tokens = ('%hi(zeroCtrlPafA989Pair00Len)',
            'addiu   $t2, $zero, 0x0E', '%hi(zeroCtrlPafA989Pair0CLen)',
            'addiu   $t2, $zero, 0x08',
            '%hi(zeroCtrlPafA989Pair00Data00)', 'lbu     $t1, 0x0E($t0)',
            '%hi(zeroCtrlPafA989Pair0CData00)', 'lbu     $t1, 0x08($t0)',
            '%hi(zeroCtrlPafA989W28Data00)', 'lbu     $t1, 0x27($t0)')
    shape_positions = [helper.find(token, scalar_positions[-1])
            for token in shape_tokens]
    callback_load = helper.find('%hi(zeroCtrlVsh314A4ExpectedCallback)',
            shape_positions[-1])
    provenance_tokens = ('lui     $t2, 0x0001', 'ori     $t2, $t2, 0xA274',
            '%hi(zeroCtrlPafA989DependencyW18)', 'ori     $t2, $t2, 0xA324',
            '%hi(zeroCtrlPafA989DependencyW1C)', 'ori     $t2, $t2, 0xA3A4',
            '%hi(zeroCtrlPafA989DependencyW24)')
    provenance_positions = [helper.find(token, callback_load)
            for token in provenance_tokens]
    validation_complete = helper.find('.L314A4ValidationComplete:',
            provenance_positions[-1])
    validation_milestone = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Milestone)($t0)',
            validation_complete)
    validation_return = helper.find('b       9f', validation_milestone)
    shadow_gate = helper.find('.L314A4ShadowGate:', validation_return)
    shadow_ack = helper.find('bne     $t5, $t4, 9f', shadow_gate)
    shadow_start = helper.find('.L314A4ShadowBuild:', shadow_ack)
    busy_set = helper.find('sw      $t1, %lo(zeroCtrlVsh314A4Busy)($t0)',
            shadow_start)
    attempted_set = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Attempted)($t0)', busy_set)
    stage0_inc = helper.find('BRIDGE_INC zeroCtrlVsh314A4Stage0Calls',
            attempted_set)
    constructed0_load = helper.find('%hi(zeroCtrlVsh314A4Constructed0)',
            stage0_inc)
    constructed0_call = helper.find('jalr    $t9', constructed0_load)
    if any(pos < 0 for pos in validity_positions + scalar_positions +
                shape_positions + provenance_positions) or \
            validity_positions != sorted(validity_positions) or \
            scalar_positions != sorted(scalar_positions) or \
            shape_positions != sorted(shape_positions) or \
            not validity_positions[-1] < scalar_positions[0] < \
                scalar_positions[-1] < shape_positions[0] < shape_positions[-1] < \
                callback_load < provenance_positions[0] < \
                provenance_positions[-1] < validation_complete < \
                validation_milestone < validation_return < shadow_gate < shadow_ack < \
                shadow_start < busy_set < \
                attempted_set < stage0_inc < constructed0_load < constructed0_call:
        fail("retained-state validation does not precede shadow Sony execution")
    if any(token in helper for token in ('0x1FB10', '0x1FBC0', '0x1FC40')) or \
            helper.count('addu    $t2, $s5, $t2') != 3:
        fail("persistent VSH pointers are not callback-relative")
    shadow_clear_start = shadow_start
    shadow_build_end = helper.find('.L314A4ShadowComplete:', shadow_start)
    shadow_build = helper[shadow_clear_start:shadow_build_end]
    dependency_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$s3\)', shadow_build))
    if dependency_zero_offsets != tuple('%02X' % offset
            for offset in range(0, 0x70, 4)):
        fail("shadow dependency is not fully zeroed before selected fields")
    outer_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$s1\)', shadow_build))
    inner_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$s2\)', shadow_build))
    node_a_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$t2\)', shadow_build))
    node_b_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$t3\)', shadow_build))
    root_zero_offsets = tuple(re.findall(
            r'sw      \$zero, 0x([0-9A-F]{2})\(\$t4\)', shadow_build))
    if outer_zero_offsets != tuple('%02X' % offset
                for offset in range(0, 0x1C, 4)) or \
            inner_zero_offsets != tuple('%02X' % offset
                for offset in range(0, 0x10, 4)) or \
            node_a_zero_offsets != ('00',) or \
            node_b_zero_offsets != ('00',) or \
            root_zero_offsets != tuple('%02X' % offset
                for offset in range(0, 0x30, 4)):
        fail("shadow outer/inner/+0x44 nodes are not reset per attempt")
    required_shadow_tokens = (
            'sw      $t0, 0x00($s3)', 'sw      $t1, 0x04($s3)',
            'sw      $t0, 0x0C($s3)', 'sw      $t1, 0x10($s3)',
            'sw      $t1, 0x18($s3)', 'sw      $t1, 0x1C($s3)',
            'sw      $t1, 0x20($s3)', 'sw      $t1, 0x24($s3)',
            'sw      $t0, 0x28($s3)', 'sw      $t1, 0x2C($s3)',
            'sw      $t1, 0x34($s3)', 'sw      $t1, 0x38($s3)',
            'sw      $t1, 0x3C($s3)', 'sw      $t1, 0x40($s3)',
            'sw      $t2, 0x44($s3)', 'sw      $t1, 0x54($s3)',
            'sw      $t1, 0x64($s3)', 'sw      $t1, 0x68($s3)',
            'sw      $t1, 0x6C($s3)',
            '%hi(zeroCtrlPafA989Shadow44NodeA)',
            '%hi(zeroCtrlPafA989Shadow44NodeB)', 'sw      $t3, 0x00($t2)',
            '%hi(zeroCtrlPafA989Shadow44Root)', 'sw      $t4, 0x00($t3)',
            'addiu   $t1, $zero, 0x0A', 'sb      $t1, 0x2D($t4)',
            'sw      $s3, 0x08($s2)',
            'sw      $s5, 0x0C($s2)', 'sw      $t1, 0x00($s1)',
            'sw      $s2, 0x04($s1)', 'sw      $t1, 0x08($s1)',
            'sw      $t1, 0x0C($s1)', 'sw      $t1, 0x14($s1)')
    for token in required_shadow_tokens:
        if token not in shadow_build:
            fail("private shadow construction lacks " + token)
    if 'zeroCtrlPafA989Shadow44Wrapper' in helper or \
            'sw      $t2, 0x00($t3)' in shadow_build or \
            'sb      $t1, 0x2D($t2)' in shadow_build or \
            'sb      $t1, 0x2D($t3)' in shadow_build or \
            shadow_build.count('sb      ') != 1:
        fail("functional bridge retains a cyclic or preinitialized node topology")
    shadow_milestone = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Milestone)($t0)', shadow_build_end)
    shadow_return = helper.find('b       9f', shadow_milestone)
    arm_gate = helper.find('.L314A4ArmGate:', shadow_return)
    arm_ack = helper.find('bne     $t5, $t4, 9f', arm_gate)
    reject10_value = helper.find('addiu   $t1, $zero, 10', arm_ack)
    reject10_publish = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Reject)($t0)', reject10_value)
    arm_milestone = helper.find('addiu   $t1, $zero, 4', reject10_publish)
    arm_publish = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Milestone)($t0)', arm_milestone)
    arm_return = helper.find('b       9f', arm_publish)
    call_gate = helper.find('.L314A4CallGate:', arm_return)
    call_ack = helper.find('bne     $t5, $t4, 9f', call_gate)
    node_a_link = helper.find('sw      $t3, 0x00($t2)', shadow_start)
    node_b_link = helper.find('sw      $t4, 0x00($t3)', node_a_link)
    root_flag = helper.find('sb      $t1, 0x2D($t4)', node_b_link)
    dependency_node = helper.find('sw      $t2, 0x44($s3)', root_flag)
    shadow_complete = helper.find('sw      $t1, 0x14($s1)', dependency_node)
    if not shadow_start < node_a_link < node_b_link < root_flag < \
            dependency_node < shadow_complete < shadow_build_end < \
            shadow_milestone < shadow_return < arm_gate < arm_ack < reject10_value < \
            reject10_publish < arm_milestone < arm_publish < arm_return < call_gate < \
            call_ack < busy_set < attempted_set < stage0_inc < \
            constructed0_call:
        fail("constructed0 milestone/publication ordering regressed")
    if helper.count('sw      $t1, %lo(zeroCtrlVsh314A4Busy)($t0)') != 1 or \
            helper.count(
                'sw      $t1, %lo(zeroCtrlVsh314A4Attempted)($t0)') != 1 or \
            helper.count('BRIDGE_INC zeroCtrlVsh314A4Attempts') != 1 or \
            helper.count('BRIDGE_INC zeroCtrlVsh314A4Stage0Calls') != 1:
        fail("constructed0 one-shot state publication is duplicated")
    constructed0_a0 = helper.find('move    $a0, $s2', constructed0_load)
    constructed0_a1 = helper.find('move    $a1, $s1', constructed0_load)
    if 'sw      $zero, 0x48($s3)' not in shadow_build or \
            not constructed0_a0 < constructed0_call < constructed0_a1 or \
            helper.count('move    $a0, $s2\n    jalr    $t9\n'
                    '    move    $a1, $s1') != 1:
        fail("constructed0 does not receive the complete private shadow")
    return_result = helper.find('lw      $s4, 0x04($s2)', constructed0_call)
    return_store = helper.find(
            'sw      $s4, %lo(zeroCtrlVsh314A4RejectObject)($t0)', return_result)
    post_capture_tokens = (
            ('lw      $t3, 0x04($s1)',
             'sw      $t3, %lo(zeroCtrlVsh314A4PostOuter04)($t0)'),
            ('lw      $t3, 0x14($s1)',
             'sw      $t3, %lo(zeroCtrlVsh314A4PostOuter14)($t0)'),
            ('lw      $t3, 0x08($s2)',
             'sw      $t3, %lo(zeroCtrlVsh314A4PostInner08)($t0)'),
            ('lw      $t3, 0x0C($s2)',
             'sw      $t3, %lo(zeroCtrlVsh314A4PostInner0C)($t0)'))
    capture_positions = []
    capture_cursor = return_store
    for load, store in post_capture_tokens:
        load_pos = helper.find(load, capture_cursor)
        store_pos = helper.find(store, load_pos)
        if load_pos < capture_cursor or store_pos < load_pos or \
                helper.count(store) != 1:
            fail("immediate constructed0 snapshot capture ordering regressed")
        capture_positions.extend((load_pos, store_pos))
        capture_cursor = store_pos
    return_busy_clear = helper.find(
            'sw      $zero, %lo(zeroCtrlVsh314A4Busy)($t0)', capture_cursor)
    returned_milestone = helper.find('addiu   $t1, $zero, 5', return_busy_clear)
    returned_publish = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Milestone)($t0)', returned_milestone)
    returned_return = helper.find('b       9f', returned_publish)
    post_gate = helper.find('.L314A4PostGate:', returned_return)
    post_ack = helper.find('bne     $t5, $t4, 9f', post_gate)
    saved_result_load = helper.find(
            'lw      $s4, %lo(zeroCtrlVsh314A4RejectObject)($t0)', post_ack)
    post_start = saved_result_load
    post_tokens = ('BRIDGE_VALIDATE $s4, 4, 5f',
            'lw      $t3, %lo(zeroCtrlVsh314A4PostOuter04)($t0)',
            'bne     $t3, $s2, 5f',
            'lw      $t3, %lo(zeroCtrlVsh314A4PostOuter14)($t0)',
            'lw      $t3, %lo(zeroCtrlVsh314A4PostInner08)($t0)',
            'bne     $t3, $s3, 5f',
            'lw      $t3, %lo(zeroCtrlVsh314A4PostInner0C)($t0)',
            'bne     $t3, $s5, 5f')
    post_positions = [helper.find(token, post_start) for token in post_tokens]
    for symbol in ('PostOuter04', 'PostOuter14', 'PostInner08', 'PostInner0C'):
        if helper.count(
                f'lw      $t3, %lo(zeroCtrlVsh314A4{symbol})($t0)') != 1:
            fail("postgate snapshot load count regressed for " + symbol)
    stage1_inc = helper.find('BRIDGE_INC zeroCtrlVsh314A4Stage1Calls',
            post_positions[-1])
    constructed1_call = helper.find('jalr    $t9', stage1_inc)
    reject11_value = helper.find('addiu   $t1, $zero, 11', post_positions[-1])
    reject11_publish = helper.find(
            'sw      $t1, %lo(zeroCtrlVsh314A4Reject)($t0)', reject11_value)
    constructed1_bypass = helper.find('b       6f', reject11_publish)
    if any(pos < 0 for pos in post_positions) or \
            post_positions != sorted(post_positions) or \
            not constructed0_call < return_result < return_store < \
                capture_positions[0] < capture_positions[-1] < \
                return_busy_clear < returned_milestone < returned_publish < \
                returned_return < post_gate < post_ack < saved_result_load < \
                post_positions[0] < post_positions[-1] < \
                reject11_value < reject11_publish < constructed1_bypass < \
                stage1_inc < constructed1_call or \
            helper.find('move    $a1, $s2', stage1_inc) > constructed1_call:
        fail("constructed0 success does not bypass constructed1")
    immediate_snapshot = helper[return_result:return_busy_clear]
    postgate_body = helper[post_gate:reject11_value]
    if 'b       9f' in immediate_snapshot or 'jalr' in immediate_snapshot or \
            any(token in postgate_body for token in
                ('lw      $t3, 0x04($s1)', 'lw      $t3, 0x14($s1)',
                 'lw      $t3, 0x08($s2)', 'lw      $t3, 0x0C($s2)')):
        fail("post-validation does not exclusively use immediate snapshot state")
    for code, label in ((6, '1:'), (7, '2:'), (8, '3:'), (9, '4:'),
            (5, '5:')):
        label_pos = helper.find(label, constructed1_call)
        value_pos = helper.find('addiu   $t1, $zero, ' + str(code), label_pos)
        if label_pos < 0 or value_pos < label_pos:
            fail("functional bridge reject code mapping regressed")
    for forbidden in ('sw      $zero, %lo(zeroCtrlTrigger58D4Request)',
            'zeroCtrlTrigger13F6CHits', 'zeroCtrlTrigger14020Hits',
            '0x57B0', '0x58D4'):
        if forbidden in helper:
            fail("functional bridge violates request/counter/call isolation: " + forbidden)
    if "sizeof(ZeroCtrlPsp1000BridgeRegistration) == 72" not in bsman_header or \
            "sizeof(ZeroCtrlBSManClosedRegistration) == 1012" not in bsman_header or \
            "sizeof(ZeroCtrlActivationWideRegistration) == 304" not in bsman_header:
        fail("bridge registration changed a fixed activation ABI")
    if "sizeof(ZeroCtrlVsh5704TraceRegistration) == 16" not in bsman_header or \
            "scalar_addr[16]" not in bsman_header:
        fail("VSH+5704 trace is not a separate fixed diagnostic registration")
    if "sizeof(ZeroCtrlPafA989TargetTraceRegistration) == 32" not in \
            bsman_header:
        fail("A989 target trace is not a separate 32-byte registration")
    milestone_bss = (
            'zeroCtrlVsh314A4RejectObject: .space 4\n'
            '.globl zeroCtrlVsh314A4Milestone\n'
            'zeroCtrlVsh314A4Milestone: .space 4\n'
            '.globl zeroCtrlVsh314A4MilestoneAck\n'
            'zeroCtrlVsh314A4MilestoneAck: .space 4\n'
            '.globl zeroCtrlVsh314A4PostOuter04\n'
            'zeroCtrlVsh314A4PostOuter04: .space 4\n'
            '.globl zeroCtrlVsh314A4PostOuter14\n'
            'zeroCtrlVsh314A4PostOuter14: .space 4\n'
            '.globl zeroCtrlVsh314A4PostInner08\n'
            'zeroCtrlVsh314A4PostInner08: .space 4\n'
            '.globl zeroCtrlVsh314A4PostInner0C\n'
            'zeroCtrlVsh314A4PostInner0C: .space 4\n')
    if milestone_bss not in assembly:
        fail("functional milestone/ACK words are not adjacent to RejectObject")
    bridge_registration_start = kernel.find(
            'void zeroCtrlRegisterPsp1000FunctionalBridge(')
    bridge_registration_end = kernel.find(
            '\nstatic void zeroCtrlInstallVsh5704RegistrationTrace',
            bridge_registration_start)
    bridge_registration = kernel[
            bridge_registration_start:bridge_registration_end]
    for token in ('copied.scalar_addr[15] > 0xFFFFFFFFU - 24',
            'copied.scalar_addr[15] + 4, 24',
            'bridge_milestone_addr = copied.scalar_addr[15] + 4',
            'bridge_milestone_ack_addr = copied.scalar_addr[15] + 8',
            'copied.scalar_addr[15] + 12 + i * 4'):
        if token not in bridge_registration:
            fail("bridge private milestone derivation lacks " + token)
    bridge_install_start = kernel.find(
            'static void zeroCtrlInstallVshCtrl314A4Bridge(void) {')
    bridge_install_end = kernel.find(
            '\nvoid zeroCtrlRegisterPsp1000FunctionalBridge(', bridge_install_start)
    bridge_install = kernel[bridge_install_start:bridge_install_end]
    milestone_clear = bridge_install.find('_sw(0, slide_diag.bridge_milestone_addr)')
    ack_clear = bridge_install.find('_sw(0, slide_diag.bridge_milestone_ack_addr)')
    owner_patch = bridge_install.find('_sw(replacement, owner)')
    if not 0 <= milestone_clear < ack_clear < owner_patch or \
            bridge_install.count('bridge_milestone_addr, 4') != 1 or \
            bridge_install.count('bridge_milestone_ack_addr, 4') != 1 or \
            ('for (i = 0; i < 4; i++)\n        _sw(0, '
             'slide_diag.bridge_post_snapshot_addr[i])') not in bridge_install or \
            'bridge_post_snapshot_addr[i], 4' not in bridge_install:
        fail("bridge milestones are not cleared and synchronized before install")
    a989_registration_end = bsman_header.find(
            '} ZeroCtrlPafA989TargetTraceRegistration;')
    a989_registration_start = bsman_header.rfind(
            'typedef struct {', 0, a989_registration_end)
    a989_registration = bsman_header[
            a989_registration_start:a989_registration_end]
    if a989_registration_start < 0 or a989_registration_end < 0 or \
            a989_registration.count('u32 ') != 8 or \
            any(token in a989_registration for token in
                ('DependencyDirect', 'DependencyW', 'snapshot')):
        fail("A989 target trace registration fields changed")
    for source, token in ((kernel_exports,
                'zeroCtrlRegisterVsh5704Trace, 0x13373582'),
            (user_imports, '0x13373582, zeroCtrlRegisterVsh5704Trace'),
            (user_imports, '0x00140005'),
            (kernel_exports,
                'zeroCtrlRegisterPafA989TargetTrace, 0x13373583'),
            (user_imports, '0x13373583, zeroCtrlRegisterPafA989TargetTrace')):
        if token not in source:
            fail("VSH+5704 trace registration interface lacks " + token)
    bridge_user_registration = user[user.find(
            'psp1000BridgeRegistration.helper_addr'):user.find(
            'zeroCtrlRegisterPsp1000FunctionalBridge', user.find(
                'psp1000BridgeRegistration.helper_addr'))]
    if 'scalar_addr[15]' not in bridge_user_registration or \
            '&zeroCtrlVsh314A4RejectObject' not in bridge_user_registration:
        fail("bridge scalar 15 does not register exact reject-object evidence")
    if 'zeroCtrlTrigger13F6CHits' in user[user.find(
            'psp1000BridgeRegistration.helper_addr'):user.find(
            'zeroCtrlRegisterPsp1000FunctionalBridge', user.find(
                'psp1000BridgeRegistration.helper_addr'))]:
        fail("bridge registration aliases historical trigger counters")
    trace_install_start = kernel.find(
            'static void zeroCtrlInstallVsh5704RegistrationTrace(void) {')
    trace_register_start = kernel.find('void zeroCtrlRegisterVsh5704Trace(',
            trace_install_start)
    trace_register_end = kernel.find(
            'static int zeroCtrlPsp1000BridgeUserRangeValid(',
            trace_register_start)
    trace_install = kernel[trace_install_start:trace_register_start]
    trace_registration = kernel[trace_register_start:trace_register_end]
    for token in ('model != 0', 'sceKernelDevkitVersion() != 0x06060110',
            '!slide_diag.functional_enabled', 'vsh->text_size != 0x556C0',
            '!slide_diag.vsh_module_seen', 'vsh->modid != slide_diag.vsh_modid',
            'vsh->text_addr != slide_diag.vsh_text_addr',
            'vsh->text_size != slide_diag.vsh_text_size',
            'text + 0x56FC, 0x10', 'text + 0x5700', 'text + 0x589C',
            'owner = text + 0x5704', 'target = text + 0x3F568',
            '(_lw(owner) >> 26) != 3',
            'zeroCtrlMipsJumpTarget(owner, _lw(owner)) != target',
            'zeroCtrlMipsMove(_lw(text + 0x5708), 4, 29)',
            '"scePaf", 0xA989A2C4', 'paf->text_addr + 0x35978',
            '_lw(slide_diag.vsh5704_trace_jump_slot) != 0x08000000',
            'zeroCtrlMipsJumpTarget(slide_diag.vsh5704_trace_jump_slot,',
            'zeroCtrlMipsJumpTarget(owner, replacement)',
            'slide_diag.vsh5704_trace_validation = 1'):
        if token not in trace_install:
            fail("VSH+5704 exact installer lacks " + token)
    for token in ('!slide_diag.paf_a989_target_trace_registered',
            'slide_diag.paf_a989_target_trace_validation != 1',
            'slide_diag.paf_a989_target_trace_install != 1',
            'slide_diag.paf_a989_target_trace_cache_sync != 1'):
        if token not in trace_install:
            fail("VSH+5704 can install before synchronous A989 capture: " + token)
    helper_patch = trace_install.find(
            '_sw(helper_jump, slide_diag.vsh5704_trace_jump_slot)')
    helper_dcache = trace_install.find(
            'sceKernelDcacheWritebackInvalidateRange(', helper_patch)
    helper_icache = trace_install.find(
            'sceKernelIcacheInvalidateRange(', helper_dcache)
    owner_patch = trace_install.find('_sw(replacement, owner)', helper_icache)
    owner_dcache = trace_install.find(
            'sceKernelDcacheWritebackInvalidateRange((const void *)owner, 4)',
            owner_patch)
    owner_icache = trace_install.find(
            'sceKernelIcacheInvalidateRange((const void *)owner, 4)', owner_dcache)
    if not 0 <= helper_patch < helper_dcache < helper_icache < owner_patch < \
            owner_dcache < owner_icache:
        fail("VSH+5704 helper/owner commit and cache ordering regressed")
    for token in ('ZeroCtrlVsh5704TraceRegistration copied',
            'copied.helper_end_addr - copied.helper_addr',
            'copied.jump_slot_addr', 'copied.hit_counter_addr',
            'slide_diag.vsh5704_trace_registered = 1',
            'zeroCtrlInstallVsh5704RegistrationTrace();'):
        if token not in trace_registration:
            fail("VSH+5704 trace registration lacks " + token)
    trace_helper_start = assembly.find('zeroCtrlVsh5704RegistrationTrace:')
    trace_helper_end = assembly.find(
            'zeroCtrlVsh5704RegistrationTraceEnd:', trace_helper_start)
    trace_helper = assembly[trace_helper_start:trace_helper_end]
    if hashlib.sha256(trace_helper.encode()).hexdigest() != \
            '32cbbf3a61999e8a3fa9f37a54f96fbb428c7b70bd229e1afdaaa496e3a16dfb':
        fail("VSH+5704 trace helper assembly changed during diagnostic work")
    for token in ('addiu   $sp, $sp, -8', 'sw      $t0, 0($sp)',
            'sw      $t1, 4($sp)', 'lw      $t1, 4($sp)',
            'lw      $t0, 0($sp)', '.word   0x08000000',
            'addiu   $sp, $sp, 8',
            'zeroCtrlVsh5704RegistrationTraceHits'):
        if token not in trace_helper:
            fail("VSH+5704 transparent helper lacks " + token)
    if any(token in trace_helper for token in ('jal ', 'jalr', 'sw      $ra',
            'move    $a', 'zeroCtrlTrigger58D4Request')):
        fail("VSH+5704 trace calls code or changes Sony argument/return state")
    if trace_helper.count('sw      $t1, %lo(') != 1:
        fail("VSH+5704 helper records more than its dedicated hit counter")
    trace_user_registration = user[user.find(
            'vsh5704TraceRegistration.helper_addr'):user.find(
            'zeroCtrlRegisterVsh5704Trace', user.find(
                'vsh5704TraceRegistration.helper_addr'))]
    for token in ('zeroCtrlVsh5704RegistrationTrace',
            'zeroCtrlVsh5704RegistrationTraceEnd',
            'zeroCtrlVsh5704RegistrationTraceJump',
            'zeroCtrlVsh5704RegistrationTraceHits'):
        if token not in trace_user_registration:
            fail("user VSH+5704 registration lacks " + token)
    if 'zeroCtrlInstallVsh5704RegistrationTrace' in home_request:
        fail("HOME installs the VSH+5704 diagnostic trace")
    if 'vsh5704_trace_registered' not in module_start or \
            'zeroCtrlInstallVsh5704RegistrationTrace();' not in module_start:
        fail("OnModuleStart no longer retries the VSH+5704 trace")
    target_install_start = kernel.find(
            'static void zeroCtrlInstallPafA989TargetTrace(void) {')
    target_register_start = kernel.find(
            'void zeroCtrlRegisterPafA989TargetTrace(', target_install_start)
    target_register_end = kernel.find(
            'static int zeroCtrlPsp1000BridgeUserRangeValid(',
            target_register_start)
    target_install = kernel[target_install_start:target_register_start]
    target_registration = kernel[target_register_start:target_register_end]
    for token in ('vtext + 0x5704', 'vtext + 0x3F568',
            '"scePaf", 0xA989A2C4', 'ptext + 0x35978',
            'wrapper + 0x18', 'inner != ptext + 0x34A24',
            'inner + 0x90', 'consumer = zeroCtrlMipsJumpTarget(',
            '_lw(consumer + 0x10), 22, 8',
            '_lw(consumer + 0x18), 21, 6',
            '_lw(consumer + 0x20), 20, 9',
            '_lw(consumer + 0x28), 19, 7',
            '_lw(consumer + 0x30), 18, 5',
            '_lw(consumer + 0x68) != 0x24040028',
            '_lw(consumer + 0x74)', '_lw(consumer + 0x78) != 0x24500008',
            '_lw(consumer + 0x7C)', '_lw(consumer + 0x88) != 0xAC520008',
            '(_lw(consumer + 0x80) >> 26) != 4',
            '((_lw(consumer + 0x80) >> 21) & 0x1F) != 2',
            '((_lw(consumer + 0x80) >> 16) & 0x1F) != 0',
            'zeroCtrlMipsBranchTarget(consumer + 0x80,',
            'consumer + 0xD0',
            'zeroCtrlMipsMove(_lw(consumer + 0x84), 3, 0)',
            '_lw(consumer + 0x8C)', '_lw(consumer + 0x90) != 0xAE150004',
            '_lw(consumer + 0x94) != 0xAE130008',
            '_lw(consumer + 0x98) != 0xAE16000C',
            '_lw(consumer + 0x9C) != 0xAE140014',
            'owner = consumer + 0xA0', '(_lw(consumer + 0xA0) >> 26) != 3',
            '_lw(consumer + 0xA4) != 0xAE000018',
            '_lw(target) != 0x03E00008', '_lw(target + 4) != 0xAC850004',
            '_lw(slide_diag.paf_a989_target_trace_jump_slot) != 0x08000000'):
        if token not in target_install:
            fail("synchronous A989 consumer derivation lacks " + token)
    if '!= vtext + 0x3F568' not in target_install:
        fail("A989 consumer trace is not installed before the VSH+5704 owner")
    for token in ('PspSysmemPartitionInfo info',
            'sceKernelQueryMemoryPartitionInfo(2, &info)',
            '0xFFFFFFFFU - (unsigned int)info.memsize',
            '_sw((unsigned int)info.startaddr, slide_diag.bridge_scalar[5])',
            '_sw((unsigned int)info.startaddr + (unsigned int)info.memsize,',
            'slide_diag.bridge_scalar[6]', 'for (i = 2; i <= 6; i++)'):
        if token not in target_install:
            fail("A989 consumer trace lacks fail-closed user bounds: " + token)
    for token in ('unsigned int owner, target, helper_jump, replacement, '
            'snapshot_base, i;',
            'paf_a989_target_trace_scalar[4] > 0xFFFFFFFFU - 4',
            'snapshot_base = slide_diag.paf_a989_target_trace_scalar[4] + 4',
            'zeroCtrlVshModuleRangeValid(helper, snapshot_base, 0x11C)',
            'for (i = 0; i < 71; i++)',
            '_sw(0, snapshot_base + i * 4)',
            '(const void *)(snapshot_base + i * 4), 4'):
        if token not in target_install:
            fail("A989 synchronous snapshot installer lacks " + token)
    target_helper_patch = target_install.find(
            '_sw(helper_jump, slide_diag.paf_a989_target_trace_jump_slot)')
    target_helper_dcache = target_install.find(
            'sceKernelDcacheWritebackInvalidateRange(', target_helper_patch)
    target_helper_icache = target_install.find(
            'sceKernelIcacheInvalidateRange(', target_helper_dcache)
    target_owner_patch = target_install.find(
            '_sw(replacement, owner)', target_helper_icache)
    target_owner_dcache = target_install.find(
            'sceKernelDcacheWritebackInvalidateRange((const void *)owner, 4)',
            target_owner_patch)
    target_owner_icache = target_install.find(
            'sceKernelIcacheInvalidateRange((const void *)owner, 4)',
            target_owner_dcache)
    if not 0 <= target_helper_patch < target_helper_dcache < \
            target_helper_icache < target_owner_patch < target_owner_dcache < \
            target_owner_icache:
        fail("A989 target helper is not committed before its consumer owner")
    bounds_query = target_install.find('sceKernelQueryMemoryPartitionInfo(2, &info)')
    bounds_lower = target_install.find(
            '_sw((unsigned int)info.startaddr, slide_diag.bridge_scalar[5])',
            bounds_query)
    bounds_upper = target_install.find(
            'slide_diag.bridge_scalar[6]', bounds_lower)
    bounds_sync = target_install.find('for (i = 2; i <= 6; i++)', bounds_upper)
    if not 0 <= bounds_query < bounds_lower < bounds_upper < bounds_sync < \
            target_helper_patch:
        fail("A989 user bounds are not synchronized before helper/owner commit")
    snapshot_overflow = target_install.find(
            'paf_a989_target_trace_scalar[4] > 0xFFFFFFFFU - 4')
    snapshot_derive = target_install.find(
            'snapshot_base = slide_diag.paf_a989_target_trace_scalar[4] + 4',
            snapshot_overflow)
    snapshot_range = target_install.find(
            'zeroCtrlVshModuleRangeValid(helper, snapshot_base, 0x11C)',
            snapshot_derive)
    snapshot_clear = target_install.find(
            'for (i = 0; i < 71; i++)', snapshot_range)
    snapshot_clear_word = target_install.find(
            '_sw(0, snapshot_base + i * 4)', snapshot_clear)
    snapshot_clear_sync = target_install.find(
            '(const void *)(snapshot_base + i * 4), 4', snapshot_clear_word)
    if not 0 <= snapshot_overflow < snapshot_derive < snapshot_range < \
            snapshot_clear < snapshot_clear_word < snapshot_clear_sync < \
            target_helper_patch or \
            target_install.count('_sw(0, snapshot_base + i * 4)') != 1:
        fail("A989 derived snapshot BSS is not validated/cleared before commit")
    for token in ('ZeroCtrlPafA989TargetTraceRegistration copied',
            'copied.entry_hits_addr', 'copied.exact_hits_addr',
            'copied.target_node_addr', 'copied.target_outer_addr',
            'copied.target_inner_addr',
            'slide_diag.paf_a989_target_trace_registered = 1',
            'zeroCtrlInstallPafA989TargetTrace();'):
        if token not in target_registration:
            fail("A989 target trace registration lacks " + token)
    target_helper_start = assembly.find('zeroCtrlPafA989TargetTrace:')
    target_helper_end = assembly.find(
            'zeroCtrlPafA989TargetTraceEnd:', target_helper_start)
    target_helper = assembly[target_helper_start:target_helper_end]
    if hashlib.sha256(target_helper.encode()).hexdigest() != \
            '57d9b6cbdddbc42a8e65a0a9fe51725cf52a369a5aa8c0cc4ba97a8013bbafd4':
        fail("synchronous A989 target helper hash changed")
    for reg, offset in zip(('t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7'),
            range(0, 32, 4)):
        if 'sw      $' + reg + ', ' + str(offset) + '($sp)' not in target_helper or \
                'lw      $' + reg + ', ' + str(offset) + '($sp)' not in target_helper:
            fail("A989 synchronous helper does not preserve $" + reg)
    bss_start = assembly.find('zeroCtrlPafA989TargetInner: .space 4')
    bss_end = assembly.find(
            '.align 2\n.globl zeroCtrlPafA989ShadowOuter', bss_start)
    a989_snapshot_bss = assembly[bss_start:bss_end]
    required_bss = ('zeroCtrlPafA989TargetInner',
            'zeroCtrlPafA989DependencyDirectValid',
            'zeroCtrlPafA989TargetDependencySync',
            'zeroCtrlPafA989DependencyW2C', 'zeroCtrlPafA989DependencyW34',
            'zeroCtrlPafA989DependencyW38', 'zeroCtrlPafA989DependencyW3C',
            'zeroCtrlPafA989DependencyW40', 'zeroCtrlPafA989DependencyW54',
            'zeroCtrlPafA989DependencyW64', 'zeroCtrlPafA989DependencyW68',
            'zeroCtrlPafA989DependencyW6C', 'zeroCtrlPafA989DependencyW28',
            'zeroCtrlPafA989W28BytesValid',
            'zeroCtrlPafA989W28Data00', 'zeroCtrlPafA989W28Data04',
            'zeroCtrlPafA989W28Data08', 'zeroCtrlPafA989W28Data0C',
            'zeroCtrlPafA989W28Data10', 'zeroCtrlPafA989W28Data14',
            'zeroCtrlPafA989W28Data18', 'zeroCtrlPafA989W28Data1C',
            'zeroCtrlPafA989W28Data20', 'zeroCtrlPafA989W28Data24',
            'zeroCtrlPafA989W28Data28', 'zeroCtrlPafA989W28Data2C',
            'zeroCtrlPafA989W28Data30', 'zeroCtrlPafA989W28Data34',
            'zeroCtrlPafA989W28Data38', 'zeroCtrlPafA989W28Data3C',
            'zeroCtrlPafA989Pair00Valid', 'zeroCtrlPafA989Pair00Ptr', 'zeroCtrlPafA989Pair00Len',
            'zeroCtrlPafA989Pair00Data00', 'zeroCtrlPafA989Pair00Data04', 'zeroCtrlPafA989Pair00Data08',
            'zeroCtrlPafA989Pair00Data0C', 'zeroCtrlPafA989Pair00Data10', 'zeroCtrlPafA989Pair00Data14',
            'zeroCtrlPafA989Pair00Data18', 'zeroCtrlPafA989Pair00Data1C', 'zeroCtrlPafA989Pair00Data20',
            'zeroCtrlPafA989Pair00Data24', 'zeroCtrlPafA989Pair00Data28', 'zeroCtrlPafA989Pair00Data2C',
            'zeroCtrlPafA989Pair00Data30', 'zeroCtrlPafA989Pair00Data34', 'zeroCtrlPafA989Pair00Data38',
            'zeroCtrlPafA989Pair00Data3C', 'zeroCtrlPafA989Pair0CValid', 'zeroCtrlPafA989Pair0CPtr',
            'zeroCtrlPafA989Pair0CLen', 'zeroCtrlPafA989Pair0CData00', 'zeroCtrlPafA989Pair0CData04',
            'zeroCtrlPafA989Pair0CData08', 'zeroCtrlPafA989Pair0CData0C', 'zeroCtrlPafA989Pair0CData10',
            'zeroCtrlPafA989Pair0CData14', 'zeroCtrlPafA989Pair0CData18', 'zeroCtrlPafA989Pair0CData1C',
            'zeroCtrlPafA989Pair0CData20', 'zeroCtrlPafA989Pair0CData24', 'zeroCtrlPafA989Pair0CData28',
            'zeroCtrlPafA989Pair0CData2C', 'zeroCtrlPafA989Pair0CData30', 'zeroCtrlPafA989Pair0CData34',
            'zeroCtrlPafA989Pair0CData38', 'zeroCtrlPafA989Pair0CData3C',
            'zeroCtrlPafA989DependencyW18', 'zeroCtrlPafA989DependencyW1C',
            'zeroCtrlPafA989DependencyW20', 'zeroCtrlPafA989DependencyW24')
    bss_positions = [a989_snapshot_bss.find(name + ': .space 4')
            for name in required_bss]
    if bss_start < 0 or bss_end < 0 or any(pos < 0 for pos in bss_positions) or \
            bss_positions != sorted(bss_positions) or \
            a989_snapshot_bss.count(': .space 4') != 72 or \
            '.align' in a989_snapshot_bss:
        fail("A989 synchronous snapshot BSS is not exactly contiguous")
    shadow_bss_end = assembly.find(
            '.globl zeroCtrlGlobalPredicate6F84Hits', bss_end)
    shadow_bss = assembly[bss_end:shadow_bss_end]
    expected_shadow_bss = (
            '.globl zeroCtrlPafA989ShadowOuter\n'
            'zeroCtrlPafA989ShadowOuter: .space 0x1C\n'
            '.globl zeroCtrlPafA989ShadowInner\n'
            'zeroCtrlPafA989ShadowInner: .space 0x10\n'
            '.globl zeroCtrlPafA989ShadowDependency\n'
            'zeroCtrlPafA989ShadowDependency: .space 0x70\n'
            '.globl zeroCtrlPafA989Shadow44NodeA\n'
            'zeroCtrlPafA989Shadow44NodeA: .space 4\n'
            '.globl zeroCtrlPafA989Shadow44NodeB\n'
            'zeroCtrlPafA989Shadow44NodeB: .space 4\n'
            '.globl zeroCtrlPafA989Shadow44Root\n'
            'zeroCtrlPafA989Shadow44Root: .space 0x30\n'
            '.globl zeroCtrlVsh314A4ShadowProbeDone\n'
            'zeroCtrlVsh314A4ShadowProbeDone: .space 4\n')
    if shadow_bss_end < 0 or shadow_bss.count('.align 2') != 1 or             shadow_bss.replace('.align 2\n', '') != expected_shadow_bss:
        fail("private functional shadow BSS layout changed")
    for token in ('zeroCtrlVsh5704RegistrationTraceHits',
            'bnez    $t1, 1f', 'addiu   $t2, $a0, 8',
            'bne     $t2, $a1, 1f', 'lw      $t4, 0x00($a1)',
            'zeroCtrlVsh314A4Constructed0', 'lw      $t4, 0x08($a1)',
            'lw      $t4, 0x0C($a1)', 'addiu   $t5, $zero, -1',
            'lw      $t4, 0x14($a1)', 'zeroCtrlVsh314A4Constructed1',
            'lw      $t4, 0x18($a1)', 'bnez    $t4, 1f',
            'lw      $t6, 0x04($a1)', 'bne     $t6, $s5, 1f',
            'lw      $t4, 0x0C($t6)', 'zeroCtrlVsh314A4ExpectedCallback',
            'sw      $a0, %lo(zeroCtrlPafA989TargetNode)',
            'sw      $a1, %lo(zeroCtrlPafA989TargetOuter)',
            'sw      $t6, %lo(zeroCtrlPafA989TargetInner)',
            'zeroCtrlPafA989TargetTraceExactHits', '.word   0x08000000',
            'addiu   $sp, $sp, 32'):
        if token not in target_helper:
            fail("A989 synchronous helper contract lacks " + token)
    a0_range = target_helper.find('BRIDGE_VALIDATE $a0, 8, 1f')
    a1_range = target_helper.find('BRIDGE_VALIDATE $a1, 0x1C, 1f', a0_range)
    outer_first_read = target_helper.find('lw      $t4, 0x00($a1)')
    inner_load = target_helper.find('lw      $t6, 0x04($a1)', outer_first_read)
    inner_equal = target_helper.find('bne     $t6, $s5, 1f', inner_load)
    inner_range = target_helper.find('BRIDGE_VALIDATE $t6, 0x10, 1f', inner_equal)
    inner_callback = target_helper.find('lw      $t4, 0x0C($t6)', inner_range)
    if not 0 <= a0_range < a1_range < outer_first_read < inner_load < \
            inner_equal < inner_range < inner_callback:
        fail("A989 helper dereferences node/outer/inner before range validation")
    tuple_inner_store = target_helper.find(
            'sw      $t6, %lo(zeroCtrlPafA989TargetInner)', inner_callback)
    dependency_load = target_helper.find('lw      $t7, 0x08($t6)',
            tuple_inner_store)
    dependency_range = target_helper.find(
            'BRIDGE_VALIDATE $t7, 0x70, 2f', dependency_load)
    dependency_store = target_helper.find(
            'sw      $t7, %lo(zeroCtrlPafA989TargetDependencySync)',
            dependency_range)
    direct_offsets = ('2C', '34', '38', '3C', '40', '54', '64', '68', '6C',
            '28')
    direct_loads = [target_helper.find('lw      $t3, 0x' + offset + '($t7)',
            dependency_store) for offset in direct_offsets]
    direct_symbols = ('zeroCtrlPafA989DependencyW2C',
            'zeroCtrlPafA989DependencyW34', 'zeroCtrlPafA989DependencyW38',
            'zeroCtrlPafA989DependencyW3C', 'zeroCtrlPafA989DependencyW40',
            'zeroCtrlPafA989DependencyW54', 'zeroCtrlPafA989DependencyW64',
            'zeroCtrlPafA989DependencyW68', 'zeroCtrlPafA989DependencyW6C',
            'zeroCtrlPafA989DependencyW28')
    direct_stores = [target_helper.find(
            'sw      $t3, %lo(' + symbol + ')', direct_loads[index])
            for index, symbol in enumerate(direct_symbols)]
    valid_store = target_helper.find(
            'sw      $t3, %lo(zeroCtrlPafA989DependencyDirectValid)',
            direct_stores[-1])
    snapshot_done = target_helper.find('\n2:\n', valid_store)
    if not 0 <= tuple_inner_store < dependency_load < dependency_range < \
            dependency_store or any(pos < 0 for pos in direct_loads) or \
            any(pos < 0 for pos in direct_stores) or \
            any(not direct_loads[index] < direct_stores[index] <
                (direct_loads[index + 1] if index + 1 < len(direct_loads) else
                    valid_store) for index in range(len(direct_loads))) or \
            direct_loads != sorted(direct_loads) or not direct_stores[-1] < \
            valid_store < snapshot_done:
        fail("A989 synchronous dependency capture/publication order regressed")
    loaded_offsets = re.findall(r'lw      \$t3, 0x([0-9A-F]+)\(\$t7\)',
            target_helper[dependency_range:snapshot_done])
    if tuple(loaded_offsets[:len(direct_offsets)]) != direct_offsets or \
            target_helper.count('BRIDGE_VALIDATE $t7, 0x70, 2f') != 1 or \
            target_helper.count(
                'sw      $t3, %lo(zeroCtrlPafA989DependencyDirectValid)') != 1:
        fail("A989 synchronous dependency capture reads unexpected fields")
    string_offsets = ('00', '04', '08', '0C', '10', '14', '18', '1C',
            '20', '24', '28', '2C', '30', '34', '38', '3C')
    string_base = target_helper.find('addu    $t5, $t3, $zero',
            direct_stores[-1])
    string_valid_clear = target_helper.find(
            'sw      $zero, %lo(zeroCtrlPafA989W28BytesValid)', string_base)
    string_null = target_helper.find('beqz    $t5, 3f', string_valid_clear)
    string_align = target_helper.find('andi    $t2, $t5, 3', string_null)
    string_align_fail = target_helper.find('bnez    $t2, 3f', string_align)
    string_range = target_helper.find(
            'BRIDGE_VALIDATE $t5, 0x40, 3f', string_align_fail)
    string_loads = [target_helper.find('lw      $t3, 0x' + offset + '($t5)',
            string_range) for offset in string_offsets]
    string_stores = [target_helper.find(
            'sw      $t3, %lo(zeroCtrlPafA989W28Data' + offset + ')',
            string_loads[index]) for index, offset in enumerate(string_offsets)]
    string_valid_set = target_helper.find(
            'sw      $t3, %lo(zeroCtrlPafA989W28BytesValid)',
            string_stores[-1])
    string_done = target_helper.find('\n3:\n', string_valid_set)
    if not 0 <= string_base < string_valid_clear < string_null < string_align < \
            string_align_fail < string_range or \
            any(pos < 0 for pos in string_loads) or \
            any(pos < 0 for pos in string_stores) or \
            any(not string_loads[index] < string_stores[index] <
                (string_loads[index + 1] if index + 1 < len(string_loads) else
                    string_valid_set) for index in range(len(string_loads))) or \
            not string_stores[-1] < string_valid_set < string_done < valid_store:
        fail("A989 w28 string snapshot validation/publication order regressed")
    string_source_offsets = re.findall(
            r'lw      \$t3, 0x([0-9A-F]+)\(\$t5\)',
            target_helper[string_range:string_done])
    if tuple(string_source_offsets) != string_offsets or \
            target_helper.count('BRIDGE_VALIDATE $t5, 0x40, 3f') != 1 or \
            target_helper.count(
                'sw      $t3, %lo(zeroCtrlPafA989W28BytesValid)') != 1 or \
            '0x40($t5)' in target_helper:
        fail("A989 w28 string snapshot reads outside the fixed 0x40 bytes")
    pair_specs = (('00', '00', '04', '4', '5'),
            ('0C', '0C', '10', '6', '7'))
    pair_ends = []
    pair_search = string_done
    for pair, pointer_offset, length_offset, failure_label, success_label in \
            pair_specs:
        pair_valid_clear = target_helper.find(
                'sw      $zero, %lo(zeroCtrlPafA989Pair' + pair + 'Valid)',
                pair_search)
        pair_pointer_load = target_helper.find(
                'lw      $t5, 0x' + pointer_offset + '($t7)', pair_valid_clear)
        pair_pointer_store = target_helper.find(
                'sw      $t5, %lo(zeroCtrlPafA989Pair' + pair + 'Ptr)',
                pair_pointer_load)
        pair_length_load = target_helper.find(
                'lw      $t4, 0x' + length_offset + '($t7)', pair_pointer_store)
        pair_length_store = target_helper.find(
                'sw      $t4, %lo(zeroCtrlPafA989Pair' + pair + 'Len)',
                pair_length_load)
        pair_zero = target_helper.find(
                'beqz    $t4, ' + success_label + 'f', pair_length_store)
        pair_bound = target_helper.find('sltiu   $t2, $t4, 0x40', pair_zero)
        pair_bound_fail = target_helper.find(
                'beqz    $t2, ' + failure_label + 'f', pair_bound)
        pair_null = target_helper.find(
                'beqz    $t5, ' + failure_label + 'f', pair_bound_fail)
        pair_align = target_helper.find('andi    $t2, $t5, 3', pair_null)
        pair_align_fail = target_helper.find(
                'bnez    $t2, ' + failure_label + 'f', pair_align)
        pair_range = target_helper.find(
                'BRIDGE_VALIDATE $t5, 0x40, ' + failure_label + 'f',
                pair_align_fail)
        pair_loads = [target_helper.find(
                'lw      $t3, 0x' + offset + '($t5)', pair_range)
                for offset in string_offsets]
        pair_stores = [target_helper.find(
                'sw      $t3, %lo(zeroCtrlPafA989Pair' + pair + 'Data' +
                    offset + ')', pair_loads[index])
                for index, offset in enumerate(string_offsets)]
        pair_success = target_helper.find('\n' + success_label + ':\n',
                pair_stores[-1])
        pair_valid_set = target_helper.find(
                'sw      $t3, %lo(zeroCtrlPafA989Pair' + pair + 'Valid)',
                pair_success)
        pair_failure = target_helper.find('\n' + failure_label + ':\n',
                pair_valid_set)
        if not 0 <= pair_valid_clear < pair_pointer_load < pair_pointer_store < \
                pair_length_load < pair_length_store < pair_zero < pair_bound < \
                pair_bound_fail < pair_null < pair_align < pair_align_fail < \
                pair_range or any(pos < 0 for pos in pair_loads) or \
                any(pos < 0 for pos in pair_stores) or \
                any(not pair_loads[index] < pair_stores[index] <
                    (pair_loads[index + 1] if index + 1 < len(pair_loads) else
                        pair_success) for index in range(len(pair_loads))) or \
                not pair_stores[-1] < pair_success < pair_valid_set < pair_failure:
            fail("A989 pair" + pair + " validation/publication order regressed")
        pair_source_offsets = re.findall(
                r'lw      \$t3, 0x([0-9A-F]+)\(\$t5\)',
                target_helper[pair_range:pair_success])
        if tuple(pair_source_offsets) != string_offsets or \
                target_helper.count('BRIDGE_VALIDATE $t5, 0x40, ' +
                    failure_label + 'f') != 1 or \
                target_helper.count('sw      $t3, %lo(zeroCtrlPafA989Pair' +
                    pair + 'Valid)') != 1 or \
                '0x40($t5)' in target_helper[pair_range:pair_success]:
            fail("A989 pair" + pair + " capture exceeds its fixed source window")
        pair_ends.append(pair_failure)
        pair_search = pair_failure
    if not string_done < pair_ends[0] < pair_ends[1] < valid_store:
        fail("A989 optional pair failures do not preserve later captures")
    extra_offsets = ('18', '1C', '20', '24')
    extra_symbols = ('zeroCtrlPafA989DependencyW18',
            'zeroCtrlPafA989DependencyW1C', 'zeroCtrlPafA989DependencyW20',
            'zeroCtrlPafA989DependencyW24')
    extra_loads = [target_helper.find(
            'lw      $t3, 0x' + offset + '($t7)', pair_ends[1])
            for offset in extra_offsets]
    extra_stores = [target_helper.find(
            'sw      $t3, %lo(' + symbol + ')', extra_loads[index])
            for index, symbol in enumerate(extra_symbols)]
    if any(pos < 0 for pos in extra_loads + extra_stores) or \
            extra_loads != sorted(extra_loads) or \
            any(not extra_loads[index] < extra_stores[index] <
                (extra_loads[index + 1] if index + 1 < len(extra_loads) else
                    valid_store) for index in range(len(extra_loads))) or \
            not pair_ends[1] < extra_loads[0] < extra_stores[-1] < valid_store:
        fail("A989 direct-extra capture/publication order regressed")
    for offset, symbol in zip(extra_offsets, extra_symbols):
        if target_helper.count('lw      $t3, 0x' + offset + '($t7)') != 1 or \
                target_helper.count('sw      $t3, %lo(' + symbol + ')') != 1:
            fail("A989 direct-extra field is not captured exactly once")
    loaded_offsets = re.findall(r'lw      \$t3, 0x([0-9A-F]+)\(\$t7\)',
            target_helper[dependency_range:snapshot_done])
    if tuple(loaded_offsets) != direct_offsets + extra_offsets:
        fail("A989 synchronous dependency capture reads unexpected fields")
    if '$gp' in target_helper:
        fail("completed natural-GP capture remains in the A989 helper")
    if any(token in target_helper for token in ('jal ', 'jalr', 'sw      $ra',
            'sw      $a2', 'sw      $a3', 'move    $a')):
        fail("A989 synchronous helper calls code or changes Sony-visible state")
    trace_hit_load = target_helper.find(
            'lw      $t1, %lo(zeroCtrlVsh5704RegistrationTraceHits)')
    trace_hit_gate = target_helper.find('beqz    $t1, 1f', trace_hit_load)
    node_guard = target_helper.find('bnez    $t1, 1f')
    node_store = target_helper.find('sw      $a0, %lo(zeroCtrlPafA989TargetNode)')
    exact_publish = target_helper.rfind(
            'sw      $t1, %lo(zeroCtrlPafA989TargetTraceExactHits)')
    if not 0 <= trace_hit_load < trace_hit_gate < node_guard < node_store < \
            dependency_load < snapshot_done < exact_publish or \
            target_helper.count('bne     $t4, $t5, 1f') != 2:
        fail("A989 target tuple is not first-match-only and publication ordered")
    if 'zeroCtrlInstallPafA989TargetTrace' in home_request:
        fail("HOME installs the synchronous A989 target trace")
    if 'paf_a989_target_trace_registered' not in module_start or \
            'zeroCtrlInstallPafA989TargetTrace();' not in module_start:
        fail("OnModuleStart no longer retries the synchronous A989 trace")
    if module_start.find('zeroCtrlInstallPafA989TargetTrace();') > \
            module_start.find('zeroCtrlInstallVsh5704RegistrationTrace();'):
        fail("OnModuleStart can install VSH+5704 before its consumer capture")
    user_target_register = user.find(
            'zeroCtrlRegisterPafA989TargetTrace(&pafA989TargetTraceRegistration)')
    user_vsh_register = user.find(
            'zeroCtrlRegisterVsh5704Trace(&vsh5704TraceRegistration)')
    if not 0 <= user_target_register < user_vsh_register:
        fail("user registration can expose VSH+5704 before consumer capture")
    if '[psp1000-functional-314a4-bridge]' not in writer:
        fail("functional bridge telemetry is missing")
    if '[psp1000-functional-314a4-livein]' not in writer or \
            'blocker_domain=%u' not in writer or \
            'blocker_off=0x%X' not in writer or 'blocker_arg=%u' not in writer:
        fail("functional bridge live-in evidence is missing")
    livein_line = writer[writer.find('livein[0] ='):
            writer.find('state[0] = slide_diag.bridge_validation')]
    for index, token in enumerate((
            'slide_diag.bridge_livein_validation',
            'slide_diag.bridge_livein_arg[0]',
            'slide_diag.bridge_livein_arg[1]',
            'slide_diag.bridge_livein_arg[2]',
            'slide_diag.bridge_livein_arg[3]',
            'slide_diag.bridge_livein_blocker_domain',
            'slide_diag.bridge_livein_blocker_call',
            'slide_diag.bridge_livein_blocker_arg',
            'slide_diag.bridge_livein_blocker_reason',
            'slide_diag.bridge_livein_blocker_taint')):
        if 'livein[' + str(index) + '] = ' + token not in livein_line:
            fail("functional bridge live-in telemetry omits field " + token)
    livein_compare = livein_line.find(
            'memcmp(livein, observed_functional_bridge_livein')
    livein_copy = livein_line.find(
            'memcpy(observed_functional_bridge_livein, livein', livein_compare)
    livein_emit = livein_line.find('zeroCtrlDiagnosticsText(line)', livein_copy)
    if not 0 <= livein_compare < livein_copy < livein_emit:
        fail("functional live-in telemetry is not changed-only")
    if 'bridge_livein_written' in kernel:
        fail("one-shot live-in telemetry gate suppresses later proof evidence")
    for token in ('enum ZeroCtrlBridgeBlockerReason',
            'bridge_livein_blocker_prev_word', 'bridge_livein_blocker_word',
            'bridge_livein_blocker_next_word',
            '[psp1000-functional-314a4-blocker]',
            'prev=0x%08X', 'word=0x%08X', 'next=0x%08X',
            'reason=%u', 'taint=0x%08X', 'arg=%u'):
        if token not in kernel:
            fail("functional blocker evidence lacks " + token)
    blocker_line = writer[writer.find('blocker[0] ='):
            writer.find('state[0] = slide_diag.bridge_validation')]
    blocker_compare = blocker_line.find(
            'memcmp(blocker, observed_functional_bridge_blocker')
    blocker_copy = blocker_line.find(
            'memcpy(observed_functional_bridge_blocker, blocker', blocker_compare)
    blocker_emit = blocker_line.find('zeroCtrlDiagnosticsText(line)', blocker_copy)
    if not 0 <= blocker_compare < blocker_copy < blocker_emit:
        fail("functional blocker telemetry is not changed-only")
    if 'blocker[8]' in blocker_line or 'blocker_code' in blocker_line:
        fail("functional blocker telemetry exceeds three local code words")
    install_line = re.search(
            r'"\[psp1000-functional-314a4-install\][\s\S]{0,360}?'
            r'"validation=%u install=%u cache_sync=%u\\n"', writer)
    if not install_line:
        fail("functional bridge install-stage telemetry is missing or oversized")
    bridge_line = re.search(
            r'"\[psp1000-functional-314a4-bridge\][\s\S]{0,460}?'
            r'"consumed=%u reject_object=0x%08X\\n"',
            writer)
    if not bridge_line:
        fail("functional bridge telemetry is incomplete or oversized")
    if 'functional_gp_probe_written' in writer or \
            '[psp1000-functional-314a4-gp-probe]' in writer or \
            'snapshot_base + 0x11C' in writer or \
            'snapshot_base + 0x120' in writer:
        fail("completed GP-probe telemetry remains in the writer")
    constructed0_probe_marker = writer.find(
            '[psp1000-functional-314a4-constructed0-probe]')
    constructed0_probe_start = writer.rfind(
            'if ((state[9] == 5 || state[9] == 11) &&', 0,
            constructed0_probe_marker)
    constructed0_probe_end = writer.find('zeroCtrlDiagnosticsText(line);',
            constructed0_probe_marker)
    constructed0_probe_writer = writer[
            constructed0_probe_start:constructed0_probe_end]
    for token in ('!functional_constructed0_probe_written',
            'unsigned int result = state[12]',
            'result != 0', '(result & 3) == 0',
            'zeroCtrlPsp1000BridgeUserRangeValid(',
            'result, 4, lower, upper',
            '[psp1000-functional-314a4-constructed0-probe] ',
            'reject=%u result=0x%08X nonzero=%u aligned=%u ',
            'user_range=%u attempts=%u stage0_calls=%u ',
            'stage1_calls=%u',
            'state[9]', 'state[5], state[6], state[7]'):
        if token not in constructed0_probe_writer:
            fail("constructed0-probe telemetry lacks " + token)
    if constructed0_probe_start < 0 or \
            constructed0_probe_end < constructed0_probe_marker or \
            writer.count('int functional_constructed0_probe_written = 0;') != 1 or \
            'functional_alloc_probe_written' in writer or \
            '[psp1000-functional-314a4-alloc-probe]' in writer or \
            'state[9] == 13' in writer or \
            any(token in constructed0_probe_writer for token in
                ('_lw(', '_lb(', '_lbu(', 'sceKernelFindModuleByAddress')):
        fail("constructed0-probe telemetry dereferences or over-classifies result")
    service_start = kernel.find('static void zeroCtrlServiceFunctionalMilestone(void) {')
    service_end = kernel.find('\nstatic int zeroCtrlCreateSlideDiagnosticsThread',
            service_start)
    milestone_service = kernel[service_start:service_end]
    committed = milestone_service.find('zeroCtrlDiagnosticsTextCommitted(line)')
    ack_store = milestone_service.find(
            '_sw(milestone, slide_diag.bridge_milestone_ack_addr)', committed)
    ack_sync = milestone_service.find('sceKernelDcacheWritebackInvalidateRange(',
            ack_store)
    if not 0 <= committed < ack_store < ack_sync or \
            'if (zeroCtrlDiagnosticsTextCommitted(line)) {' not in \
                milestone_service or \
            milestone_service.count(
                '_sw(milestone, slide_diag.bridge_milestone_ack_addr)') != 1:
        fail("milestone persistence does not precede ACK store/cache sync")
    for token in ('[psp1000-step] seq=%u phase=%s',
            'request_observed', 'validation_complete', 'shadow_complete',
            'constructed0_enter_armed',
            '[psp1000-step] seq=5 phase=constructed0_return',
            '[psp1000-final] phase=%s', 'post_validation',
            'pre_constructed0_reject'):
        if token not in milestone_service:
            fail("compact milestone service lacks " + token)
    logger_write_start = logger.find('static int zeroCtrlDiagnosticsWrite(')
    logger_write_end = logger.find('\nvoid zeroCtrlDiagnosticsText(',
            logger_write_start)
    logger_write = logger[logger_write_start:logger_write_end]
    for token in ('if (!diagnostics_enabled)', 'length = strlen(text)',
            'written = sceIoWrite(fd, text, length)',
            'closed = sceIoClose(fd)',
            'return written == length && closed >= 0'):
        if token not in logger_write:
            fail("committed diagnostic writer lacks " + token)
    if 'int zeroCtrlDiagnosticsTextCommitted(const char *text)' not in logger or \
            'int zeroCtrlDiagnosticsTextCommitted(const char *text);' not in \
                logger_header:
        fail("committed diagnostic API is missing")
    compact_gate = writer.find(
            'if (slide_diag.functional_enabled && !slide_diag.diagnostics_verbose)')
    compact_continue = writer.find('continue;', compact_gate)
    first_forensic = writer.find('zeroCtrlWriteSlideCheckpoints(&written)')
    compact_path = writer[compact_gate:compact_continue]
    for token in ('[psp1000-ready]', '[psp1000-request]',
            'zeroCtrlServiceFunctionalMilestone()',
            'memcmp(request, compact_request, sizeof(request))',
            'slide_diag.functional_runtime_registration_valid',
            'slide_diag.functional_runtime_valid_addr != 0',
            '(slide_diag.functional_runtime_valid_addr & 3) == 0',
            'zeroCtrlReadHelperCounter(',
            'slide_diag.functional_runtime_valid_addr) != 0',
            'runtime, retained',
            'sceKernelDelayThread(SLIDE_OBSERVATION_POLL_US);',
            'elapsed += SLIDE_OBSERVATION_POLL_US;'):
        if token not in compact_path:
            fail("compact diagnostics path lacks " + token)
    if not 0 <= compact_gate < compact_continue < first_forensic or \
            any(token in compact_path for token in
                ('-code]', 'zeroCtrlWriteConstructed0Dependency',
                 'zeroCtrlWriteFunctionalClockPathAnalysis')):
        fail("compact path reaches forensic code maps or lacks early routing")
    if 'SLIDE_POLL_INTERVAL_US' in kernel:
        fail("compact diagnostics use undefined SLIDE_POLL_INTERVAL_US")
    ready_format = compact_path[compact_path.find('[psp1000-ready]'):
            compact_path.find('compact_ready_written = 1')]
    if 'slide_diag.functional_request_armed' in ready_format:
        fail("compact ready runtime field uses request-armed state")
    if 'if (slide_diag.functional_enabled)\n            zeroCtrlServiceFunctionalMilestone();' \
            not in writer[compact_continue:first_forensic]:
        fail("verbose writer does not service durable milestone ACKs")
    if 'PSP1000Diagnostics = Enabled' not in sample_config or \
            'PSP1000DiagnosticsVerbose = Disabled' not in sample_config or \
            '"PSP1000DiagnosticsVerbose", "Disabled"' not in kernel:
        fail("compact-by-default diagnostics configuration regressed")
    trace_line = re.search(
            r'"\[psp1000-vsh5704-registration-trace\][\s\S]{0,280}?'
            r'"original_target_off=0x3F568\\n"', writer)
    if not trace_line:
        fail("VSH+5704 changed-only hit telemetry is missing or oversized")
    reject2_start = writer.find(
            'if (slide_diag.bridge_validation == 1 &&')
    reject2_end = writer.find('\n            }\n', reject2_start)
    reject2_writer = writer[reject2_start:reject2_end]
    for token in ('slide_diag.bridge_install == 1', 'state[9] == 2',
            'state[12] != 0',
            'zeroCtrlPsp1000BridgeUserRangeValid(object,',
            '0x1C, lower, upper)',
            'zeroCtrlPsp1000BridgeUserRangeValid(inner,',
            '0x10, lower, upper)',
            '_lw(object + 0x00)', '_lw(object + 0x04)',
            '_lw(object + 0x08)', '_lw(object + 0x0C)',
            '_lw(object + 0x14)', '_lw(object + 0x18)',
            '_lw(inner + 0x04)', '_lw(inner + 0x0C)',
            'slide_diag.bridge_constructed0',
            'slide_diag.bridge_constructed1', 'slide_diag.bridge_callback',
            'memcmp(reject2, observed_functional_bridge_reject2',
            '[psp1000-functional-314a4-reject2-object]',
            '[psp1000-functional-314a4-reject2-inner]'):
        if token not in reject2_writer:
            fail("reject-2 bounded snapshot lacks " + token)
    if 'for (' in reject2_writer or 'while (' in reject2_writer:
        fail("reject-2 diagnostics add an arbitrary-memory scan")
    root_marker = writer.find('[psp1000-a989-root-state]')
    root_start = writer.rfind(
            'if (slide_diag.bridge_validation == 1 &&', 0, root_marker)
    root_end = writer.find('\n                }\n', root_marker)
    root_writer = writer[root_start:root_end]
    for token in ('zeroCtrlVshModuleRangeValid(paf,',
            'slide_diag.bridge_root_slot, 4)',
            'zeroCtrlPsp1000BridgeUserRangeValid(header, 8,',
            'unsigned int node = _lw(header + 4)', 'node == header',
            'node != header',
            'zeroCtrlPsp1000BridgeUserRangeValid(node, 8,',
            'unsigned int outer = _lw(node + 0x04)',
            'zeroCtrlPsp1000BridgeUserRangeValid(outer,',
            '0x1C, lower, upper)', '_lw(outer + 0x00)',
            '_lw(outer + 0x04)', '_lw(outer + 0x08)',
            '_lw(outer + 0x0C)', '_lw(outer + 0x14)',
            '_lw(outer + 0x18)',
            'inner, 0x10, lower, upper)', '_lw(inner + 0x0C)',
            'f08 == 0xFFFFFFFF', 'f0c == 0xFFFFFFFF', 'f18 == 0',
            'memcmp(root_state, observed_a989_root_state',
            '[psp1000-a989-root-state]'):
        if token not in root_writer:
            fail("bounded A989 root-state classification lacks " + token)
    if 'for (' in root_writer or 'while (' in root_writer:
        fail("A989 root-state diagnostic walks or scans the root list")
    for token in ('if (a989_target_node != 0)',
            'current_node == a989_target_node',
            'zeroCtrlPsp1000BridgeUserRangeValid(',
            'a989_target_node, 8, lower, upper)',
            '_lw(a989_target_node + 0x04)',
            'a989_target_outer, 0x1C, lower, upper)',
            '_lw(a989_target_outer + 0x00)',
            '_lw(a989_target_outer + 0x04)',
            '_lw(a989_target_outer + 0x08)',
            '_lw(a989_target_outer + 0x0C)',
            '_lw(a989_target_outer + 0x14)',
            '_lw(a989_target_outer + 0x18)',
            'a989_target_inner, 0x10, lower, upper)',
            '_lw(a989_target_inner + 0x04)',
            '_lw(a989_target_inner + 0x0C)',
            'memcmp(life, observed_a989_target_life',
            '[psp1000-a989-target-life]',
            '[psp1000-a989-target-life-inner]'):
        if token not in root_writer:
            fail("latched A989 target lifetime evidence lacks " + token)
    if 'a989_target_node = node' in root_writer or \
            '[psp1000-a989-target-latch]' in root_writer:
        fail("asynchronous root polling can still create the A989 target")
    if 'a989_target_dependency =' in root_writer:
        fail("asynchronous root polling can create the A989 dependency")
    capture_marker = writer.find('[psp1000-a989-target-capture]')
    capture_start = writer.rfind(
            'if (slide_diag.paf_a989_target_trace_registered)', 0,
            capture_marker)
    capture_end = writer.find('\n                }\n', capture_marker)
    capture_writer = writer[capture_start:capture_end]
    for token in ('paf_a989_target_trace_scalar[0]',
            'paf_a989_target_trace_scalar[1]', 'capture[5] != 0',
            'a989_target_node == 0',
            'paf_a989_target_trace_scalar[2]',
            'paf_a989_target_trace_scalar[3]',
            'paf_a989_target_trace_scalar[4]',
            '[psp1000-paf-a989-target-trace]',
            '[psp1000-a989-target-capture]'):
        if token not in capture_writer:
            fail("writer target is not seeded solely by synchronous capture: " +
                    token)
    if 'unsigned int a989_target_dependency = 0;' not in writer or \
            'a989_target_dependency' in kernel[:writer_start] or \
            'slide_diag.a989_target_dependency' in kernel:
        fail("A989 dependency is not writer-local diagnostic state")
    for token in ('a989_target_inner, 0x10, lower, upper)',
            '_lw(a989_target_inner + 0x0C)',
            'slide_diag.bridge_callback',
            'a989_target_dependency =',
            '_lw(a989_target_inner + 0x08)',
            'a989_target_dependency, 0x10,',
            '[psp1000-a989-dependency-capture]',
            '[psp1000-a989-dependency-capture-missed]'):
        if token not in capture_writer:
            fail("synchronous dependency capture lacks " + token)
    capture_gate = capture_writer.find(
            'if (capture[5] != 0 && a989_target_node == 0)')
    inner_range = capture_writer.find(
            'a989_target_inner, 0x10, lower, upper)', capture_gate)
    callback_read = capture_writer.find(
            '_lw(a989_target_inner + 0x0C)', inner_range)
    callback_match = capture_writer.find(
            'slide_diag.bridge_callback', callback_read)
    dependency_assign = capture_writer.find(
            'a989_target_dependency =', callback_match)
    dependency_read = capture_writer.find(
            '_lw(a989_target_inner + 0x08)', dependency_assign)
    if not 0 <= capture_gate < inner_range < callback_read < callback_match < \
            dependency_assign < dependency_read:
        fail("dependency is read before bounded captured-inner callback proof")
    if len(re.findall(r'(?<!unsigned int )a989_target_dependency\s*=',
            writer)) != 1:
        fail("captured A989 dependency can be assigned more than once")
    snapshot_marker = capture_writer.find(
            '[psp1000-a989-dependency44-snapshot]')
    snapshot_start = capture_writer.rfind(
            'if (exact_dependency_capture &&', 0, snapshot_marker)
    snapshot_writer = capture_writer[snapshot_start:]
    for token in ('int a989_dependency44_snapshot_written = 0;',
            'int exact_dependency_capture = 0;',
            'exact_dependency_capture = 1;',
            'if (exact_dependency_capture &&',
            '!a989_dependency44_snapshot_written',
            'a989_dependency44_snapshot_written = 1;',
            'a989_target_dependency, 0x4C,',
            '_lw(a989_target_dependency + 0x44)',
            '_lw(a989_target_dependency + 0x48)',
            'dependency48, 4, lower, upper)',
            'dependency44, 4, lower, upper)',
            'first = _lw(dependency44 + 0x00)',
            'first, 4, lower, upper)',
            'root = _lw(first + 0x00)',
            'root, 0x2E, lower, upper)',
            '_lb(root + 0x2D) & 0xFF',
            '[psp1000-a989-dependency44-snapshot] ',
            'validation=0\\n', 'validation=1 dependency=0x%08X',
            'w44=0x%08X w48=0x%08X',
            'w48_user_ptr=%u first_valid=%u',
            'first=0x%08X root_valid=%u',
            'root=0x%08X flag2d_valid=%u', 'flag2d=0x%02X'):
        if (token == 'int a989_dependency44_snapshot_written = 0;' and
                token not in writer) or (token !=
                'int a989_dependency44_snapshot_written = 0;' and
                token not in capture_writer):
            fail("authoritative dependency+0x44 snapshot lacks " + token)
    snapshot_authority = capture_writer.find(
            'exact_dependency_capture = 1;', dependency_read)
    snapshot_gate = capture_writer.find(
            'if (exact_dependency_capture &&', snapshot_authority)
    snapshot_once = capture_writer.find(
            'a989_dependency44_snapshot_written = 1;', snapshot_gate)
    snapshot_dependency_range = capture_writer.find(
            'a989_target_dependency, 0x4C,', snapshot_once)
    snapshot_w44 = capture_writer.find(
            '_lw(a989_target_dependency + 0x44)', snapshot_dependency_range)
    snapshot_w48 = capture_writer.find(
            '_lw(a989_target_dependency + 0x48)', snapshot_w44)
    snapshot_w48_class = capture_writer.find(
            'dependency48, 4, lower, upper)', snapshot_w48)
    snapshot_first_range = capture_writer.find(
            'dependency44, 4, lower, upper)', snapshot_w48_class)
    snapshot_first_read = capture_writer.find(
            'first = _lw(dependency44 + 0x00)', snapshot_first_range)
    snapshot_root_range = capture_writer.find(
            'first, 4, lower, upper)', snapshot_first_read)
    snapshot_root_read = capture_writer.find(
            'root = _lw(first + 0x00)', snapshot_root_range)
    snapshot_flag_range = capture_writer.find(
            'root, 0x2E, lower, upper)', snapshot_root_read)
    snapshot_flag_read = capture_writer.find(
            '_lb(root + 0x2D) & 0xFF', snapshot_flag_range)
    if not 0 <= dependency_read < snapshot_authority < snapshot_gate < snapshot_once < \
            snapshot_dependency_range < snapshot_w44 < snapshot_w48 < \
            snapshot_w48_class < snapshot_first_range < snapshot_first_read < \
            snapshot_root_range < snapshot_root_read < snapshot_flag_range < \
            snapshot_flag_read:
        fail("dependency+0x44 snapshot validation/dereference order regressed")
    if capture_writer.count('_lw(a989_target_dependency + 0x44)') != 1 or \
            capture_writer.count('_lw(a989_target_dependency + 0x48)') != 1 or \
            capture_writer.count('a989_dependency44_snapshot_written = 1;') != 1 or \
            '_lw(dependency48' in snapshot_writer or \
            snapshot_writer.count('_lb(root + ') != 1 or \
            '_lb(root + 0x2D)' not in snapshot_writer or \
            any(token in snapshot_writer for token in
                ('_sw(', '_sb(', 'sceKernelDcache', 'sceKernelIcache',
                 'slide_diag.a989_dependency44', 'sceKernelAlloc')):
        fail("dependency+0x44 snapshot is repeated, unsafe, or changes runtime state")
    if 'slide_diag.a989_dependency44' in kernel or \
            writer.count('int a989_dependency44_snapshot_written = 0;') != 1:
        fail("dependency+0x44 snapshot state is not writer-local")
    direct_sync_marker = capture_writer.find(
            '[psp1000-a989-dependency-direct-sync]')
    direct_sync_start = capture_writer.rfind(
            'if (capture[5] != 0 &&', 0, direct_sync_marker)
    direct_sync_end = capture_writer.find(
            'if (capture[5] != 0 && a989_target_node == 0)', direct_sync_marker)
    direct_sync_writer = capture_writer[direct_sync_start:direct_sync_end]
    for token in ('int a989_dependency_direct_sync_written = 0;',
            'if (capture[5] != 0 &&',
            '!a989_dependency_direct_sync_written',
            'a989_dependency_direct_sync_written = 1;',
            'paf_a989_target_trace_scalar[4] <= 0xFFFFFFFFU - 4',
            'paf_a989_target_trace_scalar[4] + 4',
            'unsigned int snapshot[71] = { 0 };',
            'snapshot_base + 0x00', 'snapshot[0] != 1',
            '[psp1000-a989-dependency-direct-sync] ',
            'validation=0\\n', 'validation=1 dependency=0x%08X',
            'w2c=0x%08X w34=0x%08X', 'w38=0x%08X w3c=0x%08X',
            'w40=0x%08X w54=0x%08X', 'w64=0x%08X w68=0x%08X',
            'w6c=0x%08X w28=0x%08X',
            'snapshot_base + 0x2C',
            '[psp1000-a989-dependency-w28] ',
            'validation=1 value=0x%08X', 'aligned=%u user_range=%u',
            'module_owned=1 module=%.27s', 'segment=%u segment_off=0x%X',
            'module_owned=0',
            '[psp1000-a989-dependency-w28-string] ',
            'validation=%u size=0x40',
            '[psp1000-a989-dependency-w28-string-code] ',
            'off=0x00 w0=%08X w1=%08X w2=%08X',
            'off=0x20 w0=%08X w1=%08X w2=%08X',
            '[psp1000-a989-dependency-pair00] ',
            '[psp1000-a989-dependency-pair00-code] ',
            '[psp1000-a989-dependency-pair0c] ',
            '[psp1000-a989-dependency-pair0c-code] ',
            'validation=%u ptr=0x%08X len=0x%08X',
            '[psp1000-a989-dependency-direct-extra] ',
            'validation=1 w18=0x%08X w1c=0x%08X ',
            'w20=0x%08X w24=0x%08X'):
        if (token.startswith('int ') and token not in writer) or \
                (not token.startswith('int ') and
                    token not in direct_sync_writer):
            fail("synchronous direct-dependency telemetry lacks " + token)
    for offset in range(0, 0x74, 4):
        token = 'snapshot_base + 0x%02X' % offset
        if len(re.findall(re.escape(token) + r'(?![0-9A-F])',
                    direct_sync_writer)) != 1:
            fail("direct-sync telemetry does not read exactly " + token)
    sync_valid_read = direct_sync_writer.find('snapshot_base + 0x00')
    sync_valid_gate = direct_sync_writer.find('snapshot[0] != 1', sync_valid_read)
    sync_data_first = direct_sync_writer.find('snapshot_base + 0x04', sync_valid_gate)
    sync_data_last = direct_sync_writer.find('snapshot_base + 0x2C', sync_data_first)
    string_valid_read = direct_sync_writer.find(
            'snapshot_base + 0x30', sync_data_last)
    string_data_gate = direct_sync_writer.find(
            'if (snapshot[12] == 1)', string_valid_read)
    string_last_read = direct_sync_writer.find(
            'snapshot_base + 0x70', string_data_gate)
    string_record = direct_sync_writer.find(
            '[psp1000-a989-dependency-w28-string] ', string_last_read)
    string_row0 = direct_sync_writer.find('off=0x00 w0=%08X', string_record)
    string_row1 = direct_sync_writer.find('off=0x20 w0=%08X', string_row0)
    string_row0_end = direct_sync_writer.find(
            'zeroCtrlDiagnosticsText(line);', string_row0)
    string_row1_end = direct_sync_writer.find(
            'zeroCtrlDiagnosticsText(line);', string_row1)
    if direct_sync_start < 0 or not 0 <= sync_valid_read < sync_valid_gate < \
            sync_data_first < sync_data_last < string_valid_read < \
            string_data_gate < string_last_read < string_record < string_row0 < \
            string_row1 or \
            'a989_target_inner + 0x0C' in direct_sync_writer or \
            'a989_target_dependency' in direct_sync_writer or \
            '_lw(' in direct_sync_writer or \
            'a989_dependency_direct_snapshot_written' in writer or \
            '[psp1000-a989-dependency-direct-snapshot]' in writer or \
            '_lw(a989_target_dependency + 0x28)' in writer or \
            '_lw(snapshot[11]' in direct_sync_writer or \
            not re.search(r'zeroCtrlPsp1000BridgeUserRangeValid\s*\(\s*'
                r'snapshot\[11\],\s*4,', direct_sync_writer) or \
            'sceKernelFindModuleByAddress(snapshot[11])' not in \
                direct_sync_writer or \
            'zeroCtrlModuleContainingSegment(owner,' not in direct_sync_writer:
        fail("direct-sync telemetry rereads mutable Sony dependency state")
    if direct_sync_writer.count(
                '[psp1000-a989-dependency-w28-string-code] ') != 2 or \
            direct_sync_writer.count('snapshot[13]') != 2 or \
            direct_sync_writer.count('snapshot[28]') != 2 or \
            tuple(re.findall(r'snapshot\[(\d+)\]',
                direct_sync_writer[string_row0:string_row0_end])) != \
                    tuple(str(index) for index in range(13, 21)) or \
            tuple(re.findall(r'snapshot\[(\d+)\]',
                direct_sync_writer[string_row1:string_row1_end])) != \
                    tuple(str(index) for index in range(21, 29)) or \
            '%s' in direct_sync_writer or 'strlen' in direct_sync_writer or \
            '_lb(' in direct_sync_writer or '_lbu(' in direct_sync_writer or \
            'snapshot_base + 0x11C' in direct_sync_writer:
        fail("w28 string telemetry scans, formats, or exceeds private snapshot")
    pair00_meta = [direct_sync_writer.find('snapshot_base + 0x%02X' % offset)
            for offset in (0x74, 0x78, 0x7C)]
    pair00_gate = direct_sync_writer.find(
            'if (snapshot[29] == 1 && snapshot[31] != 0)', pair00_meta[-1])
    pair00_reads = [direct_sync_writer.find(
            'snapshot_base + 0x%02X' % offset, pair00_gate)
            for offset in range(0x80, 0xC0, 4)]
    pair0c_meta = [direct_sync_writer.find('snapshot_base + 0x%02X' % offset,
            pair00_reads[-1]) for offset in (0xC0, 0xC4, 0xC8)]
    pair0c_gate = direct_sync_writer.find(
            'if (snapshot[48] == 1 && snapshot[50] != 0)', pair0c_meta[-1])
    pair0c_reads = [direct_sync_writer.find(
            'snapshot_base + 0x%02X' % offset, pair0c_gate)
            for offset in range(0xCC, 0x10C, 4)]
    pair00_record = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair00] ', pair0c_reads[-1])
    pair00_row0 = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair00-code] ', pair00_record)
    pair00_row1 = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair00-code] ', pair00_row0 + 1)
    pair0c_record = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair0c] ', pair00_row1)
    pair0c_row0 = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair0c-code] ', pair0c_record)
    pair0c_row1 = direct_sync_writer.find(
            '[psp1000-a989-dependency-pair0c-code] ', pair0c_row0 + 1)
    pair_rows = ((pair00_row0, pair00_row1, 32),
            (pair0c_row0, pair0c_row1, 51))
    if any(len(re.findall(re.escape('snapshot_base + 0x%02X' % offset) +
                r'(?![0-9A-F])', direct_sync_writer)) != 1
                for offset in range(0x74, 0x10C, 4)) or \
            any(pos < 0 for pos in pair00_meta + pair00_reads + pair0c_meta +
                pair0c_reads) or pair00_reads != sorted(pair00_reads) or \
            pair0c_reads != sorted(pair0c_reads) or \
            not pair00_meta[-1] < pair00_gate < pair00_reads[0] < \
                pair00_reads[-1] < pair0c_meta[0] or \
            not pair0c_meta[-1] < pair0c_gate < pair0c_reads[0] < \
                pair0c_reads[-1] < \
                pair00_record < pair00_row0 < pair00_row1 < pair0c_record < \
                pair0c_row0 < pair0c_row1 or \
            direct_sync_writer.count(
                '[psp1000-a989-dependency-pair00-code] ') != 2 or \
            direct_sync_writer.count(
                '[psp1000-a989-dependency-pair0c-code] ') != 2:
        fail("pair telemetry is not bounded to its private snapshot windows")
    for row0, row1, first_index in pair_rows:
        row0_end = direct_sync_writer.find('zeroCtrlDiagnosticsText(line);', row0)
        row1_end = direct_sync_writer.find('zeroCtrlDiagnosticsText(line);', row1)
        if tuple(re.findall(r'snapshot\[(\d+)\]',
                    direct_sync_writer[row0:row0_end])) != \
                tuple(str(index) for index in range(first_index,
                    first_index + 8)) or \
                tuple(re.findall(r'snapshot\[(\d+)\]',
                    direct_sync_writer[row1:row1_end])) != \
                tuple(str(index) for index in range(first_index + 8,
                    first_index + 16)):
            fail("pair telemetry does not expose exactly sixteen private words")
    if any(token in direct_sync_writer for token in
            ('_lw(snapshot[30]', '_lw(snapshot[49]',
             'zeroCtrlReadHelperCounter(snapshot[30]',
             'zeroCtrlReadHelperCounter(snapshot[49]')):
        fail("pair telemetry dereferences a captured runtime pointer")
    extra_offsets = (0x10C, 0x110, 0x114, 0x118)
    extra_reads = [direct_sync_writer.find(
            'snapshot_base + 0x%X' % offset) for offset in extra_offsets]
    extra_record = direct_sync_writer.find(
            '[psp1000-a989-dependency-direct-extra] ', pair0c_row1)
    extra_record_end = direct_sync_writer.find(
            'zeroCtrlDiagnosticsText(line);', extra_record)
    if any(pos < 0 for pos in extra_reads) or \
            extra_reads != sorted(extra_reads) or \
            not pair0c_reads[-1] < extra_reads[0] < extra_reads[-1] < \
                pair00_record < pair0c_row1 < extra_record < extra_record_end or \
            any(direct_sync_writer.count('snapshot_base + 0x%X' % offset) != 1
                for offset in extra_offsets) or \
            tuple(re.findall(r'snapshot\[(\d+)\]',
                direct_sync_writer[extra_record:extra_record_end])) != \
                    ('67', '68', '69', '70') or \
            'snapshot_base + 0x11C' in direct_sync_writer:
        fail("direct-extra telemetry is not bounded to four private words")
    dependency_marker = writer.find('[psp1000-a989-dependency-life]')
    dependency_start = writer.rfind(
            'if (a989_target_dependency != 0)', 0, dependency_marker)
    dependency_end = writer.find('\n                    }', dependency_marker)
    dependency_writer = writer[dependency_start:dependency_end]
    for token in ('a989_target_dependency, 0x10, lower, upper)',
            '_lw(a989_target_dependency + 0x00)',
            '_lw(a989_target_dependency + 0x04)',
            '_lw(a989_target_dependency + 0x08)',
            '_lw(a989_target_dependency + 0x0C)',
            'memcmp(dependency,', 'observed_a989_target_dependency',
            'memcpy(observed_a989_target_dependency, dependency',
            '[psp1000-a989-dependency-life]'):
        if token not in dependency_writer:
            fail("bounded changed-only A989 dependency lifetime lacks " + token)
    if dependency_writer.count('_lw(a989_target_dependency + ') != 4 or \
            'for (' in dependency_writer or 'while (' in dependency_writer or \
            'current_node' in dependency_writer or \
            'current_header_valid' in dependency_writer:
        fail("A989 dependency observation scans, chases, or depends on linkage")
    dependency_analysis_start = kernel.find(
            'static int zeroCtrlWriteConstructed0DependencyConsumer(void) {')
    dependency_analysis_end = kernel.find(
            '\nstatic ', dependency_analysis_start + 1)
    dependency_analysis = kernel[
            dependency_analysis_start:dependency_analysis_end]
    if dependency_analysis_start < 0 or dependency_analysis_end < 0:
        fail("constructed0 dependency loaded-code analysis is missing")
    for token in ('model != 0',
            'sceKernelDevkitVersion() != 0x06060110',
            '!slide_diag.functional_enabled',
            'slide_diag.bridge_validation != 1',
            'slide_diag.bridge_install != 1',
            '!zeroCtrlLoadedModuleMetadataValid(vsh)',
            '!zeroCtrlLoadedModuleMetadataValid(paf)',
            'slide_diag.bridge_callback != vsh->text_addr + 0x589C',
            'slide_diag.bridge_constructed1 != paf->text_addr + 0x34658',
            'slide_diag.bridge_constructed0 != paf->text_addr + 0x34610',
            'constructed0 = slide_diag.bridge_constructed0',
            '_lw(constructed0 + 0x14)',
            'allocation_target = zeroCtrlMipsJumpTarget(',
            '_lw(constructed0 + 0x24)',
            'target = zeroCtrlMipsJumpTarget(',
            'CONSTRUCTED0_DEPENDENCY_MAX_RANGE',
            'provenance[5].kind = ZERO_DEPENDENCY_BASE',
            '[psp1000-constructed0-dependency-consumer]',
            '[psp1000-constructed0-dependency-forward]',
            '[psp1000-constructed0-dependency-analysis]'):
        if token not in dependency_analysis:
            fail("constructed0 dependency analysis lacks " + token)
    for token in ('_lw(constructed0) != 0x27BDFFF0',
            '_lw(constructed0 + 0x04) != 0xAFB10004',
            '_lw(constructed0 + 0x08)',
            '_lw(constructed0 + 0x0C) != 0x240401D8',
            '_lw(constructed0 + 0x10) != 0xAFBF0008',
            '(_lw(constructed0 + 0x14) >> 26) != 3',
            '_lw(constructed0 + 0x18) != 0xAFB00000',
            '_lw(constructed0 + 0x1C)',
            '_lw(constructed0 + 0x20) != 0x8E250008',
            '(_lw(constructed0 + 0x24) >> 26) != 3',
            '_lw(constructed0 + 0x28)',
            '_lw(constructed0 + 0x2C) != 0xAE300004'):
        if token not in dependency_analysis:
            fail("constructed0 dependency prefix proof lacks " + token)
    for token in ('delay = _lw(pc + 4)', 'offset + 4, provenance',
            '"BRANCH"', 'reason = "BRANCH_LIKELY"',
            'reason = "INDIRECT_CALL"',
            'reason = call_forwarded ? "FORWARDED" : "DIRECT_CALL"',
            '"CONTROL_FLOW"', 'reason = "NO_RETURN"'):
        if token not in dependency_analysis:
            fail("dependency control-flow analysis is not fail-closed: " + token)
    likely_start = dependency_analysis.find(
            'if (opcode >= 0x14 && opcode <= 0x17) {')
    regimm_start = dependency_analysis.find(
            'if (opcode == 1) {', likely_start)
    generic_start = dependency_analysis.find(
            'if (opcode == 3 || opcode == 2 ||', regimm_start)
    likely_block = dependency_analysis[likely_start:regimm_start]
    regimm_block = dependency_analysis[regimm_start:generic_start]
    generic_end = dependency_analysis.find(
            'if (!zeroCtrlApplyConstructed0DependencyInstruction(word, offset,',
            generic_start)
    generic_control = dependency_analysis[generic_start:generic_end]
    if not 0 <= likely_start < regimm_start < generic_start < generic_end:
        fail("branch-likely is not separated before normal delay handling")
    for token in ('zeroCtrlBridgeExecutableRange(paf, pc + 4, 4)',
            'delay = _lw(pc + 4)', 'reason = "BRANCH_LIKELY"',
            'goto incomplete'):
        if token not in likely_block:
            fail("branch-likely fail-closed handling lacks " + token)
    if 'zeroCtrlApplyConstructed0DependencyInstruction' in likely_block or \
            any(token in likely_block for token in
                ('accesses++', 'chases++', 'forwards++')):
        fail("branch-likely delay slot mutates or reports provenance")
    regimm_decode = dependency_analysis.find(
            'unsigned int rt = (word >> 16) & 0x1F;')
    regimm_likely = dependency_analysis.find(
            'rt == 2 || rt == 3 || rt == 0x12 || rt == 0x13', regimm_start)
    regimm_likely_reason = dependency_analysis.find(
            'reason = "BRANCH_LIKELY"', regimm_likely)
    regimm_link = dependency_analysis.find(
            'rt == 0x10 || rt == 0x11', regimm_likely_reason)
    regimm_link_reason = dependency_analysis.find(
            'reason = "REGIMM_LINK"', regimm_link)
    regimm_unsupported = dependency_analysis.find(
            'if (rt != 0 && rt != 1)', regimm_link_reason)
    regimm_unsupported_reason = dependency_analysis.find(
            'reason = "UNSUPPORTED_REGIMM"', regimm_unsupported)
    if not 0 <= regimm_decode < likely_start < regimm_start <= regimm_likely < \
            regimm_likely_reason < regimm_link < regimm_link_reason < \
            regimm_unsupported < regimm_unsupported_reason < generic_start:
        fail("REGIMM classification/order is incomplete or ambiguous")
    for token in ('zeroCtrlBridgeExecutableRange(paf, pc + 4, 4)',
            'delay = _lw(pc + 4)', '(void)delay'):
        if regimm_block.count(token) < 2:
            fail("REGIMM likely/link evidence validation lacks " + token)
    if 'zeroCtrlApplyConstructed0DependencyInstruction' in regimm_block or \
            any(token in regimm_block for token in
                ('accesses++', 'chases++', 'forwards++')):
        fail("REGIMM likely/link/unsupported handling applies delay provenance")
    unsupported_regimm_block = dependency_analysis[
            regimm_unsupported:generic_start]
    if '_lw(pc + 4)' in unsupported_regimm_block or \
            'delay =' in unsupported_regimm_block:
        fail("unsupported REGIMM incorrectly treats pc+4 as a delay slot")
    ordinary_regimm = '(opcode == 1 && (rt == 0 || rt == 1))'
    if ordinary_regimm not in generic_control or \
            'opcode == 3 || opcode == 2 || opcode == 1 ||' in \
                dependency_analysis:
        fail("REGIMM can bypass explicit rt classification into normal delay")
    ordinary_membership = generic_control.find('(opcode >= 4 && opcode <= 7)')
    generic_delay = generic_control.find('delay = _lw(pc + 4)')
    generic_apply = generic_control.find(
            'zeroCtrlApplyConstructed0DependencyInstruction(delay,')
    branch_reason = generic_control.find('"BRANCH"', generic_apply)
    forward_loop = generic_control.find('for (arg = 4; arg <= 7; arg++)')
    if not 0 <= ordinary_membership < generic_delay < generic_apply < \
            branch_reason or not generic_apply < forward_loop:
        fail("ordinary branches/calls no longer apply delay slots before use")
    for token in ('opcode == 3', 'opcode == 2', ordinary_regimm,
            'function == 8', 'function == 9'):
        if token not in generic_control:
            fail("J/JAL/JR/JALR or ordinary REGIMM delay handling regressed")
    if 'zeroCtrlMipsBranchTarget' in dependency_analysis or \
            'QUEUE' in dependency_analysis or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyConsumer(') != 1:
        fail("dependency analyzer introduced dual-path or recursive CFG traversal")
    if any(token in dependency_analysis for token in
            ('_sw(', '_sb(', 'sceKernelDcache', 'sceKernelIcache',
             'a989_target_dependency', 'bridge_scalar[', 'for (candidate')):
        fail("constructed0 dependency analysis writes code/data or uses runtime objects")
    if '#define CONSTRUCTED0_DEPENDENCY_MAX_RANGE 0x200' not in kernel or \
            '#define CONSTRUCTED0_DEPENDENCY_MAX_ACCESS 32' not in kernel or \
            '#define CONSTRUCTED0_DEPENDENCY_MAX_CHASE 16' not in kernel or \
            '#define CONSTRUCTED0_DEPENDENCY_MAX_FORWARD 16' not in kernel:
        fail("constructed0 dependency analysis bounds changed")
    boundary_loop = dependency_analysis.find('for (offset = 0;')
    boundary_limit = dependency_analysis.find(
            'offset <= CONSTRUCTED0_DEPENDENCY_MAX_RANGE - 8;', boundary_loop)
    boundary_range = dependency_analysis.find(
            'zeroCtrlBridgeExecutableRange(paf, target + offset, 8)',
            boundary_limit)
    boundary_read = dependency_analysis.find(
            '_lw(target + offset) == 0x03E00008', boundary_range)
    boundary_set = dependency_analysis.find(
            'boundary = offset + 8;', boundary_read)
    no_return = dependency_analysis.find(
            'reason=NO_RETURN off=0x200', boundary_set)
    analysis_loop = dependency_analysis.find(
            'for (offset = 0; offset < boundary; offset += 4)', no_return)
    if not 0 <= boundary_loop < boundary_limit < boundary_range < \
            boundary_read < boundary_set < no_return < analysis_loop:
        fail("dependency return boundary does not keep jr/delay within 0x200")
    boundary_search = dependency_analysis[boundary_loop:no_return]
    provenance_pass = dependency_analysis[analysis_loop:]
    if 'offset < CONSTRUCTED0_DEPENDENCY_MAX_RANGE' in boundary_search or \
            'offset <= boundary' in provenance_pass or \
            'target + CONSTRUCTED0_DEPENDENCY_MAX_RANGE' in \
                dependency_analysis:
        fail("dependency analysis can read or process offset 0x200")
    if 'boundary = offset + 8;' not in boundary_search or \
            'if (boundary == 0)' not in boundary_search:
        fail("dependency analysis no longer fails closed without a full return")
    w28_forward_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyW28ForwardCalleeMap(')
    w28_forward_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyW28CalleeMap(',
            w28_forward_start)
    w28_forward = kernel[w28_forward_start:w28_forward_end]
    if w28_forward_start < 0 or w28_forward_end < 0:
        fail("constructed0 dependency w28 forward-callee map is missing")
    for token in ('w28_parent_target + 0x28,', '0xD0)',
            'w28_parent_target + 0x028) != 0x00809021',
            'for (offset = 0x02C; offset <= 0x0DC; offset += 4)',
            'word = _lw(w28_parent_target + offset)',
            'destination = zeroCtrlMipsGprWriteDestination(word)',
            'destination < 0 || destination == 18',
            'w28_parent_target + 0x0E0) != 0x02402021',
            'w28_parent_target + 0x0E4) != 0x8FA30024',
            'w28_parent_target + 0x0E8) != 0x8FA20020',
            'w28_parent_target + 0x0EC) != 0xAE030018',
            'w28_parent_target + 0x0F4) != 0xAE02001C',
            'call = _lw(w28_parent_target + 0x0F0)', '(call >> 26) != 3',
            'target = zeroCtrlMipsJumpTarget(w28_parent_target + 0x0F0, call)',
            'zeroCtrlModuleContainingSegment(paf, target, &segment, &remaining)',
            'segment != 0', 'target < paf->text_addr',
            'target - paf->text_addr != 0x13E3DC', 'remaining < 0x100',
            'zeroCtrlBridgeExecutableRange(paf, target, 0x100)',
            '[psp1000-constructed0-dependency-w28-forward-callee] ',
            'validation=0\\n', 'validation=1 parent_off=0x687E8',
            'source_off=0xF0', 'target=0x%08X target_off=0x%X size=0x100',
            'a0_source=dependency_w28_via_s2',
            '[psp1000-constructed0-dependency-w28-forward-callee-code]'):
        if token not in w28_forward:
            fail("dependency w28 forward-callee proof lacks " + token)
    forward_parent_range = w28_forward.find(
            'zeroCtrlBridgeExecutableRange(paf, w28_parent_target + 0x28,')
    forward_parent_size = w28_forward.find('0xD0)', forward_parent_range)
    forward_parent_first = w28_forward.find(
            '_lw(w28_parent_target + 0x028)', forward_parent_size)
    forward_scan = w28_forward.find(
            'for (offset = 0x02C; offset <= 0x0DC; offset += 4)',
            forward_parent_first)
    forward_scan_read = w28_forward.find(
            'word = _lw(w28_parent_target + offset)', forward_scan)
    forward_restore = w28_forward.find(
            '_lw(w28_parent_target + 0x0E0)', forward_scan_read)
    forward_call = w28_forward.find(
            'call = _lw(w28_parent_target + 0x0F0)', forward_restore)
    forward_decode = w28_forward.find(
            'target = zeroCtrlMipsJumpTarget(w28_parent_target + 0x0F0, call)',
            forward_call)
    forward_owner = w28_forward.find(
            'zeroCtrlModuleContainingSegment(paf, target, &segment, &remaining)',
            forward_decode)
    forward_relative = w28_forward.find(
            'target - paf->text_addr != 0x13E3DC', forward_owner)
    forward_range = w28_forward.find(
            'zeroCtrlBridgeExecutableRange(paf, target, 0x100)',
            forward_relative)
    forward_header = w28_forward.find(
            '[psp1000-constructed0-dependency-w28-forward-callee] ',
            forward_range)
    forward_loop = w28_forward.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)', forward_header)
    forward_first_read = w28_forward.find(
            '_lw(target + offset + 0x00)', forward_loop)
    forward_last_read = w28_forward.find(
            '_lw(target + offset + 0x1C)', forward_loop)
    if not 0 <= forward_parent_range < forward_parent_size < \
            forward_parent_first < forward_scan < forward_scan_read < \
            forward_restore < forward_call < forward_decode < forward_owner < \
            forward_relative < forward_range < forward_header < forward_loop < \
            forward_first_read < forward_last_read:
        fail("dependency w28 forward-callee validation/read order regressed")
    if w28_forward.count('_lw(target + offset + ') != 8 or \
            w28_forward.count(
                'for (offset = 0; offset <= 0xE0; offset += 0x20)') != 1 or \
            w28_forward.count('zeroCtrlMipsJumpTarget(') != 1 or \
            w28_forward.count(
                'zeroCtrlWriteConstructed0DependencyW28ForwardCalleeMap(') != 1 or \
            kernel.count(
                'zeroCtrlWriteConstructed0DependencyW28ForwardCalleeMap(') != 2 or \
            'target + offset + 0x20' in w28_forward or \
            'target + 0x100' in w28_forward or \
            any(token in w28_forward for token in
                ('a989_target_dependency', 'snapshot[', '_sw(', '_sb(',
                 'sceKernelDcache', 'sceKernelIcache', 'sceKernelStart',
                 'for (candidate')):
        fail("dependency w28 forward-callee map executes, writes, or exceeds bounds")
    w28_map_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyW28CalleeMap(')
    w28_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyW40ZeroTargetMap(',
            w28_map_start)
    w28_map = kernel[w28_map_start:w28_map_end]
    if w28_map_start < 0 or w28_map_end < 0:
        fail("constructed0 dependency w28 callee map is missing")
    for token in ('dependency_consumer_target + 0x67C, 0x1C',
            'dependency_consumer_target + 0x67C) != 0x8E640028',
            'dependency_consumer_target + 0x680) != 0x8E2701C0',
            'dependency_consumer_target + 0x684) != 0x26280058',
            'dependency_consumer_target + 0x688) != 0x24050001',
            'dependency_consumer_target + 0x68C) != 0x00003021',
            'dependency_consumer_target + 0x694) != 0x27A90040',
            'call = _lw(dependency_consumer_target + 0x690)',
            '(call >> 26) != 3',
            'target = zeroCtrlMipsJumpTarget(dependency_consumer_target + 0x690,',
            'zeroCtrlModuleContainingSegment(paf, target, &segment, &remaining)',
            'segment != 0', 'target < paf->text_addr',
            'target - paf->text_addr != 0x687E8', 'remaining < 0x100',
            'zeroCtrlBridgeExecutableRange(paf, target, 0x100)',
            '[psp1000-constructed0-dependency-w28-callee] validation=0',
            '[psp1000-constructed0-dependency-w28-callee] validation=1',
            'source_off=0x690 target=0x%08X target_off=0x%X size=0x100',
            'a0_source=dependency_w28 a1=1 a2=0',
            'a3_source=s1_plus_1c0 t0_source=s1_plus_58',
            't1_source=sp_plus_40',
            '[psp1000-constructed0-dependency-w28-callee-code]'):
        if token not in w28_map:
            fail("dependency w28 callee proof lacks " + token)
    w28_source_range = w28_map.find('zeroCtrlBridgeExecutableRange(paf,')
    w28_source_args = w28_map.find(
            'dependency_consumer_target + 0x67C, 0x1C', w28_source_range)
    w28_source_first = w28_map.find(
            '_lw(dependency_consumer_target + 0x67C)', w28_source_args)
    w28_source_last = w28_map.find(
            '_lw(dependency_consumer_target + 0x694)', w28_source_first)
    w28_call = w28_map.find(
            'call = _lw(dependency_consumer_target + 0x690)', w28_source_last)
    w28_decode = w28_map.find(
            'target = zeroCtrlMipsJumpTarget(dependency_consumer_target + 0x690,',
            w28_call)
    w28_owner = w28_map.find(
            'zeroCtrlModuleContainingSegment(paf, target, &segment, &remaining)',
            w28_decode)
    w28_relative = w28_map.find(
            'target - paf->text_addr != 0x687E8', w28_owner)
    w28_range = w28_map.find(
            'zeroCtrlBridgeExecutableRange(paf, target, 0x100)', w28_relative)
    w28_header = w28_map.find(
            '[psp1000-constructed0-dependency-w28-callee] validation=1',
            w28_range)
    w28_loop = w28_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)', w28_header)
    w28_first_read = w28_map.find('_lw(target + offset + 0x00)', w28_loop)
    w28_last_read = w28_map.find('_lw(target + offset + 0x1C)', w28_loop)
    w28_forward_call = w28_map.find(
            'zeroCtrlWriteConstructed0DependencyW28ForwardCalleeMap(paf, target);',
            w28_last_read)
    w28_success_return = w28_map.find('return;', w28_forward_call)
    if not 0 <= w28_source_range < w28_source_args < w28_source_first < \
            w28_source_last < w28_call < w28_decode < w28_owner < \
            w28_relative < w28_range < w28_header < w28_loop < \
            w28_first_read < w28_last_read < w28_forward_call < \
            w28_success_return:
        fail("dependency w28 callee validation/read order regressed")
    if w28_map.count('_lw(target + offset + ') != 8 or \
            w28_map.count(
                'for (offset = 0; offset <= 0xE0; offset += 0x20)') != 1 or \
            w28_map.count('zeroCtrlMipsJumpTarget(') != 1 or \
            'target + offset + 0x20' in w28_map or \
            'target + 0x100' in w28_map or '0x68A04' in w28_map or \
            kernel.count(
                'zeroCtrlWriteConstructed0DependencyW28CalleeMap(') != 2 or \
            any(token in w28_map for token in
                ('a989_target_dependency', '_sw(', '_sb(', 'sceKernelDcache',
                 'sceKernelIcache', 'sceKernelStart', 'for (candidate')):
        fail("dependency w28 callee map executes, writes, or exceeds bounds")
    w40_map_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyW40ZeroTargetMap(')
    w40_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyW2CNonzeroTargetMap(',
            w40_map_start)
    w40_map = kernel[w40_map_start:w40_map_end]
    if w40_map_start < 0 or w40_map_end < 0:
        fail("constructed0 dependency w40-zero target map is missing")
    for token in ('dependency_consumer_target + 0x27C, 0x30',
            'dependency_consumer_target + 0x27C) != 0x8E72003C',
            'dependency_consumer_target + 0x298) != 0x1640011A',
            'dependency_consumer_target + 0x29C) != 0xAE2001D0',
            'dependency_consumer_target + 0x2A0) != 0x8E620040',
            'dependency_consumer_target + 0x2A4) != 0x10400113',
            'delay = _lw(dependency_consumer_target + 0x2A8)',
            '(delay >> 26) != 0x0F', '((delay >> 16) & 0x1F) != 4',
            'dependency_w40_zero_target = zeroCtrlMipsBranchTarget(',
            'dependency_consumer_target + 0x2A4,',
            '_lw(dependency_consumer_target + 0x2A4)',
            'dependency_w40_zero_target < dependency_consumer_target',
            'dependency_w40_zero_target - dependency_consumer_target != 0x6F4',
            'zeroCtrlModuleContainingSegment(paf, dependency_w40_zero_target,',
            'segment != 0', 'remaining < 0x100',
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_zero_target,',
            '[psp1000-constructed0-dependency-w40-zero-target] validation=0',
            '[psp1000-constructed0-dependency-w40-zero-target] validation=1',
            'source_off=0x2A4 target=0x%08X target_off=0x%X',
            'consumer_off=0x6F4 delay=0x%08X size=0x100',
            '[psp1000-constructed0-dependency-w40-zero-code]'):
        if token not in w40_map:
            fail("dependency w40-zero target proof lacks " + token)
    w40_source_range = w40_map.find(
            'zeroCtrlBridgeExecutableRange(paf,')
    w40_source_args = w40_map.find(
            'dependency_consumer_target + 0x27C, 0x30', w40_source_range)
    w40_source_first = w40_map.find(
            '_lw(dependency_consumer_target + 0x27C)', w40_source_args)
    w40_source_last = w40_map.find(
            'delay = _lw(dependency_consumer_target + 0x2A8)', w40_source_first)
    w40_decode = w40_map.find(
            'dependency_w40_zero_target = zeroCtrlMipsBranchTarget(',
            w40_source_last)
    w40_decode_pc = w40_map.find(
            'dependency_consumer_target + 0x2A4,', w40_decode)
    w40_decode_word = w40_map.find(
            '_lw(dependency_consumer_target + 0x2A4)', w40_decode_pc)
    w40_relative = w40_map.find(
            'dependency_w40_zero_target - dependency_consumer_target != 0x6F4',
            w40_decode_word)
    w40_owner = w40_map.find(
            'zeroCtrlModuleContainingSegment(paf, dependency_w40_zero_target,',
            w40_relative)
    w40_range = w40_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_zero_target,',
            w40_owner)
    w40_range_size = w40_map.find('0x100)', w40_range)
    w40_header = w40_map.find(
            '[psp1000-constructed0-dependency-w40-zero-target] validation=1',
            w40_range_size)
    w40_loop = w40_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)', w40_header)
    w40_first_read = w40_map.find(
            '_lw(dependency_w40_zero_target + offset + 0x00)', w40_loop)
    w40_last_read = w40_map.find(
            '_lw(dependency_w40_zero_target + offset + 0x1C)', w40_loop)
    if not 0 <= w40_source_range < w40_source_args < w40_source_first < \
            w40_source_last < w40_decode < w40_decode_pc < w40_decode_word < \
            w40_relative < w40_owner < w40_range < w40_range_size < \
            w40_header < w40_loop < w40_first_read < w40_last_read:
        fail("dependency w40-zero target validation/read order regressed")
    w40_rows = w40_map[w40_loop:]
    if w40_rows.count('_lw(dependency_w40_zero_target + offset + ') != 8 or \
            w40_map.count(
                'for (offset = 0; offset <= 0xE0; offset += 0x20)') != 1 or \
            w40_map.count('zeroCtrlMipsBranchTarget(') != 1 or \
            w40_map.count(
                'dependency_w40_zero_target = zeroCtrlMipsBranchTarget(') != 1 or \
            'dependency_w40_zero_target + offset + 0x20' in w40_rows or \
            'dependency_w40_zero_target + 0x100' in w40_map or \
            re.search(r'delay\s*&\s*0xFFFF', w40_map) or \
            any(token in w40_map for token in
                ('0x35A24', 'a989_target_dependency',
                 'zeroCtrlMipsJumpTarget', '_sw(', '_sb(', 'sceKernelDcache',
                 'sceKernelIcache', 'for (candidate', 'consumer_target + 0x300',
                 'consumer_target + 0x6F0')):
        fail("dependency w40-zero map follows code, scans, or exceeds bounds")
    w2c_map_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyW2CNonzeroTargetMap(')
    w2c_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0Dependency44CalleeMap(',
            w2c_map_start)
    w2c_map = kernel[w2c_map_start:w2c_map_end]
    if w2c_map_start < 0 or w2c_map_end < 0:
        fail("constructed0 dependency w2c-nonzero target map is missing")
    for token in ('dependency_consumer_target + 0x2A4, 8',
            'dependency_consumer_target + 0x2A4) != 0x10400113',
            'delay = _lw(dependency_consumer_target + 0x2A8)',
            '(delay >> 26) != 0x0F', '((delay >> 16) & 0x1F) != 4',
            'dependency_w40_zero_target = zeroCtrlMipsBranchTarget(',
            'dependency_w40_zero_target - dependency_consumer_target != 0x6F4',
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_zero_target,',
            '0x10)',
            'fallback_load = _lw(dependency_w40_zero_target + 0x00)',
            '(fallback_load >> 26) != 0x23',
            '((fallback_load >> 21) & 0x1F) != 4',
            '((fallback_load >> 16) & 0x1F) != 2',
            'dependency_w40_zero_target + 0x04) != 0x8C43002C',
            'jump = _lw(dependency_w40_zero_target + 0x08)',
            '(jump >> 26) != 2',
            'dependency_w40_zero_target + 0x0C) != 0xAE23019C',
            'dependency_w40_rejoin_target = zeroCtrlMipsJumpTarget(',
            'dependency_w40_zero_target + 0x08,',
            '_lw(dependency_w40_zero_target + 0x08)',
            'dependency_w40_rejoin_target - dependency_consumer_target != 0x2B0',
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_rejoin_target,',
            '0x20)',
            'rejoin_load = _lw(dependency_w40_rejoin_target + 0x00)',
            '(rejoin_load >> 26) != 0x23',
            '((rejoin_load >> 21) & 0x1F) != 4',
            '((rejoin_load >> 16) & 0x1F) != 2',
            '(rejoin_load & 0xFFFF) != (fallback_load & 0xFFFF)',
            'dependency_w40_rejoin_target + 0x04) != 0x8E2401D4',
            'dependency_w40_rejoin_target + 0x08) != 0x8C450098',
            'dependency_w40_rejoin_target + 0x0C) != 0x14800109',
            'dependency_w40_rejoin_target + 0x10) != 0xAE2501C0',
            'dependency_w40_rejoin_target + 0x14) != 0x8E62002C',
            'dependency_w40_rejoin_target + 0x18) != 0x144000E7',
            'dependency_w40_rejoin_target + 0x1C) != 0x00000000',
            'dependency_w2c_nonzero_target = zeroCtrlMipsBranchTarget(',
            'dependency_consumer_target + 0x2C8,',
            '_lw(dependency_consumer_target + 0x2C8)',
            'dependency_w2c_nonzero_target - dependency_consumer_target != 0x668',
            'zeroCtrlModuleContainingSegment(paf, dependency_w2c_nonzero_target,',
            'segment != 0', 'remaining < 0x8C',
            'zeroCtrlBridgeExecutableRange(paf, dependency_w2c_nonzero_target,',
            '0x8C)',
            '[psp1000-constructed0-dependency-w2c-nonzero-target] validation=0',
            '[psp1000-constructed0-dependency-w2c-nonzero-target] validation=1',
            'source_off=0x2C8 target=0x%08X target_off=0x%X',
            'consumer_off=0x668 rejoin_off=0x2B0 end_before=0x6F4',
            'size=0x8C',
            '[psp1000-constructed0-dependency-w2c-nonzero-code]'):
        if token not in w2c_map:
            fail("dependency w2c-nonzero target proof lacks " + token)
    route_source_range = w2c_map.find(
            'zeroCtrlBridgeExecutableRange(paf,')
    route_source_args = w2c_map.find(
            'dependency_consumer_target + 0x2A4, 8', route_source_range)
    route_branch_read = w2c_map.find(
            '_lw(dependency_consumer_target + 0x2A4)', route_source_args)
    route_delay_read = w2c_map.find(
            'delay = _lw(dependency_consumer_target + 0x2A8)',
            route_branch_read)
    route_delay_shape = w2c_map.find(
            '((delay >> 16) & 0x1F) != 4', route_delay_read)
    trampoline_decode = w2c_map.find(
            'dependency_w40_zero_target = zeroCtrlMipsBranchTarget(',
            route_delay_shape)
    trampoline_range = w2c_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_zero_target,')
    trampoline_range_size = w2c_map.find('0x10)', trampoline_range)
    trampoline_first_read = w2c_map.find(
            '_lw(dependency_w40_zero_target + 0x00)', trampoline_range_size)
    trampoline_jump_read = w2c_map.find(
            'jump = _lw(dependency_w40_zero_target + 0x08)',
            trampoline_first_read)
    rejoin_decode = w2c_map.find(
            'dependency_w40_rejoin_target = zeroCtrlMipsJumpTarget(',
            trampoline_jump_read)
    rejoin_relative = w2c_map.find(
            'dependency_w40_rejoin_target - dependency_consumer_target != 0x2B0',
            rejoin_decode)
    rejoin_range = w2c_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_w40_rejoin_target,',
            rejoin_relative)
    rejoin_range_size = w2c_map.find('0x20)', rejoin_range)
    rejoin_first_read = w2c_map.find(
            '_lw(dependency_w40_rejoin_target + 0x00)', rejoin_range_size)
    rejoin_immediate_match = w2c_map.find(
            '(rejoin_load & 0xFFFF) != (fallback_load & 0xFFFF)',
            rejoin_first_read)
    rejoin_last_read = w2c_map.find(
            '_lw(dependency_w40_rejoin_target + 0x1C)',
            rejoin_immediate_match)
    w2c_decode = w2c_map.find(
            'dependency_w2c_nonzero_target = zeroCtrlMipsBranchTarget(',
            rejoin_last_read)
    w2c_relative = w2c_map.find(
            'dependency_w2c_nonzero_target - dependency_consumer_target != 0x668',
            w2c_decode)
    w2c_owner = w2c_map.find(
            'zeroCtrlModuleContainingSegment(paf, dependency_w2c_nonzero_target,',
            w2c_relative)
    w2c_range = w2c_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_w2c_nonzero_target,',
            w2c_owner)
    w2c_range_size = w2c_map.find('0x8C)', w2c_range)
    w2c_header = w2c_map.find(
            '[psp1000-constructed0-dependency-w2c-nonzero-target] validation=1',
            w2c_range_size)
    w2c_loop = w2c_map.find(
            'for (offset = 0; offset <= 0x60; offset += 0x20)', w2c_header)
    w2c_complete_first = w2c_map.find(
            '_lw(dependency_w2c_nonzero_target + offset + 0x00)', w2c_loop)
    w2c_complete_last = w2c_map.find(
            '_lw(dependency_w2c_nonzero_target + offset + 0x1C)', w2c_loop)
    w2c_partial = w2c_map.find('off=0x080 w0=%08X w1=%08X w2=%08X',
            w2c_complete_last)
    w2c_final_read = w2c_map.find(
            '_lw(dependency_w2c_nonzero_target + 0x88)', w2c_partial)
    w28_map_call = w2c_map.find(
            'zeroCtrlWriteConstructed0DependencyW28CalleeMap(paf,',
            w2c_final_read)
    w2c_success_return = w2c_map.find('return;', w28_map_call)
    if not 0 <= route_source_range < route_source_args < route_branch_read < \
            route_delay_read < route_delay_shape < trampoline_decode < \
            trampoline_range < trampoline_range_size < \
            trampoline_first_read < trampoline_jump_read < rejoin_decode < \
            rejoin_relative < rejoin_range < rejoin_range_size < \
            rejoin_first_read < rejoin_immediate_match < rejoin_last_read < \
            w2c_decode < w2c_relative < \
            w2c_owner < w2c_range < w2c_range_size < w2c_header < w2c_loop < \
            w2c_complete_first < w2c_complete_last < w2c_partial < \
            w2c_final_read < w28_map_call < w2c_success_return:
        fail("dependency w2c-nonzero validation/read order regressed")
    w2c_complete_rows = w2c_map[w2c_loop:w2c_partial]
    w2c_partial_row = w2c_map[w2c_partial:]
    if w2c_complete_rows.count(
                '_lw(dependency_w2c_nonzero_target + offset + ') != 8 or \
            w2c_map.count(
                'for (offset = 0; offset <= 0x60; offset += 0x20)') != 1 or \
            w2c_partial_row.count('_lw(dependency_w2c_nonzero_target + 0x') != 3 or \
            w2c_map.count('zeroCtrlMipsBranchTarget(') != 2 or \
            w2c_map.count('zeroCtrlMipsJumpTarget(') != 1 or \
            w2c_map.count(
                'zeroCtrlWriteConstructed0DependencyW28CalleeMap(') != 1 or \
            '0x8C825A34' in w2c_map or '0x8C825B34' in w2c_map or \
            re.search(r'delay\s*&\s*0xFFFF', w2c_map) or \
            'dependency_w2c_nonzero_target + 0x8C' in w2c_map or \
            'dependency_w2c_nonzero_target + 0x6F4' in w2c_map or \
            any(token in w2c_map for token in
                ('0x35A24', 'a989_target_dependency', '_sw(', '_sb(',
                 'sceKernelDcache', 'sceKernelIcache', 'for (candidate',
                 'dependency_consumer_target + 0x2D0',
                 'dependency_consumer_target + 0x667')):
        fail("dependency w2c-nonzero map follows code, duplicates, or exceeds bounds")
    dependency44_map_start = kernel.find(
            'static void zeroCtrlWriteConstructed0Dependency44CalleeMap(')
    dependency44_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyConsumerContinuation(',
            dependency44_map_start)
    dependency44_map = kernel[dependency44_map_start:dependency44_map_end]
    if dependency44_map_start < 0 or dependency44_map_end < 0:
        fail("constructed0 dependency+0x44 callee map is missing")
    for token in ('int destination;',
            'dependency_consumer_target + 0x1A8) != 0x262401A0',
            'dependency_consumer_target + 0x1AC) != 0x26650044',
            'for (offset = 0x1B0; offset <= 0x24C; offset += 4)',
            'destination = zeroCtrlMipsGprWriteDestination(word)',
            'destination < 0 || destination == 5',
            'word = _lw(dependency_consumer_target + 0x250)',
            '(word >> 26) != 3',
            '_lw(dependency_consumer_target + 0x254) != 0xAE20019C',
            'dependency44_callee_target = zeroCtrlMipsJumpTarget(',
            'dependency_consumer_target + 0x250,',
            '_lw(dependency_consumer_target + 0x250)',
            'zeroCtrlModuleContainingSegment(paf, dependency44_callee_target,',
            'segment != 0', 'remaining < 0x100',
            'zeroCtrlBridgeExecutableRange(paf, dependency44_callee_target,',
            '[psp1000-constructed0-dependency-44-callee] validation=0',
            '[psp1000-constructed0-dependency-44-callee] validation=1',
            'call_off=0x250 target=0x%08X target_off=0x%X size=0x100',
            '[psp1000-constructed0-dependency-44-callee-code]'):
        if token not in dependency44_map:
            fail("dependency+0x44 callee proof lacks " + token)
    dependency44_prefix_range = dependency44_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_consumer_target,')
    dependency44_prefix_size = dependency44_map.find(
            '0x258)', dependency44_prefix_range)
    dependency44_setup_a0 = dependency44_map.find(
            'dependency_consumer_target + 0x1A8) != 0x262401A0',
            dependency44_prefix_size)
    dependency44_setup_a1 = dependency44_map.find(
            'dependency_consumer_target + 0x1AC) != 0x26650044',
            dependency44_setup_a0)
    dependency44_live_loop = dependency44_map.find(
            'for (offset = 0x1B0; offset <= 0x24C; offset += 4)',
            dependency44_setup_a1)
    dependency44_live_read = dependency44_map.find(
            'word = _lw(dependency_consumer_target + offset)',
            dependency44_live_loop)
    dependency44_live_decode = dependency44_map.find(
            'destination = zeroCtrlMipsGprWriteDestination(word)',
            dependency44_live_read)
    dependency44_live_fail = dependency44_map.find(
            'destination < 0 || destination == 5', dependency44_live_decode)
    dependency44_call_read = dependency44_map.find(
            'word = _lw(dependency_consumer_target + 0x250)',
            dependency44_live_fail)
    dependency44_jal = dependency44_map.find(
            '(word >> 26) != 3', dependency44_call_read)
    dependency44_delay = dependency44_map.find(
            '_lw(dependency_consumer_target + 0x254) != 0xAE20019C',
            dependency44_jal)
    dependency44_decode = dependency44_map.find(
            'dependency44_callee_target = zeroCtrlMipsJumpTarget(',
            dependency44_delay)
    dependency44_decode_pc = dependency44_map.find(
            'dependency_consumer_target + 0x250,', dependency44_decode)
    dependency44_decode_word = dependency44_map.find(
            '_lw(dependency_consumer_target + 0x250)', dependency44_decode_pc)
    dependency44_owner = dependency44_map.find(
            'zeroCtrlModuleContainingSegment(paf, dependency44_callee_target,',
            dependency44_decode_word)
    dependency44_segment = dependency44_map.find(
            'segment != 0', dependency44_owner)
    dependency44_remaining = dependency44_map.find(
            'remaining < 0x100', dependency44_segment)
    dependency44_range = dependency44_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency44_callee_target,',
            dependency44_remaining)
    dependency44_range_size = dependency44_map.find(
            '0x100)', dependency44_range)
    dependency44_header = dependency44_map.find(
            '[psp1000-constructed0-dependency-44-callee] validation=1',
            dependency44_range_size)
    dependency44_loop = dependency44_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)',
            dependency44_header)
    dependency44_first_read = dependency44_map.find(
            '_lw(dependency44_callee_target + offset + 0x00)',
            dependency44_loop)
    dependency44_last_read = dependency44_map.find(
            '_lw(dependency44_callee_target + offset + 0x1C)',
            dependency44_loop)
    if not 0 <= dependency44_prefix_range < dependency44_prefix_size < \
            dependency44_setup_a0 < dependency44_setup_a1 < \
            dependency44_live_loop < dependency44_live_read < \
            dependency44_live_decode < dependency44_live_fail < \
            dependency44_call_read < dependency44_jal < dependency44_delay < \
            dependency44_decode < dependency44_decode_pc < \
            dependency44_decode_word < dependency44_owner < \
            dependency44_segment < dependency44_remaining < \
            dependency44_range < dependency44_range_size < \
            dependency44_header < dependency44_loop < \
            dependency44_first_read < dependency44_last_read:
        fail("dependency+0x44 callee derivation/range order regressed")
    dependency44_rows = dependency44_map[dependency44_loop:]
    if dependency44_rows.count(
                '_lw(dependency44_callee_target + offset + ') != 8 or \
            dependency44_map.count(
                'for (offset = 0; offset <= 0xE0; offset += 0x20)') != 1 or \
            dependency44_map.count('zeroCtrlMipsJumpTarget(') != 1 or \
            dependency44_map.count(
                'dependency44_callee_target = zeroCtrlMipsJumpTarget(') != 1 or \
            'dependency44_callee_target + offset + 0x20' in dependency44_rows or \
            'dependency44_callee_target + 0x100' in dependency44_map or \
            any(token in dependency44_map for token in
                ('0x35A24', 'zeroCtrlMipsBranchTarget',
                 'a989_target_dependency', 'a989_target_node',
                 'a989_target_outer', 'a989_target_inner', '_sw(', '_sb(',
                 'sceKernelDcache', 'sceKernelIcache', 'dependency+0x44')):
        fail("dependency+0x44 callee map follows code, uses runtime state, or writes")
    consumer_cont_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyConsumerContinuation(')
    consumer_cont_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyMap(',
            consumer_cont_start)
    consumer_cont = kernel[consumer_cont_start:consumer_cont_end]
    if consumer_cont_start < 0 or consumer_cont_end < 0:
        fail("constructed0 dependency consumer continuation is missing")
    for token in ('dependency_consumer_target + 0x1A8) != 0x262401A0',
            'dependency_consumer_target + 0x1AC) != 0x26650044',
            'for (offset = 0x1B0; offset <= 0x1FC; offset += 4)',
            'zeroCtrlMipsGprWriteDestination(',
            '_lw(dependency_consumer_target + offset)) == 5',
            'dependency_consumer_target + 0x200, 0x100',
            '[psp1000-constructed0-dependency-consumer-cont] ',
            'validation=0\\n',
            '[psp1000-constructed0-dependency-consumer-cont] validation=1',
            'start_off=0x200 size=0x100',
            '[psp1000-constructed0-dependency-consumer-cont-code]'):
        if token not in consumer_cont:
            fail("dependency consumer continuation proof lacks " + token)
    cont_prefix_range = consumer_cont.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_consumer_target,')
    cont_prefix_size = consumer_cont.find('0x200)', cont_prefix_range)
    cont_setup_a0 = consumer_cont.find(
            'dependency_consumer_target + 0x1A8) != 0x262401A0',
            cont_prefix_size)
    cont_setup_a1 = consumer_cont.find(
            'dependency_consumer_target + 0x1AC) != 0x26650044',
            cont_setup_a0)
    cont_liveness_loop = consumer_cont.find(
            'for (offset = 0x1B0; offset <= 0x1FC; offset += 4)',
            cont_setup_a1)
    cont_liveness_decode = consumer_cont.find(
            'zeroCtrlMipsGprWriteDestination(', cont_liveness_loop)
    cont_liveness_read = consumer_cont.find(
            '_lw(dependency_consumer_target + offset)', cont_liveness_decode)
    cont_liveness_a1 = consumer_cont.find('== 5', cont_liveness_read)
    cont_range = consumer_cont.find(
            'zeroCtrlBridgeExecutableRange(paf,', cont_liveness_a1)
    cont_range_args = consumer_cont.find(
            'dependency_consumer_target + 0x200, 0x100', cont_range)
    cont_header = consumer_cont.find(
            '[psp1000-constructed0-dependency-consumer-cont] validation=1',
            cont_range_args)
    cont_loop = consumer_cont.find(
            'for (offset = 0x200; offset <= 0x2E0; offset += 0x20)',
            cont_header)
    cont_first_read = consumer_cont.find(
            '_lw(dependency_consumer_target + offset + 0x00)', cont_loop)
    cont_last_read = consumer_cont.find(
            '_lw(dependency_consumer_target + offset + 0x1C)', cont_loop)
    if not 0 <= cont_prefix_range < cont_prefix_size < cont_setup_a0 < \
            cont_setup_a1 < cont_liveness_loop < cont_liveness_decode < \
            cont_liveness_read < cont_liveness_a1 < cont_range < \
            cont_range_args < cont_header < cont_loop < cont_first_read < \
            cont_last_read:
        fail("dependency consumer continuation validation/read order regressed")
    cont_rows = consumer_cont[cont_loop:]
    if cont_rows.count('_lw(dependency_consumer_target + offset + ') != 8 or \
            consumer_cont.count(
                'for (offset = 0x200; offset <= 0x2E0; offset += 0x20)') != 1 or \
            'dependency_consumer_target + offset + 0x20' in cont_rows or \
            'dependency_consumer_target + 0x300' in consumer_cont or \
            any(token in consumer_cont for token in
                ('0x35A24', 'zeroCtrlMipsJumpTarget',
                 'zeroCtrlMipsBranchTarget',
                 'zeroCtrlWriteConstructed0DependencyConsumerContinuation('
                 'paf,', 'a989_target_dependency', 'a989_target_node',
                 'a989_target_outer', 'a989_target_inner', '_sw(', '_sb(',
                 'sceKernelDcache', 'sceKernelIcache')):
        fail("dependency consumer continuation exceeds bounds, follows code, uses runtime state, or writes")
    map_start = kernel.find(
            'static void zeroCtrlWriteConstructed0DependencyMap(')
    map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyHelperMap(', map_start)
    dependency_map = kernel[map_start:map_end]
    if map_start < 0 or map_end < 0:
        fail("constructed0 dependency NO_RETURN code map is missing")
    map_validation = dependency_map.find(
            'zeroCtrlBridgeExecutableRange(paf, target, 0x200)')
    map_header = dependency_map.find(
            '[psp1000-constructed0-dependency-map] validation=1',
            map_validation)
    map_loop = dependency_map.find(
            'for (offset = 0; offset <= 0x1E0; offset += 0x20)', map_header)
    map_first_read = dependency_map.find('_lw(target + offset + 0x00)', map_loop)
    map_last_read = dependency_map.find('_lw(target + offset + 0x1C)', map_loop)
    if not 0 <= map_validation < map_header < map_loop < map_first_read < \
            map_last_read:
        fail("dependency map reads before validating its full 0x200-byte range")
    for token in ('[psp1000-constructed0-dependency-map] validation=0',
            'target=0x%08X target_off=0x%X size=0x200',
            '[psp1000-constructed0-dependency-code] off=0x%03X',
            'w0=%08X w1=%08X w2=%08X w3=%08X',
            'w4=%08X w5=%08X w6=%08X w7=%08X'):
        if token not in dependency_map:
            fail("bounded constructed0 dependency map lacks " + token)
    if dependency_map.count('_lw(') != 8 or \
            any(token in dependency_map for token in
                ('zeroCtrlMipsJumpTarget', 'zeroCtrlMipsBranchTarget',
                 'a989_target_dependency', 'inner', 'outer', 'node',
                 '_sw(', 'sceKernelDcache', 'sceKernelIcache')):
        fail("dependency map scans, follows control flow, uses runtime objects, or writes")
    no_return_gate = dependency_analysis.find('if (boundary == 0)')
    no_return_record = dependency_analysis.find(
            'reason=NO_RETURN off=0x200', no_return_gate)
    map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyMap(paf, target);',
            no_return_record)
    consumer_cont_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyConsumerContinuation(paf, target);',
            map_call)
    w40_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyW40ZeroTargetMap(paf, target);',
            consumer_cont_call)
    w2c_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyW2CNonzeroTargetMap(paf, target);',
            w40_map_call)
    dependency44_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0Dependency44CalleeMap(paf, target);',
            w2c_map_call)
    helper_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyHelperMap(paf, target);',
            dependency44_map_call)
    no_return_exit = dependency_analysis.find('return 0;', map_call)
    if not 0 <= no_return_gate < no_return_record < map_call < \
            consumer_cont_call < w40_map_call < dependency44_map_call < \
            helper_map_call < no_return_exit or not w40_map_call < \
            w2c_map_call < dependency44_map_call or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyMap(') != 1 or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyConsumerContinuation(') != 1 or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyW40ZeroTargetMap(') != 1 or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyW2CNonzeroTargetMap(') != 1 or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0Dependency44CalleeMap(') != 1:
        fail("dependency map is not gated solely by the existing NO_RETURN path")
    if 'int constructed0_dependency_written = 0;' not in writer or \
            'slide_diag.constructed0_dependency' in kernel:
        fail("dependency map one-shot state is not writer-local")
    helper_map_start = map_end + 1
    helper_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyCopyImplementationMap(',
            helper_map_start)
    dependency_helper_map = kernel[helper_map_start:helper_map_end]
    if helper_map_start <= 0 or helper_map_end < 0:
        fail("constructed0 dependency common-helper map is missing")
    for token in ('dependency_consumer_target + 0x034',
            'zeroCtrlMipsMove(', '19, 5',
            'dependency_consumer_target + 0x038',
            'dependency_consumer_target + 0x04C',
            '(addiu >> 26) != 9', '((addiu >> 21) & 0x1F) != 19',
            '((addiu >> 16) & 0x1F) != 5',
            '(short)(addiu & 0xFFFF) != 0x0C',
            'dependency_consumer_target + 0x050',
            'call0 = zeroCtrlMipsJumpTarget(',
            'call1 = zeroCtrlMipsJumpTarget(', 'call0 != call1',
            'zeroCtrlModuleContainingSegment(paf, call0, &segment,',
            '[psp1000-constructed0-dependency-helper] validation=0',
            'call0_off=0x038 call1_off=0x050 target=0x%08X',
            'segment=%u segment_off=0x%X size=0x100',
            '[psp1000-constructed0-dependency-helper-code] off=0x%03X'):
        if token not in dependency_helper_map:
            fail("constructed0 dependency common-helper proof lacks " + token)
    consumer_map_range = dependency_helper_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_consumer_target,')
    consumer_map_size = dependency_helper_map.find('0x200)', consumer_map_range)
    consumer_structure_read = dependency_helper_map.find(
            '_lw(dependency_consumer_target + 0x034)', consumer_map_size)
    if not 0 <= consumer_map_range < consumer_map_size < consumer_structure_read:
        fail("helper-call proof does not reuse the validated 0x200 consumer map")
    helper_range = dependency_helper_map.find(
            'zeroCtrlBridgeExecutableRange(paf, call0,')
    helper_range_size = dependency_helper_map.find('0x100)', helper_range)
    helper_header = dependency_helper_map.find(
            '[psp1000-constructed0-dependency-helper] validation=1',
            helper_range_size)
    helper_loop = dependency_helper_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)', helper_header)
    helper_first_read = dependency_helper_map.find(
            '_lw(helper_target + offset + 0x00)', helper_loop)
    helper_last_read = dependency_helper_map.find(
            '_lw(helper_target + offset + 0x1C)', helper_loop)
    if not 0 <= helper_range < helper_range_size < helper_header < \
            helper_loop < helper_first_read < helper_last_read:
        fail("dependency helper map reads before full 0x100 executable proof")
    if dependency_helper_map.count('_lw(helper_target + offset + ') != 8 or \
            dependency_helper_map.count('zeroCtrlMipsJumpTarget(') != 2 or \
            any(token in dependency_helper_map for token in
                ('0x35A24', 'zeroCtrlMipsBranchTarget',
                 'a989_target_dependency', '_sw(', 'sceKernelDcache',
                 'sceKernelIcache', 'zeroCtrlWriteConstructed0DependencyConsumer(')):
        fail("dependency helper map scans, recurses, uses runtime state, or writes")
    helper_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyHelperMap(paf, target);',
            map_call)
    if not map_call < helper_map_call < no_return_exit or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyHelperMap(') != 1:
        fail("dependency helper map is not one-shot under the NO_RETURN gate")
    impl_map_start = helper_map_end + 1
    impl_map_end = kernel.find(
            '\nstatic void zeroCtrlWriteConstructed0DependencyCopyCalleeMap(',
            impl_map_start)
    dependency_impl_map = kernel[impl_map_start:impl_map_end]
    if impl_map_start <= 0 or impl_map_end < 0:
        fail("constructed0 dependency copy implementation map is missing")
    for token in ('zeroCtrlBridgeExecutableRange(paf, copy_target, 8)',
            '(_lw(copy_target) >> 26) != 2',
            '_lw(copy_target + 0x004) != 0',
            'implementation_target = zeroCtrlMipsJumpTarget(copy_target,',
            'owner = sceKernelFindModuleByAddress(implementation_target)',
            '!zeroCtrlLoadedModuleMetadataValid(owner)',
            'zeroCtrlModuleContainingSegment(owner, implementation_target,',
            'segment != 0', 'remaining < 0x100',
            'zeroCtrlBridgeExecutableRange(owner, implementation_target,',
            '[psp1000-constructed0-dependency-copy-impl] validation=0',
            'stub=0x%08X target=0x%08X module=%.27s segment=%u',
            'segment_off=0x%X size=0x100',
            '[psp1000-constructed0-dependency-copy-impl-code] off=0x%03X'):
        if token not in dependency_impl_map:
            fail("constructed0 dependency copy implementation lacks " + token)
    stub_range = dependency_impl_map.find(
            'zeroCtrlBridgeExecutableRange(paf, copy_target, 8)')
    stub_word = dependency_impl_map.find('_lw(copy_target)', stub_range)
    stub_delay = dependency_impl_map.find(
            '_lw(copy_target + 0x004)', stub_word)
    implementation_decode = dependency_impl_map.find(
            'zeroCtrlMipsJumpTarget(copy_target,', stub_delay)
    implementation_owner = dependency_impl_map.find(
            'sceKernelFindModuleByAddress(implementation_target)',
            implementation_decode)
    implementation_range = dependency_impl_map.find(
            'zeroCtrlBridgeExecutableRange(owner, implementation_target,',
            implementation_owner)
    implementation_range_size = dependency_impl_map.find(
            '0x100)', implementation_range)
    implementation_header = dependency_impl_map.find(
            '[psp1000-constructed0-dependency-copy-impl] validation=1',
            implementation_range_size)
    implementation_loop = dependency_impl_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)',
            implementation_header)
    implementation_first_read = dependency_impl_map.find(
            '_lw(implementation_target + offset + 0x00)', implementation_loop)
    implementation_last_read = dependency_impl_map.find(
            '_lw(implementation_target + offset + 0x1C)', implementation_loop)
    if not 0 <= stub_range < stub_word < stub_delay < implementation_decode < \
            implementation_owner < implementation_range < \
            implementation_range_size < implementation_header < \
            implementation_loop < implementation_first_read < \
            implementation_last_read:
        fail("copy implementation derivation/range validation is out of order")
    continuation_start = dependency_impl_map.find(
            'unsigned int load = _lw(implementation_target + 0x024);',
            implementation_last_read)
    initial_implementation_map = dependency_impl_map[:continuation_start]
    continuation_map = dependency_impl_map[continuation_start:]
    if initial_implementation_map.count(
                '_lw(implementation_target + offset + ') != 8 or \
            dependency_impl_map.count('zeroCtrlMipsJumpTarget(') != 1 or \
            dependency_impl_map.count(
                'sceKernelFindModuleByAddress(implementation_target)') != 1 or \
            'copy_target + 0x008' in dependency_impl_map or \
            any(token in dependency_impl_map for token in
                ('0x08820140', '0x35A24', '0x148CDC', '0x15B9C4',
                 'scePaf_Module',
                 'a989_target_dependency', 'a989_target_node',
                 'a989_target_outer', 'a989_target_inner', '_sw(',
                 'sceKernelDcache', 'sceKernelIcache')):
        fail("copy implementation map uses fixed/runtime state, follows code, or writes")
    for token in ('zeroCtrlMipsMove(_lw(implementation_target + 0x000), 10, 5)',
            'zeroCtrlMipsMove(_lw(implementation_target + 0x004), 3, 4)',
            '_lw(implementation_target + 0x00C) != 0x00865821',
            '(load >> 26) != 0x24', '((load >> 21) & 0x1F) != 10',
            '(store >> 26) != 0x28', '((store >> 21) & 0x1F) != 3',
            '((store >> 16) & 0x1F) != ((load >> 16) & 0x1F)',
            '_lw(implementation_target + 0x034) != 0x254A0001',
            '_lw(implementation_target + 0x038) != 0x03E00008',
            '_lw(implementation_target + 0x03C) != 0x00801021',
            'implementation_target + 0x100, 0x180',
            '[psp1000-constructed0-dependency-copy-cont] ',
            'validation=0\\n',
            'start_off=0x100 size=0x180',
            '[psp1000-constructed0-dependency-copy-cont-code]'):
        if token not in continuation_map:
            fail("copy implementation continuation proof lacks " + token)
    continuation_range = continuation_map.find(
            'zeroCtrlBridgeExecutableRange(owner,')
    continuation_range_args = continuation_map.find(
            'implementation_target + 0x100, 0x180', continuation_range)
    continuation_header = continuation_map.find(
            '[psp1000-constructed0-dependency-copy-cont] validation=1',
            continuation_range_args)
    continuation_loop = continuation_map.find(
            'for (offset = 0x100; offset <= 0x260; offset += 0x20)',
            continuation_header)
    continuation_first_read = continuation_map.find(
            '_lw(implementation_target + offset + 0x00)', continuation_loop)
    continuation_last_read = continuation_map.find(
            '_lw(implementation_target + offset + 0x1C)', continuation_loop)
    if not 0 <= continuation_start or not 0 <= continuation_range < \
            continuation_range_args < continuation_header < continuation_loop < \
            continuation_first_read < continuation_last_read:
        fail("copy continuation reads before prefix/full-range validation")
    continuation2_start = continuation_map.find(
            'unsigned int boundary_branch =')
    continuation1_map = continuation_map[:continuation2_start]
    continuation2_map = continuation_map[continuation2_start:]
    if continuation2_start < 0:
        fail("copy implementation second continuation is missing")
    if continuation1_map.count(
                '_lw(implementation_target + offset + ') != 8 or \
            'offset <= 0x280' in continuation1_map or \
            'implementation_target + 0x280' in continuation1_map or \
            any(token in continuation1_map for token in
                ('0x08820340', 'sceKernelLibrary', '0x540',
                 'zeroCtrlMipsJumpTarget', 'zeroCtrlMipsBranchTarget',
                 'a989_target_dependency', 'a989_target_node',
                 'a989_target_outer', 'a989_target_inner', '_sw(',
                 'sceKernelDcache', 'sceKernelIcache')):
        fail("copy continuation exceeds bounds, follows code, uses runtime state, or writes")
    for token in ('_lw(implementation_target + 0x278) != 0x2CC70008',
            'boundary_branch != 0x10E00008',
            '(boundary_branch >> 26) != 4',
            'zeroCtrlMipsBranchTarget(implementation_target + 0x27C,',
            'boundary_branch) != implementation_target + 0x2A0',
            'implementation_target + 0x280, 0x100',
            '[psp1000-constructed0-dependency-copy-cont2] ',
            'validation=0\\n',
            '[psp1000-constructed0-dependency-copy-cont2] validation=1',
            'start_off=0x280 size=0x100',
            '[psp1000-constructed0-dependency-copy-cont2-code]'):
        if token not in continuation2_map:
            fail("copy implementation second continuation proof lacks " + token)
    cont2_boundary_278 = continuation2_map.find(
            '_lw(implementation_target + 0x278) != 0x2CC70008')
    cont2_boundary_27c = continuation2_map.find(
            'boundary_branch != 0x10E00008', cont2_boundary_278)
    cont2_opcode = continuation2_map.find(
            '(boundary_branch >> 26) != 4', cont2_boundary_27c)
    cont2_target = continuation2_map.find(
            'zeroCtrlMipsBranchTarget(implementation_target + 0x27C,',
            cont2_opcode)
    cont2_target_exact = continuation2_map.find(
            'boundary_branch) != implementation_target + 0x2A0', cont2_target)
    cont2_range = continuation2_map.find(
            'zeroCtrlBridgeExecutableRange(owner,', cont2_target_exact)
    cont2_range_args = continuation2_map.find(
            'implementation_target + 0x280, 0x100', cont2_range)
    cont2_header = continuation2_map.find(
            '[psp1000-constructed0-dependency-copy-cont2] validation=1',
            cont2_range_args)
    cont2_loop = continuation2_map.find(
            'for (offset = 0x280; offset <= 0x360; offset += 0x20)',
            cont2_header)
    cont2_first_read = continuation2_map.find(
            '_lw(implementation_target + offset + 0x00)', cont2_loop)
    cont2_last_read = continuation2_map.find(
            '_lw(implementation_target + offset + 0x1C)', cont2_loop)
    if not 0 <= cont2_boundary_278 < cont2_boundary_27c < cont2_opcode < \
            cont2_target < cont2_target_exact < cont2_range < \
            cont2_range_args < cont2_header < cont2_loop < cont2_first_read < \
            cont2_last_read:
        fail("copy second continuation reads before boundary/full-range validation")
    if continuation2_map.count(
                '_lw(implementation_target + offset + ') != 8 or \
            continuation2_map.count('zeroCtrlMipsBranchTarget(') != 1 or \
            continuation2_map.count('for (offset = 0x280; offset <= 0x360; '
                'offset += 0x20)') != 1 or \
            'implementation_target + offset + 0x20' in continuation2_map or \
            'implementation_target + 0x380' in continuation2_map or \
            any(token in continuation2_map for token in
                ('0x08820340', 'sceKernelLibrary', '0x540',
                 'zeroCtrlMipsJumpTarget', 'a989_target_dependency',
                 'a989_target_node', 'a989_target_outer', 'a989_target_inner',
                 '_sw(', 'sceKernelDcache', 'sceKernelIcache')):
        fail("copy second continuation exceeds bounds, follows code, uses runtime state, or writes")
    copy_map_start = impl_map_end + 1
    copy_map_end = kernel.find(
            '\nstatic int zeroCtrlWriteConstructed0DependencyConsumer(void)',
            copy_map_start)
    dependency_copy_map = kernel[copy_map_start:copy_map_end]
    if copy_map_start <= 0 or copy_map_end < 0:
        fail("constructed0 dependency copy-callee map is missing")
    for token in ('dependency_consumer_target + 0x034',
            'zeroCtrlMipsMove(', '19, 5',
            'dependency_consumer_target + 0x038',
            'dependency_consumer_target + 0x04C',
            'dependency_consumer_target + 0x050',
            'common0 = zeroCtrlMipsJumpTarget(',
            'common1 = zeroCtrlMipsJumpTarget(', 'common0 != common1',
            'zeroCtrlBridgeExecutableRange(paf, common0, 0x100)',
            'zeroCtrlMipsMove(word, 16, 5)',
            'source_moves != 1',
            '_lw(common_helper_target + 0x038) != 0x8E020004',
            '_lw(common_helper_target + 0x03C) != 0x1440000A',
            '_lw(common_helper_target + 0x040) != 0x24440001',
            '(_lw(common_helper_target + 0x068) >> 26) != 3',
            '_lw(common_helper_target + 0x06C) != 0x00000000',
            '_lw(common_helper_target + 0x070) != 0xAE220000',
            '_lw(common_helper_target + 0x074) != 0x00402021',
            '_lw(common_helper_target + 0x078) != 0x8E060004',
            '_lw(common_helper_target + 0x07C) != 0x8E050000',
            '_lw(common_helper_target + 0x080) != 0xAE260004',
            '(_lw(common_helper_target + 0x084) >> 26) != 3',
            '_lw(common_helper_target + 0x088) != 0x24C60001',
            'copy_target = zeroCtrlMipsJumpTarget(',
            'zeroCtrlModuleContainingSegment(paf, copy_target, &segment,',
            'segment != 0',
            '[psp1000-constructed0-dependency-copy-callee] validation=0',
            'call_off=0x084 target=0x%08X target_off=0x%X size=0x100',
            '[psp1000-constructed0-dependency-copy-code] off=0x%03X',
            'zeroCtrlWriteConstructed0DependencyCopyImplementationMap('
            'paf, copy_target)'):
        if token not in dependency_copy_map:
            fail("constructed0 dependency copy-callee proof lacks " + token)
    exact_helper_words = (
            '_lw(common_helper_target + 0x038) != 0x8E020004',
            '_lw(common_helper_target + 0x03C) != 0x1440000A',
            '_lw(common_helper_target + 0x040) != 0x24440001',
            '(_lw(common_helper_target + 0x068) >> 26) != 3',
            '_lw(common_helper_target + 0x06C) != 0x00000000',
            '_lw(common_helper_target + 0x070) != 0xAE220000',
            '_lw(common_helper_target + 0x074) != 0x00402021',
            '_lw(common_helper_target + 0x078) != 0x8E060004',
            '_lw(common_helper_target + 0x07C) != 0x8E050000',
            '_lw(common_helper_target + 0x080) != 0xAE260004',
            '(_lw(common_helper_target + 0x084) >> 26) != 3',
            '_lw(common_helper_target + 0x088) != 0x24C60001')
    exact_positions = [dependency_copy_map.find(token)
            for token in exact_helper_words]
    if any(position < 0 for position in exact_positions) or \
            exact_positions != sorted(exact_positions):
        fail("copy-callee source/destination grammar is not validated in order")
    if 'common_helper_target + 0x06C) != 0x24440001' in \
            dependency_copy_map:
        fail("copy-callee proof incorrectly moves source+4 preparation to +0x06C")
    copy_consumer_range = dependency_copy_map.find(
            'zeroCtrlBridgeExecutableRange(paf, dependency_consumer_target,')
    copy_consumer_size = dependency_copy_map.find(
            '0x200)', copy_consumer_range)
    copy_consumer_read = dependency_copy_map.find(
            '_lw(dependency_consumer_target + 0x034)', copy_consumer_size)
    copy_range = dependency_copy_map.find(
            'zeroCtrlBridgeExecutableRange(paf, copy_target, 0x100)',
            copy_consumer_read)
    copy_header = dependency_copy_map.find(
            '[psp1000-constructed0-dependency-copy-callee] validation=1',
            copy_range)
    copy_loop = dependency_copy_map.find(
            'for (offset = 0; offset <= 0xE0; offset += 0x20)', copy_header)
    copy_first_read = dependency_copy_map.find(
            '_lw(copy_target + offset + 0x00)', copy_loop)
    copy_last_read = dependency_copy_map.find(
            '_lw(copy_target + offset + 0x1C)', copy_loop)
    if not 0 <= copy_consumer_range < copy_consumer_size < \
            copy_consumer_read < copy_range < copy_header < copy_loop < \
            copy_first_read < copy_last_read:
        fail("copy-callee map reads before validated derivation/full range")
    if dependency_copy_map.count('_lw(copy_target + offset + ') != 8 or \
            dependency_copy_map.count('zeroCtrlMipsJumpTarget(') != 3 or \
            any(token in dependency_copy_map for token in
                ('0x35A24', '0x148CDC', '0x15B9C4',
                 'zeroCtrlMipsBranchTarget', 'a989_target_dependency',
                 'a989_target_node', 'a989_target_outer', 'a989_target_inner',
                 '_sw(', 'sceKernelDcache', 'sceKernelIcache',
                 'zeroCtrlWriteConstructed0DependencyConsumer(')):
        fail("copy-callee map follows code, uses runtime state, recurses, or writes")
    implementation_map_call = dependency_copy_map.find(
            'zeroCtrlWriteConstructed0DependencyCopyImplementationMap('
            'paf, copy_target)', copy_last_read)
    copy_success_return = dependency_copy_map.find(
            'return;', implementation_map_call)
    if not copy_last_read < implementation_map_call < copy_success_return or \
            dependency_copy_map.count(
                'zeroCtrlWriteConstructed0DependencyCopyImplementationMap(') != 1:
        fail("copy implementation map is not ordered after the existing stub map")
    copy_map_call = dependency_analysis.find(
            'zeroCtrlWriteConstructed0DependencyCopyCalleeMap(paf, target);',
            helper_map_call)
    if not helper_map_call < copy_map_call < no_return_exit or \
            dependency_analysis.count(
                'zeroCtrlWriteConstructed0DependencyCopyCalleeMap(') != 1:
        fail("copy-callee map is not one-shot under the NO_RETURN chain")
    apply_start = kernel.find(
            'static int zeroCtrlApplyConstructed0DependencyInstruction(')
    apply_end = dependency_analysis_start
    dependency_apply = kernel[apply_start:apply_end]
    for token in ('zeroCtrlMipsMove(', 'opcode == 9',
            'ZERO_DEPENDENCY_BASE_PLUS', 'ZERO_DEPENDENCY_LOADED',
            'zeroCtrlDependencyMemoryKind(opcode)',
            'CONSTRUCTED0_DEPENDENCY_MAX_ACCESS',
            'CONSTRUCTED0_DEPENDENCY_MAX_CHASE',
            '[psp1000-constructed0-dependency-access]',
            '[psp1000-constructed0-dependency-chase]',
            '*reason = "UNSUPPORTED_MEMORY"',
            '*reason = "UNSUPPORTED_WRITE"'):
        if token not in dependency_apply:
            fail("dependency provenance engine lacks " + token)
    analysis_gate = writer.find('if (!constructed0_dependency_written &&')
    analysis_call = writer.find(
            'zeroCtrlWriteConstructed0DependencyConsumer();', analysis_gate)
    if not 0 <= analysis_gate < analysis_call or \
            'slide_diag.bridge_validation == 1' not in \
                writer[analysis_gate:analysis_call] or \
            'slide_diag.bridge_install == 1' not in \
                writer[analysis_gate:analysis_call] or \
            'zeroCtrlLoadedModuleMetadataValid(dependency_paf)' not in \
                writer[analysis_gate:analysis_call]:
        fail("constructed0 dependency analysis is not a one-shot post-install writer")
    clock_start = kernel.find(
            "static int zeroCtrlWriteFunctionalClockPathAnalysis(void)")
    clock_end = kernel.find("static int zeroCtrlMipsMove(", clock_start)
    clockpath = kernel[clock_start:clock_end]
    for token in ('sceKernelFindModuleByName("vsh_module")', "model != 0",
            "sceKernelDevkitVersion() != 0x06060110",
            "!slide_diag.functional_enabled",
            "!zeroCtrlLoadedModuleMetadataValid(vsh)",
            'strcmp(vsh->modname, "vsh_module") != 0',
            "vsh->modid != slide_diag.vsh_modid",
            "vsh->text_addr != slide_diag.vsh_text_addr",
            "vsh->text_size != slide_diag.vsh_text_size",
            "vsh->text_size != 0x556C0",
            "zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr, vsh->text_size)",
            "target58cc != text + 0x5900",
            "CLOCKPATH_DELAY(offset)", "CLOCKPATH_QUEUE(target - text)",
            "CLOCKPATH_QUEUE(offset + 8)",
            "zeroCtrlClockPathNodeIndex(node, count, 0x5900) < 0",
            "[psp1000-clockpath-cfg]", "[psp1000-clockpath-node]",
            "[psp1000-clockpath-exit]", "[psp1000-clockpath-call]",
            "[psp1000-clockpath-pointer]",
            "[psp1000-clockpath-materialize]",
            "[psp1000-clockpath-entry-arg]",
            "[psp1000-clockpath-58b8-arg]",
            "[psp1000-clockpath-registration-materialize]",
            "material_count != 1", "material_source != 0x56FC",
            "material_reg != 5", "look <= 16",
            "zeroCtrlClockPathPropagateCallback(delay",
            "[psp1000-clockpath-registration-consumer]",
            "[psp1000-clockpath-registration-args]",
            "CALLBACK_VSH_589C",
            "[psp1000-clockpath-registration-store]",
            "[psp1000-clockpath-registration-forward]",
            "[psp1000-clockpath-registration-flow]",
            "[psp1000-clockpath-registration-code]",
            "i < 96 * 4"):
        if token not in clockpath:
            fail("read-only Clock & Date CFG analysis lacks " + token)
    if "#define CLOCKPATH_CFG_LIMIT 128" not in kernel:
        fail("Clock path CFG bound is not 128 reachable instructions")
    reconstruction = clockpath[clockpath.find(
            "if ((_lw(text + 0x58A4)"):clockpath.find(
            "[psp1000-clockpath-entry-arg]")]
    for upper, lower, target in (("0x589C", "0x58A4", "0x56C7C"),
            ("0x58B4", "0x58BC", "0x56CA4")):
        pattern = (r"_lw\(text \+ " + upper +
                r"\)[\s\S]{0,180}_lw\(text \+ " + lower +
                r"\)[\s\S]{0,80}\)\s*!=\s*text \+ " + target)
        if not re.search(pattern, reconstruction):
            fail("Clock path reconstructed address comparison lacks " +
                    upper + "/" + lower + " -> " + target)
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL", "MAKE_JUMP",
            "REDIRECT_FUNCTION", "hook_import", "zeroCtrlSetSlideState",
            "zeroCtrlInstallVshCtrl314A4Trace("):
        if forbidden in clockpath:
            fail("Clock & Date CFG analysis is not read-only: " + forbidden)
    xref_start = kernel.find("static void zeroCtrlWriteClockPathXrefs(")
    xref_end = clock_start
    xrefs = kernel[xref_start:xref_end]
    for token in ("opcode == 0x23", "opcode == 0x2B", "opcode == 9", "opcode == 0x0D",
            "effective == target", "zeroCtrlClockPathControl(word)",
            "zeroCtrlMipsGprWriteDestination(word)",
            "[psp1000-clockpath-global-xref]",
            "[psp1000-clockpath-pointer-xref]"):
        if token not in xrefs:
            fail("Clock path exact xref scanner lacks " + token)
    if "#define CLOCKPATH_XREF_LOOKAHEAD 8" not in kernel:
        fail("Clock path xref scan is not bounded")
    registration_start = kernel.find(
            "static void zeroCtrlDescribeRegistrationArgument(")
    registration = kernel[registration_start:clock_end]
    for token in ('strcpy(description, "UNKNOWN")',
            "zeroCtrlVshModuleRangeValid(vsh,",
            "zeroCtrlMipsGprWriteDestination(word)",
            "opcode == 3", "opcode == 0 && function == 9"):
        if token not in registration:
            fail("Clock callback registration provenance lacks " + token)
    for forbidden in ("_sw(", "Dcache", "Icache", "MAKE_CALL", "MAKE_JUMP",
            "REDIRECT_FUNCTION", "hook_import"):
        if forbidden in registration:
            fail("Clock callback registration analysis mutates runtime state")
    if "zeroCtrlInstallVshCtrl314A4Trace();" in writer:
        fail("VSH +314A4 is still patched automatically")
    call = minimal.find("zeroCtrlWriteFunctionalClockPathAnalysis()")
    if call < 0 or "clockpath_written" not in minimal[:call]:
        fail("Clock path analysis is not a writer-only one-shot")
    parsed_keys = []
    for raw_line in sample_config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            fail("sample INI contains an invalid active line: " + line)
        parsed_keys.append(line.split("=", 1)[0].strip())
    if len(parsed_keys) != len(set(parsed_keys)):
        fail("sample INI contains duplicate active configuration keys")
    required_ini = ("PSP1000SlidePlugin", "PSP1000SlideTriggerMode",
            "PSP1000Diagnostics", "PSP1000DiagnosticsVerbose",
            "PSP1000SonyStartTrace",
            "PSP1000SelectiveSlideTrigger58D4")
    for key in required_ini:
        if parsed_keys.count(key) != 1:
            fail("sample INI must contain exactly one " + key)
    experimental = sample_config[sample_config.find("[Experimental]"):]
    for line in experimental.splitlines():
        line = line.strip()
        if line == "PSP1000Diagnostics = Enabled":
            continue
        if line.startswith("PSP1000") and not line.endswith("= Disabled"):
            fail("sample INI enables experimental PSP-1000 behavior: " + line)
    legacy_pos = sample_config.find("PSP1000SelectiveSlideTrigger58D4")
    legacy_context = sample_config[max(0, legacy_pos - 160):legacy_pos].lower()
    if legacy_pos < 0 or "legacy" not in legacy_context or \
            "deprecated" not in legacy_context:
        fail("legacy selective +58D4 alias is not clearly documented")
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
    experiment_start = kernel_module_start.find(
            "if (zeroCtrlIsPsp1000SlideExperimentEnabled() &&")
    experiment_end = kernel_module_start.find(
            'if(strcmp(mod->modname, "slide_plugin_module") == 0)',
            experiment_start)
    experiment_block = kernel_module_start[experiment_start:experiment_end]
    for forbidden in ('hook_import_bynid(mod, "sceBSMan", 0x23E3A9B6',
            'hook_import_bynid(mod, "sceVshBridge", 0x639C3CB3',
            "zeroCtrlDummyFunc", "zeroCtrlGetParam"):
        if forbidden in experiment_block:
            fail("functional PSP-1000 checkpoint retains broad import replacement")
    sony_install = kernel_module_start.find("zeroCtrlInstallSonyStartTrace(mod)")
    functional_compat = kernel_module_start.find(
            "zeroCtrlInstallPsp1000FunctionalCompat(mod)")
    diagnostic_compat = kernel_module_start.find(
            "zeroCtrlInstallBSManClosedShim(mod)", functional_compat)
    functional_return = kernel_module_start.find("return previous_result",
            diagnostic_compat)
    if not 0 <= experiment_start < sony_install < functional_compat < \
            diagnostic_compat < functional_return:
        fail("functional SlidePlugin installer split is incorrectly ordered")
    install_gate = kernel_module_start[sony_install:functional_return]
    for token in ("if (slide_diag.functional_enabled)",
            "zeroCtrlInstallPsp1000FunctionalCompat(mod)", "else",
            "zeroCtrlInstallBSManClosedShim(mod)"):
        if token not in install_gate:
            fail("functional/diagnostic activation installer split lacks " + token)
    if "ClearCaches()" in install_gate:
        fail("functional activation path performs a broad cache flush")
    for gate_name in ("bsman_not_linked_compat_enabled =",
            "post_vsh_compat_enabled ="):
        gate = kernel[kernel.find(gate_name):kernel.find(";", kernel.find(gate_name))]
        if "slide_diag.functional_enabled ||" not in gate:
            fail("functional checkpoint omits hardware-proven compatibility " + gate_name)
    for gate_name in ("paf_compat_enabled =",
            "state_zero_15to14_compat_enabled ="):
        gate = kernel[kernel.find(gate_name):kernel.find(";", kernel.find(gate_name))]
        if "slide_diag.functional_enabled ||" not in gate:
            fail("functional checkpoint omits hardware-proven compatibility " + gate_name)
    trigger_gate = kernel[kernel.find("slide_diag.trigger_mode ="):
            kernel.find(";", kernel.find("slide_diag.trigger_mode ="))]
    if "slide_diag.functional_enabled ?" not in trigger_gate or \
            "ZERO_TRIGGER_58D4" not in trigger_gate:
        fail("functional checkpoint does not use the proven selective +58D4 path")
    functional_gates = kernel[kernel.find("slide_diag.sony_start_trace.enabled ="):
            kernel.find("zeroCtrlDiagnosticsInit", kernel.find(
                "slide_diag.sony_start_trace.enabled ="))]
    for gate_name in ("sony_start_trace.enabled =", "bsman.enabled =",
            "consumer_14020_compat_enabled =", "consumer_13f6c_compat_enabled =",
            "paf_mask_compat_enabled =", "post_impose_vcall_enabled ="):
        gate_start = functional_gates.find(gate_name)
        gate_end = functional_gates.find(";", gate_start)
        if gate_start < 0 or "!slide_diag.functional_enabled" not in \
                functional_gates[gate_start:gate_end]:
            fail("functional checkpoint does not suppress diagnostic/speculative " +
                    gate_name)
    for token in ("[checkpoint] compat=58d4,paf_zero_to_one,",
            "bsman_not_linked_to_zero,state15_to14,",
            "impose_invalid_mode_to_zero"):
        if token not in kernel:
            fail("functional checkpoint marker lacks " + token)
    functional_start = kernel.find(
            "static void zeroCtrlInstallPsp1000FunctionalCompat(")
    functional_end = kernel.find(
            "static void zeroCtrlInstallPsp1000PostT39Diagnostic(",
            functional_start)
    functional = kernel[functional_start:functional_end]
    for token in (
            "0x02C, 0x0A8, 0x10C, 0x2A4",
            "mod->text_addr > 0xFFFFFFFFU - 0x9304",
            "activation = mod->text_addr + 0x9304",
            "!zeroCtrlVshModuleRangeValid(mod, activation, 0x2BC + 8)",
            "_lw(activation) != 0x27BDFFE0",
            "_lw(activation + 4) != 0xAFB10004",
            "_lw(activation + 8) != 0x00808821",
            "_lw(activation + 12) != 0xAFB00000",
            "_lw(activation + 16) != 0xAFBF001C",
            "nid == 0xED83BBCF", "nid == 0x23E3A9B6",
            "nid == 0x639C3CB3",
            "paf_matches != 1", "bsman_matches != 1",
            "vshbridge_matches != 1",
            "bsman_callers != 1",
            "bsman_caller != activation + 0xA8",
            "bsman->prefix_paf_call_leaf_addr",
            "bsman->call_leaf_addr", "bsman->post_vsh_call_leaf_addr",
            "bsman->state_zero_leaf_addr[3]",
            "bsman->prefix_paf_return_leaf_addr",
            "bsman->return_leaf_addr", "bsman->post_vsh_return_leaf_addr",
            "bsman->state_zero_leaf_addr[4]",
            "_lw(owner[0] + 4) != 0x00408021",
            "owner[1] != bsman_caller",
            "(_lw(owner[1] + 4) & 0xFFFF0000) != 0x3C130000",
            "_lw(owner[1] + 8) != 0x1040000A",
            "_lw(activation + 0x108) != 0x3C048000",
            "_lw(owner[2] + 4) != 0x3484000D",
            "_lw(owner[2] + 8) != 0x1440FFCE",
            "original[3] != 0x0040F809", "_lw(owner[3] + 4) != 0",
            "zeroCtrlMipsJumpTarget(owner[i], replacement[i]) != leaf[i]",
            "bsman->functional_validation = 1",
            "initial_mode = slide_diag.functional_home_open_pending ? 1 : 0",
            "_sw(initial_mode, bsman->prefix_paf_compat_mode_addr)",
            "_sw(initial_mode, bsman->bsman_compat_mode_addr)",
            "_sw(initial_mode, bsman->post_vsh_compat_mode_addr)",
            "_sw(initial_mode, bsman->state_zero_15to14_compat_mode_addr)",
            "ADD_FUNCTIONAL_SCALAR(bsman->state_zero_value_addr[4])",
            "ADD_FUNCTIONAL_SCALAR(bsman->state_zero_value_addr[5])",
            "ADD_FUNCTIONAL_SCALAR(bsman->state_zero_value_addr[6])",
            "_sw(0, bsman->state_zero_value_addr[4])",
            "_sw(0, bsman->state_zero_value_addr[5])",
            "_sw(0xFFFFFFFF, bsman->state_zero_value_addr[6])",
            "for (i = 0; i < scalar_count; i++)\n"
            "        sceKernelDcacheWritebackInvalidateRange",
            "for (i = 0; i < 4; i++) {",
            "_sw(replacement[i], owner[i])",
            "sceKernelDcacheWritebackInvalidateRange((const void *)owner[i], 4)",
            "sceKernelIcacheInvalidateRange((const void *)owner[i], 4)",
            "bsman->functional_install = 1",
            "bsman->functional_cache_sync = 1",
            "slide_diag.functional_home_open_pending = 0"):
        if token not in functional:
            fail("narrow functional activation installer lacks " + token)
    for mode in ("prefix_paf", "bsman", "post_vsh", "state_zero_15to14"):
        if functional.count("_sw(initial_mode, bsman->" +
                mode + "_compat_mode_addr)") != 1:
            fail("functional installer does not use shared pending mode for " + mode)
    initial_mode_set = functional.find(
            "initial_mode = slide_diag.functional_home_open_pending ? 1 : 0")
    first_mode_write = functional.find("_sw(initial_mode,")
    validation_set = functional.find("bsman->functional_validation = 1")
    install_set = functional.find("bsman->functional_install = 1")
    cache_set = functional.find("bsman->functional_cache_sync = 1")
    pending_clear = functional.find("functional_home_open_pending = 0")
    if not 0 <= initial_mode_set < first_mode_write < validation_set < \
            install_set < cache_set < pending_clear:
        fail("functional pending-mode handoff/clear ordering regressed")
    if "candidates" in functional or \
            "for (pc = 0; pc + 20 <= mod->text_size" in functional:
        fail("functional activation installer globally scans for the prologue")
    if kernel.count("unsigned int functional_activation_stage;") != 1:
        fail("functional activation stage is not one kernel-only scalar")
    if "functional_activation_stage" in bsman_header:
        fail("functional activation stage leaks into the registration ABI")
    stage_positions = []
    for stage in range(1, 14):
        token = "bsman->functional_activation_stage = %d;" % stage
        if functional.count(token) != 1:
            fail("functional activation stage %d is missing or duplicated" % stage)
        stage_positions.append(functional.find(token))
    if stage_positions != sorted(stage_positions):
        fail("functional activation stages are not monotonic")
    traversal_end = functional.find("bsman->functional_activation_stage = 4;")
    import_unique = functional.find("paf_matches != 1", traversal_end)
    if not 0 <= traversal_end < import_unique < stage_positions[4]:
        fail("functional import traversal/uniqueness stages are conflated")
    owner_commit = functional.find("_sw(replacement[i], owner[i])")
    owner_dcache = functional.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)owner[i], 4)",
            owner_commit)
    owner_icache = functional.find(
            "sceKernelIcacheInvalidateRange((const void *)owner[i], 4)",
            owner_dcache)
    if not 0 <= owner_commit < owner_dcache < owner_icache < stage_positions[11]:
        fail("functional stage 12 precedes four-owner cache synchronization")
    validation_flag = functional.find("bsman->functional_validation = 1",
            stage_positions[11])
    install_flag = functional.find("bsman->functional_install = 1",
            validation_flag)
    cache_flag = functional.find("bsman->functional_cache_sync = 1",
            install_flag)
    if not 0 <= stage_positions[11] < validation_flag < install_flag < \
            cache_flag < stage_positions[12]:
        fail("functional stage 13 precedes completion flags")
    if "if (bsman->functional_activation_stage" in functional or \
            "switch (bsman->functional_activation_stage" in functional:
        fail("functional compatibility behavior depends on diagnostic stage")
    for forbidden_io in ("zeroCtrlDiagnostics", "sceIo", "snprintf("):
        if forbidden_io in functional:
            fail("functional activation installer performs stage file/output I/O")
    stage_writer = minimal.find(
            "slide_diag.bsman.functional_activation_stage !=")
    stage_format = minimal.find(
            "[psp1000-functional] activation_compat_stage=%u", stage_writer)
    if not 0 <= stage_writer < stage_format:
        fail("deferred functional activation stage output is missing")
    snapshot_start = minimal.find(
            "if (slide_diag.bsman.functional_install &&\n"
            "                    slide_diag.bsman.functional_cache_sync) {")
    snapshot_end = minimal.find("if (slide_diag.functional_button_thread",
            snapshot_start)
    snapshot = minimal[snapshot_start:snapshot_end]
    for token in ("unsigned int compat[9]", "unsigned int compat2[12]",
            "bsman->prefix_path_mask_addr",
            "bsman->prefix_paf_return_hits_addr",
            "bsman->prefix_paf_natural_result_addr",
            "bsman->prefix_paf_substitution_hits_addr",
            "bsman->call_hits_addr", "bsman->bsman_return_hits_addr",
            "bsman->bsman_natural_result_addr",
            "bsman->bsman_effective_result_addr",
            "bsman->bsman_substitution_hits_addr",
            "bsman->state_zero_path_mask_addr",
            "bsman->state_zero_counter_addr[1]",
            "bsman->state_zero_counter_addr[2]",
            "bsman->state_zero_value_addr[6]",
            "bsman->state_zero_15to14_effective_result_addr",
            "bsman->state_zero_15to14_substitution_hits_addr",
            "bsman->post_vsh_entry_hits_addr",
            "bsman->post_vsh_return_hits_addr",
            "bsman->post_vsh_argument_addr",
            "bsman->post_vsh_natural_result_addr",
            "bsman->post_vsh_effective_result_addr",
            "bsman->post_vsh_substitution_hits_addr",
            "zeroCtrlReadHelperCounter(",
            "!observed_functional_compat_valid ||", "memcmp(compat,",
            "memcmp(compat2,", "observed_functional_compat_valid = 1",
            "[psp1000-functional-compat]",
            "[psp1000-functional-compat2]"):
        if token not in snapshot:
            fail("functional compatibility snapshot lacks " + token)
    first_change_test = snapshot.find("!observed_functional_compat_valid ||")
    first_output = snapshot.find("zeroCtrlDiagnosticsText(line)")
    if not 0 <= first_change_test < first_output:
        fail("functional compatibility snapshot is not changed-only")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP",
            "REDIRECT_FUNCTION", "sceKernelDcache", "sceKernelIcache"):
        if forbidden in snapshot:
            fail("functional compatibility snapshot modifies runtime state: " +
                    forbidden)
    post_t39_snapshot = minimal[minimal.find(
            "if (slide_diag.bsman.functional_post_t39_install"):
            minimal.find("if (slide_diag.functional_button_thread")]
    post_t39_install_marker = minimal.find(
            "[psp1000-functional-post-t39-install] rev=1 ")
    post_t39_install_start = minimal.rfind(
            "if (slide_diag.functional_enabled) {", 0,
            post_t39_install_marker)
    post_t39_install_end = minimal.find(
            "if (slide_diag.bsman.functional_post_t39_install",
            post_t39_install_marker)
    post_t39_install_snapshot = minimal[
            post_t39_install_start:post_t39_install_end]
    for token in ("functional_post_t39_stage",
            "functional_post_t39_validation",
            "functional_post_t39_install",
            "functional_post_t39_cache_sync",
            "memcmp(post_t39_install,",
            "observed_functional_post_t39_install",
            "[psp1000-functional-post-t39-install] rev=1 ",
            "stage=%u validation=%u install=%u cache_sync=%u"):
        if token not in post_t39_install_snapshot:
            fail("functional post-T39 install snapshot lacks " + token)
    if "functional_post_t39_install &&" in post_t39_install_snapshot or \
            "functional_post_t39_cache_sync)" in post_t39_install_snapshot:
        fail("functional post-T39 install snapshot is gated by install success")
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP",
            "sceKernelDcache", "sceKernelIcache"):
        if forbidden in post_t39_install_snapshot:
            fail("functional post-T39 install snapshot modifies runtime state: " +
                    forbidden)
    post_t39_helper_marker = minimal.find(
            "[psp1000-functional-post-t39-helper] fail=0x%X ")
    post_t39_helper_start = minimal.rfind(
            "if (slide_diag.functional_enabled &&", 0,
            post_t39_helper_marker)
    post_t39_helper_end = minimal.find(
            "if (slide_diag.bsman.functional_post_t39_install",
            post_t39_helper_marker)
    post_t39_helper_snapshot = minimal[
            post_t39_helper_start:post_t39_helper_end]
    for token in ("functional_post_t39_stage >= 5",
            "functional_post_t39_helper_fail",
            "functional_post_t39_helper_owner",
            "functional_post_t39_helper_call_size",
            "functional_post_t39_helper_return_size",
            "functional_post_t39_helper_text",
            "functional_post_t39_helper_size",
            "functional_post_t39_helper_replacement",
            "functional_post_t39_helper_decoded",
            "memcmp(post_t39_helper,",
            "observed_functional_post_t39_helper",
            "owner=0x%08X call=0x%08X call_size=%u",
            "return=0x%08X return_size=%u helper_text=0x%08X",
            "helper_size=%u replacement=0x%08X decoded=0x%08X"):
        if token not in post_t39_helper_snapshot:
            fail("functional post-T39 helper snapshot lacks " + token)
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP",
            "sceKernelDcache", "sceKernelIcache"):
        if forbidden in post_t39_helper_snapshot:
            fail("functional post-T39 helper snapshot modifies runtime state: " +
                    forbidden)
    for token in ("functional_post_t39_cache_sync",
            "activation_wide_scalar_addr[9]",
            "activation_wide_scalar_addr[9]) != 0",
            "activation_wide_scalar_addr[11]",
            "activation_wide_scalar_addr[13]",
            "!observed_functional_post_t39_valid ||",
            "memcmp(post_t39, observed_functional_post_t39",
            "[psp1000-functional-post-t39] entered=%u return=%u ",
            "natural=0x%08X"):
        if token not in post_t39_snapshot:
            fail("functional post-T39 changed-only snapshot lacks " + token)
    for forbidden in ("_sw(", "MAKE_CALL", "MAKE_JUMP",
            "sceKernelDcache", "sceKernelIcache"):
        if forbidden in post_t39_snapshot:
            fail("functional post-T39 snapshot modifies runtime state: " +
                    forbidden)
    if "functional_compat" in bsman_header:
        fail("functional compatibility snapshot changes registration ABI")
    for invented in ("bsman->state_zero_vcall_target_addr",
            "bsman->state_zero_vcall_ra_addr",
            "bsman->state_zero_vcall_result_addr"):
        if invented in functional:
            fail("functional installer uses nonexistent state-zero member " +
                    invented)
    first_scalar_write = functional.find("_sw(0, bsman->prefix_path_mask_addr)")
    validation_publish = functional.find("bsman->functional_validation = 1")
    scalar_validation = functional.find(
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)")
    scalar_sync = functional.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)scalar[i], 4)")
    code_commit = functional.find("_sw(replacement[i], owner[i])")
    install_publish = functional.find("bsman->functional_install = 1")
    if not 0 <= scalar_validation < first_scalar_write < scalar_sync < \
            code_commit < validation_publish < install_publish:
        fail("functional activation validation/scalar/commit ordering regressed")
    before_commit = functional[:code_commit]
    if "_sw(replacement[i], owner[i])" in before_commit:
        fail("functional activation transaction can partially own code")
    for forbidden_offset in ("0x000", "0x004", "0x034", "0x038", "0x044",
            "0x094", "0x098", "0x0B0", "0x0DC", "0x0E8", "0x0F8",
            "0x27C", "0x288", "0x298", "0x2B4", "0x2BC", "0x2C8"):
        if "activation + " + forbidden_offset in functional or \
                "activation_addr + " + forbidden_offset in functional:
            fail("functional activation installer owns forbidden " +
                    forbidden_offset)
    for forbidden in ("activation_leaf_addr", "prefix_result_leaf_addr",
            "prefix_flag_leaf_addr", "prefix_mask_leaf_addr",
            "post_bs_leaf_addr", "post_state_leaf_addr",
            "post_paf_call_leaf_addr", "state_zero_leaf_addr[5]",
            "state_zero_leaf_addr[6]", "state_zero_leaf_addr[7]",
            "activation_wide", "post_impose_vcall", "collection_"):
        if forbidden in functional:
            fail("functional activation installer depends on research owner " +
                    forbidden)
    if functional.count("_sw(replacement[i], owner[i])") != 1:
        fail("functional activation code commit is not one four-owner loop")

    post_t39_start = functional_end
    post_t39_end = kernel.find(
            "static void zeroCtrlInstallPsp1000Post1F0Diagnostic(",
            post_t39_start)
    post_t39 = kernel[post_t39_start:post_t39_end]
    for token in (
            "bsman->functional_validation || !bsman->functional_install ||",
            "activation = mod->text_addr + 0x9304",
            "owner = activation + 0x1E8",
            "!zeroCtrlVshModuleRangeValid(mod, activation + 0x1E8, 8)",
            "(original >> 26) != 3", "_lw(owner + 4) != 0",
            "target = zeroCtrlMipsJumpTarget(owner, original)",
            "target != mod->text_addr + 0x2A168",
            "bsman->activation_wide_leaf_addr[1]",
            "bsman->activation_wide_leaf_addr[2]",
            "zeroCtrlMipsJumpTarget(owner, replacement) != call_leaf",
            "bsman->activation_wide_scalar_addr[8]",
            "bsman->activation_wide_scalar_addr[9]",
            "bsman->activation_wide_scalar_addr[10]",
            "bsman->activation_wide_scalar_addr[11]",
            "bsman->activation_wide_scalar_addr[12]",
            "bsman->activation_wide_scalar_addr[13]",
            "bsman->activation_wide_scalar_addr[14]",
            "bsman->activation_wide_scalar_addr[15]",
            "bsman->activation_wide_scalar_addr[16]",
            "replacement = 0x08000000",
            "helper_fail |= 0x1",
            "helper_fail |= 0x2",
            "helper_fail |= 0x4",
            "helper_fail |= 0x8",
            "if (helper_fail != 0) return;",
            "_sw(activation + 0x1F0, scalar[2])",
            "_sw(0xFFFFFFFF, scalar[4])",
            "_sw(0xFFFFFFFF, scalar[5])",
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)",
            "_sw(replacement, owner)",
            "sceKernelDcacheWritebackInvalidateRange((const void *)owner, 4)",
            "sceKernelIcacheInvalidateRange((const void *)owner, 4)"):
        if token not in post_t39:
            fail("functional post-T39 checkpoint lacks " + token)
    post_t39_validate = post_t39.find(
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)")
    post_t39_scalar_write = post_t39.find("_sw(target, scalar[0])")
    post_t39_code_write = post_t39.find("_sw(replacement, owner)")
    post_t39_dcache = post_t39.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)owner, 4)",
            post_t39_code_write)
    post_t39_icache = post_t39.find(
            "sceKernelIcacheInvalidateRange((const void *)owner, 4)",
            post_t39_dcache)
    if not 0 <= post_t39_validate < post_t39_scalar_write < \
            post_t39_code_write < post_t39_dcache < post_t39_icache:
        fail("functional post-T39 validation/commit ordering regressed")
    if post_t39.count("_sw(replacement, owner)") != 1 or \
            "owner + 4" not in post_t39 or "_sw(" in post_t39[post_t39_code_write +
            len("_sw(replacement, owner)"):]:
        fail("functional post-T39 checkpoint does not own exactly A+0x1E8")
    helper_observation_start = post_t39.find("helper_fail = 0;")
    helper_fail_return = post_t39.find("if (helper_fail != 0) return;")
    helper_stage6 = post_t39.find("bsman->functional_post_t39_stage = 6;")
    first_scalar_init = post_t39.find(
            "scalar[0] = bsman->activation_wide_scalar_addr[8]")
    helper_code_write = post_t39.find("_sw(replacement, owner)")
    helper_bits = [post_t39.find("helper_fail |= 0x%X" % bit,
        helper_observation_start) for bit in (1, 2, 4, 8)]
    if any(position < 0 for position in helper_bits) or not \
            helper_observation_start < max(helper_bits) < helper_fail_return < \
            helper_stage6 < first_scalar_init < helper_code_write:
        fail("functional post-T39 helper failures are not fully observed "
                "before the fail-closed return")
    if "||" in post_t39[helper_observation_start:helper_fail_return]:
        fail("functional post-T39 helper observations are short-circuited")
    for forbidden in ("activation + 0x120", "activation + 0x138",
            "activation + 0x170", "activation + 0x180", "activation + 0x1A4",
            "activation + 0x1C0", "activation + 0x1E0"):
        if forbidden in post_t39:
            fail("functional post-T39 checkpoint restores research owner " +
                    forbidden)
    if "functional_post_t39" in bsman_header:
        fail("functional post-T39 checkpoint changes registration ABI")
    if kernel.count("unsigned int functional_post_t39_stage;") != 1:
        fail("functional post-T39 stage is not one kernel-private scalar")
    post_t39_stages = []
    for stage in range(1, 11):
        token = "bsman->functional_post_t39_stage = %d;" % stage
        if post_t39.count(token) != 1:
            fail("functional post-T39 stage %d is missing or duplicated" % stage)
        post_t39_stages.append(post_t39.find(token))
    if post_t39_stages != sorted(post_t39_stages):
        fail("functional post-T39 stages are not monotonic")
    range_check = post_t39.find(
            "!zeroCtrlVshModuleRangeValid(mod, activation + 0x1E8, 8)")
    fingerprint = post_t39.find("(original >> 26) != 3")
    target_check = post_t39.find("target != mod->text_addr + 0x2A168")
    helper_check = post_t39.find(
            "zeroCtrlMipsJumpTarget(owner, replacement) != call_leaf")
    scalar_check = post_t39.find(
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)")
    scalar_sync = post_t39.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)scalar[i], 4)")
    install_flag = post_t39.find("bsman->functional_post_t39_install = 1")
    cache_flag = post_t39.find(
            "bsman->functional_post_t39_cache_sync = 1")
    if not (post_t39_stages[0] < post_t39_stages[1] < range_check <
            post_t39_stages[2] < fingerprint < post_t39_stages[3] <
            target_check < post_t39_stages[4] < helper_check <
            post_t39_stages[5] < scalar_check < post_t39_stages[6] <
            scalar_sync < post_t39_stages[7] < post_t39_code_write <
            post_t39_dcache < post_t39_icache < post_t39_stages[8] <
            install_flag < cache_flag < post_t39_stages[9]):
        fail("functional post-T39 stage publication ordering regressed")
    wide662_invocation = (
            "WIDE_CALL zeroCtrlWide662Call, zeroCtrlWide662Return, "
            "zeroCtrlWide662Target, zeroCtrlWide662RA, zeroCtrlWide662Resume, "
            "zeroCtrlWide662Hits, zeroCtrlWide662First, zeroCtrlWide662Last, "
            "zeroCtrlWide662Changes, zeroCtrlWide662Zero, "
            "zeroCtrlWide662Nonzero")
    if assembly.count(wide662_invocation) != 1:
        fail("historical Wide662 WIDE_CALL implementation is not intact")
    wide_call_macro = assembly[assembly.find(".macro WIDE_CALL "):
            assembly.find(".endm", assembly.find(".macro WIDE_CALL "))]
    for token in (r"lui $t0, %hi(\resume)",
            r"lw $ra, %lo(\resume)($t0)", r"sw $v0, %lo(\first)($t0)",
            r"sw $v0, %lo(\last)($t0)", r"%hi(\changes)",
            r"%hi(\zero_hits)", r"%hi(\nonzero_hits)"):
        if token not in wide_call_macro:
            fail("historical WIDE_CALL semantics lack " + token)
    call_half = wide_call_macro[:wide_call_macro.find(r"\retname:")]
    if r"\zero_hits" in call_half:
        fail("Wide662 zero-result scalar is repurposed as an entry counter")
    if re.search(r"\b(?:move|addu|addiu|lw|li|ori)\s+\$?v0\b",
            wide_call_macro):
        fail("historical WIDE_CALL helper modifies natural v0")

    post1f0_start = post_t39_end
    post1f0_end = kernel.find("static void zeroCtrlInstallPsp1000ExitDiagnostic(",
            post1f0_start)
    post1f0 = kernel[post1f0_start:post1f0_end]
    for token in (
            "0x1F8, 0x200, 0x20C, 0x214, 0x21C, 0x22C",
            "0x26100001, 0, 0x00002821, 0x00402021, 0x8FBF001C, 0x00002021",
            "0x2A380, 0x2A290, 0x2A698, 0x2A6F8",
            "0, 1, 3, 5, 7, 8",
            "!zeroCtrlVshModuleRangeValid(mod, activation + 0x1E8, 0x50)",
            "(_lw(activation + 0x1E8) >> 26) != 3",
            "mod->text_addr + 0x2A168",
            "_lw(activation + 0x1EC) != 0",
            "original[0] != 0x1040000C",
            "activation + 0x22C",
            "original[4] != 0x1040FFF2",
            "activation + 0x1E8",
            "for (i = 0; i < 52; i++)",
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)",
            "_sw(activation + 0x200, scalar[7])",
            "_sw(activation + 0x208, scalar[10])",
            "_sw(activation + 0x214, scalar[19])",
            "_sw(activation + 0x21C, scalar[28])",
            "_sw(activation + 0x1E8, scalar[41])",
            "_sw(activation + 0x224, scalar[42])",
            "_sw(activation + 0x234, scalar[45])",
            "_sw(replacement[i], owner[i])"):
        if token not in post1f0:
            fail("functional post-1F0 transaction lacks " + token)
    first_post1f0_scalar_write = post1f0.find("_sw(0, scalar[i])")
    last_post1f0_validation = post1f0.find(
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)")
    post1f0_scalar_sync = post1f0.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)scalar[i], 4)")
    post1f0_code_write = post1f0.find("_sw(replacement[i], owner[i])")
    post1f0_dcache = post1f0.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)owner[i], 4)",
            post1f0_code_write)
    post1f0_icache = post1f0.find(
            "sceKernelIcacheInvalidateRange((const void *)owner[i], 4)",
            post1f0_dcache)
    post1f0_install = post1f0.find("bsman->functional_post1f0_install = 1")
    post1f0_cache = post1f0.find("bsman->functional_post1f0_cache_sync = 1")
    if not 0 <= last_post1f0_validation < first_post1f0_scalar_write < \
            post1f0_scalar_sync < post1f0_code_write < post1f0_dcache < \
            post1f0_icache < post1f0_install < post1f0_cache:
        fail("functional post-1F0 validation/commit ordering regressed")
    if post1f0.count("_sw(replacement[i], owner[i])") != 1 or \
            "for (i = 0; i < 6; i++)" not in \
                post1f0[post1f0_code_write - 80:post1f0_code_write]:
        fail("functional post-1F0 transaction is not one six-owner commit")
    if "_sw(" in post1f0[post1f0.find("activation + 0x1E8"):
            first_post1f0_scalar_write] or \
            "_sw(replacement, owner)" in post1f0:
        fail("functional post-1F0 transaction still owns A+0x1E8")
    module_start_functional_start = kernel_module_start.find(
            "zeroCtrlInstallPsp1000FunctionalCompat(mod)")
    module_start_functional = kernel_module_start[module_start_functional_start:
            kernel_module_start.find("zeroCtrlInstallBSManClosedShim(mod)",
                module_start_functional_start)]
    functional_installers = re.findall(
            r"zeroCtrlInstallPsp1000\w+\(mod\)", module_start_functional)
    if functional_installers != [
            "zeroCtrlInstallPsp1000FunctionalCompat(mod)"] or \
            re.search(r"zeroCtrlInstallPsp1000\w+Diagnostic\(mod\)",
                module_start_functional):
        fail("functional path does not exclusively install four-owner compatibility")

    post1f0_install_marker = minimal.find(
            "[psp1000-functional-post1f0-install] rev=1 ")
    post1f0_install_start = minimal.rfind("if (slide_diag.functional_enabled) {",
            0, post1f0_install_marker)
    post1f0_runtime_marker = minimal.find(
            "[psp1000-functional-post1f0] cmp=%u/%u/%u ")
    runtime_start = minimal.rfind(
            "if (slide_diag.bsman.functional_post1f0_install &&", 0,
            post1f0_runtime_marker)
    post1f0_install_snapshot = minimal[
            post1f0_install_start:runtime_start]
    for token in ("validation=%u install=%u cache_sync=%u",
            "memcmp(post1f0_install,",
            "observed_functional_post1f0_install"):
        if token not in post1f0_install_snapshot:
            fail("functional post-1F0 install output lacks " + token)
    if "functional_post1f0_install &&" in post1f0_install_snapshot:
        fail("functional post-1F0 install output is not failure-visible")
    runtime_end = minimal.find("if (slide_diag.functional_enabled &&",
            post1f0_runtime_marker)
    post1f0_runtime = minimal[runtime_start:runtime_end]
    for token in ("functional_post1f0_cache_sync",
            "memcmp(post1f0, observed_functional_post1f0",
            "c200=%u/%u/0x%08X", "c20c=%u/%u/0x%08X",
            "c214=%u/%u/0x%08X", "loop=%u/%u/%u",
            "c22c=%u/%u/0x%08X"):
        if token not in post1f0_runtime:
            fail("functional post-1F0 runtime output lacks " + token)
    for forbidden in ("_sw(", "sceKernelDcache", "sceKernelIcache"):
        if forbidden in post1f0_install_snapshot or forbidden in post1f0_runtime:
            fail("functional post-1F0 output modifies runtime state")
    exit_start = post1f0_end
    exit_end = kernel.find(
            "static void zeroCtrlInstallPsp1000PafDispatchReturnDiagnostic(",
            exit_start)
    exit_diag = kernel[exit_start:exit_end]
    for token in ("0x238, 0x248, 0x258, 0x268",
            "(original[0] >> 26) != 5", "((original[0] >> 21) & 31) != 18",
            "((original[0] >> 16) & 31) != 0", "a + 0x268",
            "(_lw(a + 0x23C) >> 26) != 43",
            "((_lw(a + 0x23C) >> 21) & 31) != 3",
            "((_lw(a + 0x23C) >> 16) & 31) != 18",
            "original[1] != 0x10400003", "a + 0x258",
            "_lw(a + 0x24C) != 0", "mod->text_addr + 0x9038",
            "_lw(a + 0x25C) != 0x02202021", "mod->text_addr + 0x89E4",
            "_lw(a + 0x26C) != 0x02202021",
            "_sw(a + 0x240, b->activation_wide_scalar_addr[53] + 12)",
            "_sw(a + 0x268, b->activation_wide_scalar_addr[53] + 16)",
            "_sw(a + 0x258, scalar[6])", "_sw(a + 0x250, scalar[7])",
            "_sw(a + 0x260, scalar[10])", "_sw(a + 0x270, scalar[19])",
            "_sw(replacement[i], owner[i])"):
        if token not in exit_diag:
            fail("functional exit diagnostic lacks " + token)
    exit_validation = exit_diag.find(
            "!zeroCtrlVshModuleRangeValid(helper, scalar[i], 4)")
    exit_scalar_write = exit_diag.find("_sw(0, scalar[i])")
    exit_scalar_sync = exit_diag.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)scalar[i], 4)")
    exit_code_write = exit_diag.find("_sw(replacement[i], owner[i])")
    exit_code_sync = exit_diag.find(
            "sceKernelIcacheInvalidateRange((const void *)owner[i], 4)")
    if not 0 <= exit_validation < exit_scalar_write < exit_scalar_sync < \
            exit_code_write < exit_code_sync:
        fail("functional exit validation/commit ordering regressed")
    if exit_diag.count("_sw(replacement[i], owner[i])") != 1 or \
            "for (i = 0; i < 4; i++)" not in \
                exit_diag[exit_code_write - 80:exit_code_write]:
        fail("functional exit diagnostic is not exactly four owner writes")
    for forbidden in ("0x1E8", "0x1F8", "0x200", "0x20C", "0x214",
            "0x21C", "0x22C"):
        if "owner[" in exit_diag and "offset[4]" in exit_diag and \
                forbidden in exit_diag[exit_code_write:]:
            fail("functional exit commit restores completed owner " + forbidden)
    if "zeroCtrlFunctionalExitS2Trace:" not in assembly or \
            "beqz $s2" not in assembly[assembly.find(
                "zeroCtrlFunctionalExitS2Trace:"):assembly.find(
                "zeroCtrlFunctionalExitS2TraceEnd:")]:
        fail("functional exit s2 helper does not preserve/test s2 transparently")
    exit_install_marker = minimal.find("[psp1000-functional-exit-install] rev=1 ")
    exit_runtime_marker = minimal.find("[psp1000-functional-exit] s2=%u/%u/%u ")
    if min(exit_install_marker, exit_runtime_marker) < 0 or \
            "memcmp(state, observed_functional_exit_install" not in minimal or \
            "memcmp(state, observed_functional_exit" not in minimal:
        fail("functional exit changed-only records are missing")
    exit_runtime_gate = minimal.rfind(
            "if (slide_diag.bsman.functional_exit_install &&", 0,
            exit_runtime_marker)
    if exit_runtime_gate < 0 or "functional_exit_cache_sync" not in \
            minimal[exit_runtime_gate:exit_runtime_marker]:
        fail("functional exit runtime record is not success-gated")
    exit_runtime_end = minimal.find("if (slide_diag.functional_button_thread",
            exit_runtime_marker)
    exit_runtime_source = minimal[exit_runtime_gate:exit_runtime_end]
    for token in ("0, 1, 2, 9, 11, 13, 18, 20, 22",
            "unsigned int s2_base =",
            "activation_wide_scalar_addr[53]",
            "zeroCtrlReadHelperCounter(s2_base)",
            "zeroCtrlReadHelperCounter(s2_base + 4)",
            "zeroCtrlReadHelperCounter(s2_base + 8)",
            "activation_wide_scalar_addr[index[i]]"):
        if token not in exit_runtime_source:
            fail("functional exit writer lacks safe scalar read " + token)
    if "index[i] - 53" in exit_runtime_source or re.search(
            r"activation_wide_scalar_addr\[53\]\s*\+\s*\(index\[i\]",
            exit_runtime_source):
        fail("functional exit writer retains wrapped relative scalar reads")
    helper_adjacency = (
            "zeroCtrlWide02374143EntryEnd:\n"
            ".end zeroCtrlWide02374143Entry\n\n"
            "/* Functional exit-block observer; address is derived from "
            "validated leaf-10 end. */\n"
            ".globl zeroCtrlFunctionalExitS2Trace")
    if assembly.count(helper_adjacency) != 1:
        fail("functional exit s2 helper is not immediately after leaf-10 end")
    scalar_adjacency = (
            "WIDE_SCALAR zeroCtrlWide02374143Hits\n"
            "WIDE_SCALAR zeroCtrlFunctionalExitS2Zero\n"
            "WIDE_SCALAR zeroCtrlFunctionalExitS2Nonzero\n"
            "WIDE_SCALAR zeroCtrlFunctionalExitS2ZeroTarget\n"
            "WIDE_SCALAR zeroCtrlFunctionalExitS2NonzeroTarget")
    if assembly.count(scalar_adjacency) != 1:
        fail("functional exit s2 scalars are not immediately after scalar 53")
    if "b->activation_wide_scalar_addr[53], 20" not in exit_diag:
        fail("functional exit derived s2 scalar block lacks 20-byte validation")
    return_start = exit_end
    return_end = kernel.find("static void zeroCtrlInstallBSManClosedShim(",
            return_start)
    return_diag = kernel[return_start:return_end]
    for token in (
            "0xDEA1C, 0xDEA20, 0xDEA28, 0xDEA2C, 0xDEA30",
            "0xDEABC, 0xDEAC0",
            "0xDEAD8, 0xDEADC, 0xDEAE0, 0xDEAE4, 0xDEAE8, 0xDEAEC, 0xDEAF0",
            "0x27BDFFD0, 0xAFB00020, 0xAFBF002C, 0xAFB20028, 0xAFB10024",
            "0x0100F809, 0x8CE7002C",
            "0x8FBF002C, 0x8FB20028, 0x8FB10024, 0x8FB00020, 0x00601021",
            "0x03E00008, 0x27BD0030",
            'sceKernelFindModuleByName("scePaf_Module")',
            "paf->text_addr > 0xFFFFFFFFU - 0xDECE0",
            "for (i = 0; i < 14; i++)",
            "(jump >> 26) != 2", "paf->text_addr + 0xDEAC4, jump",
            "paf->text_addr + 0xDEA64",
            "_lw(paf->text_addr + 0xDEAC8) != 0x8E0901A0",
            "(caller >> 26) != 3", "paf->text_addr + 0xDECD8, caller",
            "paf->text_addr + 0xDEA1C",
            "owner = paf->text_addr + 0xDEAEC",
            "replacement = 0x08000000",
            "zeroCtrlMipsJumpTarget(owner, replacement)",
            "b->functional_return_leaf", "b->functional_return_scalar[i]",
            "_sw(replacement, owner)"):
        if token not in return_diag:
            fail("functional PAF-dispatch-return diagnostic lacks " + token)
    return_fingerprint_validation = return_diag.find("for (i = 0; i < 14; i++)")
    return_jump_validation = return_diag.find("(jump >> 26) != 2")
    return_caller_validation = return_diag.find("(caller >> 26) != 3")
    return_scalar_validation = return_diag.find("for (i = 0; i < 7; i++)\n        if")
    return_scalar_write = return_diag.find("_sw(i == 4 || i == 5")
    return_scalar_sync = return_diag.find("sceKernelDcacheWritebackInvalidateRange(",
            return_scalar_write)
    return_code_write = return_diag.find("_sw(replacement, owner)")
    return_code_sync = return_diag.find("sceKernelIcacheInvalidateRange(",
            return_code_write)
    if not 0 <= return_fingerprint_validation < return_jump_validation < \
            return_caller_validation < return_scalar_validation < \
            return_scalar_write < return_scalar_sync < return_code_write < \
            return_code_sync or return_diag.count("_sw(replacement, owner)") != 1:
        fail("functional PAF-dispatch-return validation/transaction ordering regressed")
    if "_sw(" in return_diag[:return_scalar_write] or \
            "_sw(i == 4 || i == 5 ? 0xFFFFFFFF : 0," not in return_diag:
        fail("functional PAF-dispatch-return writes before validation or changes scalars")
    return_register = kernel[kernel.find("void zeroCtrlRegisterActivationReturn("):
            kernel.find("void zeroCtrlRegisterActivationCallerRA(")]
    for token in ("zeroCtrlRegistrationLeafValid(helper, copied.leaf_addr,",
            "for (i = 0; i < 7; i++)",
            "zeroCtrlVshModuleRangeValid(helper, copied.scalar_addr[i], 4)",
            "copied.leaf_end_addr - copied.leaf_addr"):
        if token not in return_register:
            fail("activation-return registration lacks " + token)
    return_asm = assembly[assembly.find("zeroCtrlFunctionalActivationReturnTrace:"):
            assembly.find("zeroCtrlFunctionalActivationReturnTraceEnd:")]
    if not return_asm or "jr $ra" not in return_asm or \
            re.search(r"\b(?:move|addu|addiu|lw|li|ori)\s+\$?v0\b", return_asm) or \
            re.search(r"\b(?:jal|jalr|syscall)\b", return_asm):
        fail("activation-return helper does not transparently preserve ra/v0")
    state_route_start = kernel.find(
            "static void zeroCtrlInstallPsp1000PostBSRouteDiagnostic(")
    state_route_end = kernel.find("static void zeroCtrlInstallBSManClosedShim(",
            state_route_start)
    state_route = kernel[state_route_start:state_route_end]
    for token in ("0x0B0, 0x0DC, 0x27C, 0x288, 0x298",
            "_lw(owner[0]) != 0x1040000A",
            "zeroCtrlMipsBranchTarget(owner[0], _lw(owner[0])) != a + 0xDC",
            "(_lw(a + 0xB4) >> 26) != 36",
            "((_lw(a + 0xB4) >> 21) & 31) != 19",
            "((_lw(a + 0xB4) >> 16) & 31) != 2",
            "_lw(owner[1]) != 0x10400066",
            "zeroCtrlMipsBranchTarget(owner[1], _lw(owner[1])) != a + 0x278",
            "(_lw(a + 0xE0) >> 26) != 15",
            "((_lw(a + 0xE0) >> 16) & 31) != 2",
            "_lw(owner[2]) != 0x1243FF73",
            "zeroCtrlMipsBranchTarget(owner[2], _lw(owner[2])) != a + 0x4C",
            "(_lw(a + 0x280) >> 26) != 15",
            "((_lw(a + 0x280) >> 16) & 31) != 2",
            "_lw(owner[3]) != 0x1460FF71",
            "zeroCtrlMipsBranchTarget(owner[3], _lw(owner[3])) != a + 0x50",
            "_lw(a + 0x28C) != 0x8FBF001C",
            "_lw(owner[4]) != 0x1460FF6E",
            "zeroCtrlMipsBranchTarget(owner[4], _lw(owner[4])) != a + 0x54",
            "_lw(a + 0x29C) != 0x8FB60018",
            "leaf[i + 2] = b->state_zero_leaf_addr[i]",
            "_sw(a + 0xDC, scalar[0]); _sw(a + 0xB8, scalar[1])",
            "_sw(a + 0x278, scalar[4]); _sw(a + 0xE4, scalar[5])",
            "_sw(a + 0x4C, scalar[11]); _sw(a + 0x284, scalar[12])",
            "_sw(a + 0x290, scalar[13]); _sw(a + 0x50, scalar[14])",
            "_sw(a + 0x2A0, scalar[15]); _sw(a + 0x54, scalar[16])",
            "for (i = 17; i < 21; i++) _sw(0xFFFFFFFF, scalar[i])",
            "_sw(0, scalar[21])", "_sw(0, scalar[22])"):
        if token not in state_route:
            fail("functional state-route diagnostic lacks " + token)
    state_route_validation = state_route.find("for (i = 0; i < 23; i++)")
    state_route_scalar_write = state_route.find("_sw(a + 0xDC, scalar[0])")
    state_route_scalar_sync = state_route.find(
            "sceKernelDcacheWritebackInvalidateRange((const void *)scalar[i], 4)")
    state_route_code_write = state_route.find("_sw(replacement[i], owner[i])")
    state_route_code_sync = state_route.find(
            "sceKernelIcacheInvalidateRange((const void *)owner[i], 4)")
    if not 0 <= state_route_validation < state_route_scalar_write < \
            state_route_scalar_sync < state_route_code_write < \
            state_route_code_sync:
        fail("functional state-route validation/commit ordering regressed")
    if state_route.count("_sw(replacement[i], owner[i])") != 1 or \
            "for (i = 0; i < 5; i++)" not in \
                state_route[state_route_code_write - 80:state_route_code_write]:
        fail("functional state-route transaction is not exactly five writes")
    if "_sw(" in state_route[:state_route_scalar_write] or \
            re.search(r"_sw\([^;]*scalar\[10\]", state_route):
        fail("functional state-route resets state before validation or compatibility")
    for forbidden in ("state_zero_counter_addr[1]",
            "state_zero_counter_addr[2]", "state_zero_value_addr[4]",
            "state_zero_value_addr[5]", "state_zero_value_addr[6]",
            "state_zero_15to14_effective_result_addr",
            "state_zero_15to14_substitution_hits_addr"):
        if forbidden in state_route:
            fail("functional state-route touches vcall compatibility state " + forbidden)
    for forbidden in ("a + 0x2A4", "0x6C", "0x1E8", "0x1F8", "0x200",
            "0x20C", "0x214", "0x21C", "0x22C", "0x238", "0x248",
            "0x258", "0x268", "0x9038"):
        if forbidden in state_route[state_route_code_write:]:
            fail("functional state-route commit includes forbidden owner " + forbidden)
    post_bs_call = assembly[assembly.find("zeroCtrlPostBSManBranchTrace:"):
            assembly.find("zeroCtrlPostBSManBranchTraceEnd:")]
    post_state_call = assembly[assembly.find("zeroCtrlPostStateBranchTrace:"):
            assembly.find("zeroCtrlPostStateBranchTraceEnd:")]
    compare_call = assembly[assembly.find("zeroCtrlStateZeroCompareTrace:"):
            assembly.find("zeroCtrlStateZeroCompareTraceEnd:")]
    word_call = assembly[assembly.find("zeroCtrlStateZeroWordTrace:"):
            assembly.find("zeroCtrlStateZeroWordTraceEnd:")]
    byte_call = assembly[assembly.find("zeroCtrlStateZeroByteTrace:"):
            assembly.find("zeroCtrlStateZeroByteTraceEnd:")]
    transparent_helpers = (
        ("zeroCtrlPostBSManBranchTrace", post_bs_call, 16,
         (("t0", 0), ("t1", 4), ("t2", 8), ("t9", 12))),
        ("zeroCtrlPostStateBranchTrace", post_state_call, 16,
         (("t0", 0), ("t1", 4), ("t2", 8), ("t9", 12))),
        ("zeroCtrlStateZeroCompareTrace", compare_call, 16,
         (("t0", 0), ("t1", 4), ("t2", 8), ("t9", 12))),
        ("zeroCtrlStateZeroWordTrace", word_call, 16,
         (("t0", 0), ("t1", 4), ("t9", 8))),
        ("zeroCtrlStateZeroByteTrace", byte_call, 16,
         (("t0", 0), ("t1", 4), ("t9", 8))),
    )
    counter_macro = re.search(
        r"\.macro RECORD_PREFIX_COUNTER counter\n(.*?)\.endm", assembly, re.S)
    expected_counter_macro = (
        "lui     $t0, %hi(\\counter)",
        "lw      $t2, %lo(\\counter)($t0)",
        "addiu   $t2, $t2, 1",
        "sw      $t2, %lo(\\counter)($t0)",
    )
    if not counter_macro or tuple(line.strip() for line in
            counter_macro.group(1).splitlines() if line.strip()) != \
            expected_counter_macro:
        fail("RECORD_PREFIX_COUNTER body no longer has its exact modeled writes")

    # This is intentionally a closed grammar.  Adding any instruction form to
    # these helpers requires teaching the verifier whether that form writes a GPR.
    helper_forms = (
        (re.compile(r"addiu\s+\$(\w+),\s*\$\w+,\s*-?(?:0x[0-9A-Fa-f]+|\d+)$"), 1),
        (re.compile(r"lui\s+\$(\w+),\s*%hi\([^)]+\)$"), 1),
        (re.compile(r"lw\s+\$(\w+),\s*[^,]+\(\$\w+\)$"), 1),
        (re.compile(r"sw\s+\$\w+,\s*[^,]+\(\$\w+\)$"), 0),
        (re.compile(r"ori\s+\$(\w+),\s*\$\w+,\s*(?:0x[0-9A-Fa-f]+|\d+)$"), 1),
        (re.compile(r"beq\s+\$\w+,\s*\$\w+,\s*\w+$"), 0),
        (re.compile(r"(?:beqz|bnez)\s+\$\w+,\s*\w+$"), 0),
        (re.compile(r"b\s+\w+$"), 0),
        (re.compile(r"jr\s+\$\w+$"), 0),
        (re.compile(r"nop$"), 0),
    )
    macro_form = re.compile(r"RECORD_PREFIX_COUNTER\s+\w+$")
    for name, helper, frame, saved in transparent_helpers:
        helper_start = assembly.find(name + ":")
        if assembly.rfind(".set noreorder", 0, helper_start) < \
                assembly.rfind(".set reorder", 0, helper_start):
            fail(name + " is not protected by .set noreorder")
        if frame % 8:
            fail(name + " frame violates the MIPS EABI 8-byte alignment")
        instructions = [line.split("#", 1)[0].strip()
                        for line in helper.splitlines()]
        instructions = [line for line in instructions if line and
                        not line.startswith((".", name + ":")) and
                        not re.fullmatch(r"\d+:", line)]
        classified = []
        for line in instructions:
            if macro_form.fullmatch(line):
                classified.append((line, {"t0", "t2"}))
                continue
            matches = [(pattern.fullmatch(line), writes)
                       for pattern, writes in helper_forms]
            matches = [(match, writes) for match, writes in matches if match]
            if len(matches) != 1:
                fail(name + " contains an unknown or ambiguous instruction form: " + line)
            match, writes = matches[0]
            classified.append((line, {match.group(1)} if writes else set()))

        expected_prologue = ["addiu   $sp, $sp, -%d" % frame] + [
            "sw      $%s, %d($sp)" % (reg, offset) for reg, offset in saved]
        if instructions[:len(expected_prologue)] != expected_prologue:
            fail(name + " does not have its exact required save layout")
        written = set().union(*(writes for _line, writes in classified))
        expected_written = {reg for reg, _ in saved} | {"sp"}
        if written != expected_written:
            fail(name + " writes unexpected GPRs or omits preservation coverage: " +
                 repr(sorted(written)))
        for reg, offset in saved:
            save_line = "sw      $%s, %d($sp)" % (reg, offset)
            save_index = instructions.index(save_line)
            first_write = next(i for i, (_line, writes) in enumerate(classified)
                               if reg in writes)
            if save_index >= first_write:
                fail(name + " modifies " + reg + " before saving its entry value")

        restored = [(reg, offset) for reg, offset in reversed(saved[:-1])]
        tail = ["lw      $%s, %d($sp)" % item for item in restored]
        tail += ("addiu   $sp, $sp, %d" % frame, "jr      $t9",
                 "lw      $t9, -%d($sp)" % (frame - saved[-1][1]))
        if instructions[-len(tail):] != tail:
            fail(name + " lacks the proven balanced-frame/JR-delay t9 restore")
        sp_writes = [(i, line) for i, (line, writes) in enumerate(classified)
                     if "sp" in writes]
        if sp_writes != [(0, expected_prologue[0]),
                         (len(instructions) - 3, tail[-3])]:
            fail(name + " does not restore its temporary frame exactly once")
        if re.search(r"sceIo|sceKernel|Alloc|malloc", helper):
            fail(name + " performs I/O, a kernel operation, or allocation")
        for forbidden in ("CompatMode", "SubstitutionHits", "15To14",
                          "InvalidMode"):
            if forbidden in helper:
                fail(name + " performs a compatibility transformation")
    if "sw      $v0, %lo(zeroCtrlPostStateNaturalValue)($t0)" not in post_bs_call or \
            "zeroCtrlPostBSManEffectiveResult" not in post_bs_call:
        fail("historical post-BS helper no longer saves natural v0 before routing")
    if "lw      $t2, %lo(zeroCtrlPostStateNaturalValue)($t0)" not in \
            post_state_call or re.search(r"\bbeqz?\s+\$v0\b", post_state_call):
        fail("historical post-state helper no longer routes only on saved value")
    for helper, tokens in ((compare_call, ("zeroCtrlStateZeroCompareLeft",
                    "zeroCtrlStateZeroCompareRight", "beq     $s2, $v1")),
            (word_call, ("zeroCtrlStateZeroWordValue", "bnez    $v1")),
            (byte_call, ("zeroCtrlStateZeroByteValue", "bnez    $v1"))):
        if not helper or any(token not in helper for token in tokens):
            fail("historical state decision helper semantics changed")
    state_install_marker = minimal.find(
            "[psp1000-functional-state-route-install] rev=1 ")
    state_runtime_marker = minimal.find(
            "[psp1000-functional-state-route] bs_ret=%u ")
    if min(state_install_marker, state_runtime_marker) < 0 or \
            "memcmp(state, observed_functional_post_bs_install" not in minimal or \
            "memcmp(state, observed_functional_post_bs" not in minimal:
        fail("functional state-route changed-only records are missing")
    state_runtime_gate = minimal.rfind(
            "if (slide_diag.bsman.functional_post_bs_install &&", 0,
            state_runtime_marker)
    if state_runtime_gate < 0 or "functional_post_bs_cache_sync" not in \
            minimal[state_runtime_gate:state_runtime_marker]:
        fail("functional state-route runtime record is not success-gated")
    state_install_gate = minimal.rfind("if (slide_diag.functional_enabled) {",
            0, state_install_marker)
    if "functional_post_bs_install &&" in \
            minimal[state_install_gate:state_runtime_gate]:
        fail("functional state-route install record is not failure-visible")
    if any(token in state_route for token in ("sceKernelSuspendThread",
            "sceKernelDelayThread", "sceKernelLock", "atomic snapshot")):
        fail("functional state-route introduces snapshot locking")
    if "sizeof(ZeroCtrlActivationReturnRegistration) == 36" not in bsman_header:
        fail("activation-return registration size guard is missing")
    for marker in ("[psp1000-functional-paf-dispatch-return-install] ",
            "[psp1000-functional-paf-dispatch-return] returns=%u "):
        if marker not in minimal:
            fail("activation-return changed-only output lacks " + marker)
    paf_return_install_marker = minimal.find(
            "[psp1000-functional-paf-dispatch-return-install] ")
    paf_return_runtime_marker = minimal.find(
            "[psp1000-functional-paf-dispatch-return] returns=%u ")
    paf_return_install_gate = minimal.rfind(
            "if (slide_diag.functional_enabled) {", 0,
            paf_return_install_marker)
    paf_return_runtime_gate = minimal.rfind(
            "if (slide_diag.bsman.functional_return_install &&", 0,
            paf_return_runtime_marker)
    if paf_return_install_gate < 0 or \
            "memcmp(state, observed_functional_return_install" not in \
            minimal[paf_return_install_gate:paf_return_install_marker] or \
            "functional_return_install &&" in \
            minimal[paf_return_install_gate:paf_return_install_marker]:
        fail("PAF-dispatch-return install output is not failure-visible/changed-only")
    if paf_return_runtime_gate < 0 or \
            "functional_return_cache_sync" not in \
            minimal[paf_return_runtime_gate:paf_return_runtime_marker] or \
            "memcmp(state, observed_functional_return" not in \
            minimal[paf_return_runtime_gate:paf_return_runtime_marker]:
        fail("PAF-dispatch-return runtime output is not success-gated/changed-only")
    research_state_owner = kernel[kernel.find(
            "static void zeroCtrlInstallBSManClosedShim("):
            kernel.find("int OnModuleStart(SceModule2 *mod)")]
    for token in ("0x27C, 0x288, 0x298, 0x2A4, 0x2B4, 0x2BC, 0x2C8",
            "pc == 3 ? 0x0C000000 : 0x08000000",
            "bsman->state_zero_original[6] != 0x0040F809",
            "bsman->state_zero_original[7] != 0"):
        if token not in research_state_owner:
            fail("research state owner mapping no longer proves functional +0x2A4")
    for marker in (
            "[psp1000-functional] activation_compat_validation=1",
            "[psp1000-functional] activation_compat_install=1"):
        if marker not in minimal:
            fail("functional activation marker missing " + marker)
    user_module_start = user[user.find("int OnModuleStart(SceModule2 *mod)"):
        user.find("int module_start(")]
    for token in ("zeroCtrlIsPsp1000SlideFunctionalEnabled()",
            "if(!psp1000_experiment &&",
            'strcmp(mod->modname, "slide_plugin_module") == 0',
            "MAKE_CALL(mod->text_addr+0xC990",
            "zeroCtrlRedir2Stub(mod->text_addr+0x9038"):
        if token not in user_module_start:
            fail("legacy user SlidePlugin integration lacks " + token)
    legacy_gate = user_module_start.find("if(!psp1000_experiment &&")
    legacy_clock = user_module_start.find("MAKE_CALL(mod->text_addr+0xC990",
            legacy_gate)
    legacy_init = user_module_start.find(
            "zeroCtrlRedir2Stub(mod->text_addr+0x9038", legacy_clock)
    legacy_end = user_module_start.find("\n\t}", legacy_init)
    if not 0 <= legacy_gate < legacy_clock < legacy_init < legacy_end:
        fail("legacy SlidePlugin hooks are not contained by the experiment exclusion")
    pre_legacy = user_module_start[:legacy_gate]
    post_legacy = user_module_start[legacy_end:]
    for hook in ("MAKE_CALL(mod->text_addr+0xC990",
            "zeroCtrlRedir2Stub(mod->text_addr+0x9038"):
        if hook in pre_legacy or hook in post_legacy:
            fail("PSP-1000 experiment can reach a legacy SlidePlugin hook")
    if "|| psp1000_functional" in user_module_start or \
            "functional_valid" in user_module_start:
        fail("functional PSP-1000 still opts into legacy SlidePlugin hooks")
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
        fail("legacy direct +57B0 runtime execution is not compile-time disabled")
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
    if re.search(r"\(.*\*.*\)\s*\(.*0x58D4", button):
        fail("functional HOME directly calls the +58D4 mechanism")
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
            "sw      $zero, %lo(zeroCtrlSlidePrefixPafCompatMode)($t0)",
            "sw      $zero, %lo(zeroCtrlPostBSManCompatMode)($t0)",
            "sw      $zero, %lo(zeroCtrlStateZero15To14CompatMode)($t0)",
            "sw      $zero, %lo(zeroCtrlPostVshCompatMode)($t0)",
            "\n66:", "sw      $v0, %lo(zeroCtrlPostVshEffectiveResult)",
            "lw      $ra, %lo(zeroCtrlPostVshSavedRA)"):
        if token not in post_vsh_return:
            fail("T31 exact return source lacks " + token)
    if not (post_vsh_return.find("zeroCtrlPostVshNaturalResult") <
            post_vsh_return.find("zeroCtrlPostVshCompatMode") <
            post_vsh_return.find("bne     $t1, $t2, 66f") <
            post_vsh_return.find("bne     $v0, $t2, 66f") <
            post_vsh_return.find("addu    $v0, $zero, $zero") <
            post_vsh_return.find("sw      $t1, %lo(zeroCtrlPostVshSubstitutionHits)") <
            post_vsh_return.find("sw      $zero, %lo(zeroCtrlSlidePrefixPafCompatMode)") <
            post_vsh_return.find("sw      $zero, %lo(zeroCtrlPostBSManCompatMode)") <
            post_vsh_return.find("sw      $zero, %lo(zeroCtrlStateZero15To14CompatMode)") <
            post_vsh_return.find("sw      $zero, %lo(zeroCtrlPostVshCompatMode)") <
            post_vsh_return.find("\n66:") <
            post_vsh_return.find("zeroCtrlPostVshEffectiveResult")):
        fail("T31 natural/guard/substitution/effective ordering is invalid")
    successful_vsh_block = post_vsh_return[
        post_vsh_return.find("addu    $v0, $zero, $zero"):
        post_vsh_return.find("\n66:")]
    for mode in ("zeroCtrlSlidePrefixPafCompatMode",
            "zeroCtrlPostBSManCompatMode", "zeroCtrlStateZero15To14CompatMode",
            "zeroCtrlPostVshCompatMode"):
        if successful_vsh_block.count("sw      $zero, %lo(" + mode + ")($t0)") != 1:
            fail("T31 successful substitution does not exclusively clear " + mode)
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
        kernel.find("static void zeroCtrlInstallPsp1000FunctionalCompat")]
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
    for token in ("allow_registration = bsman->activation_wide_enabled ||\n"
            "            slide_diag.functional_enabled;",
            "if (!registration) return allow_registration;",
            "if (!allow_registration || !bsman->registered) return 0;",
            "for (wide_index = 0; wide_index < 11; wide_index++)",
            "zeroCtrlRegistrationLeafValid(helper, copied.leaf_addr[wide_index],",
            "for (wide_index = 0; wide_index < 54; wide_index++)",
            "zeroCtrlVshModuleRangeValid(helper,\n"
            "                    copied.scalar_addr[wide_index], 4)",
            "copied.leaf_end_addr[wide_index] - copied.leaf_addr[wide_index]"):
        if token not in optional_register:
            fail("ActivationWide metadata registration lacks " + token)
    if optional_register.count("return allow_registration;") != 1 or \
            optional_register.count("!allow_registration") != 1 or \
            optional_register.find("if (!registration)") > optional_register.find("memcpy("):
        fail("ActivationWide NULL/non-NULL paths do not share one permission")
    functional_wide_gate = kernel[kernel.find(
            "slide_diag.bsman.activation_wide_enabled ="):
            kernel.find(";", kernel.find(
                "slide_diag.bsman.activation_wide_enabled ="))]
    if "!slide_diag.functional_enabled" not in functional_wide_gate or \
            "slide_diag.functional_enabled ||" in functional_wide_gate:
        fail("functional metadata permission enables ActivationWide research mode")
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
        r"\blui\s+t0,", r"\bsw\s+zero,", r"\blui\s+t0,", r"\bsw\s+zero,",
        r"\blui\s+t0,", r"\bsw\s+zero,", r"\blui\s+t0,", r"\bsw\s+zero,",
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
        ("zeroCtrlPostVshCompatMode", [("lw", 9, 8), ("sw", 0, 8)]),
        ("zeroCtrlPostVshArgument", [("lw", 9, 8)]),
        ("zeroCtrlPostVshSubstitutionHits", [("lw", 9, 8), ("sw", 9, 8)]),
        ("zeroCtrlSlidePrefixPafCompatMode", [("sw", 0, 8)]),
        ("zeroCtrlPostBSManCompatMode", [("sw", 0, 8)]),
        ("zeroCtrlStateZero15To14CompatMode", [("sw", 0, 8)]),
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
    disarm_pcs = [use_pcs[name][0] for name in (
        "zeroCtrlSlidePrefixPafCompatMode", "zeroCtrlPostBSManCompatMode",
        "zeroCtrlStateZero15To14CompatMode")]
    disarm_pcs.append(use_pcs["zeroCtrlPostVshCompatMode"][1])
    substitution_store = use_pcs["zeroCtrlPostVshSubstitutionHits"][1]
    if not substitution_store < min(disarm_pcs) <= max(disarm_pcs) < bypass:
        fail("T31 linked mode clears are not confined after successful substitution")
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
    if re.search(r"\bgp\b|\bjalr?\b|sceIo|Alloc|malloc", body):
        fail("post-BSMan branch trace uses gp, a call, I/O, or allocation")
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
            "zeroCtrlVsh589CCallTrace", "zeroCtrlVsh589CCallTraceTail",
            "zeroCtrlVsh589CCallTraceEnd",
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
    if symbol_addresses["zeroCtrlVsh589CCallTrace"] != \
            symbol_addresses["zeroCtrlTrigger14020"] + 24 or \
            symbol_addresses["zeroCtrlVsh589CCallTraceTail"] != \
            symbol_addresses["zeroCtrlVsh589CCallTrace"] + 72 or \
            symbol_addresses["zeroCtrlVsh589CCallTraceEnd"] != \
            symbol_addresses["zeroCtrlVsh589CCallTrace"] + 80:
        fail("linked VSH +58AC helper adjacency/size/tail offset changed")
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
    nm = subprocess.check_output(["psp-nm", "-n", str(stub_object)], text=True)
    addresses = {match.group(2): int(match.group(1), 16) for match in
            re.finditer(r"^([0-9a-fA-F]+)\s+\w\s+(\S+)$", nm, re.M)}
    for symbol in ("zeroCtrlTrigger14020", "zeroCtrlVsh589CCallTrace",
            "zeroCtrlVsh589CCallTraceTail", "zeroCtrlVsh589CCallTraceEnd"):
        if symbol not in addresses:
            fail("VSH +58AC object lacks symbol " + symbol)
    if addresses["zeroCtrlVsh589CCallTrace"] != \
            addresses["zeroCtrlTrigger14020"] + 24 or \
            addresses["zeroCtrlVsh589CCallTraceTail"] != \
            addresses["zeroCtrlVsh589CCallTrace"] + 72 or \
            addresses["zeroCtrlVsh589CCallTraceEnd"] != \
            addresses["zeroCtrlVsh589CCallTrace"] + 80:
        fail("VSH +58AC object helper adjacency/size/tail offset changed")
    vsh589c_body = function_body(disassembly, "zeroCtrlVsh589CCallTrace")
    for scalar, hi, lo in (("zeroCtrlTrigger13F6CHits", 1, 2),
            ("zeroCtrlTrigger58D4Request", 1, 1),
            ("zeroCtrlTrigger14020Hits", 1, 2)):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b", vsh589c_body)) != hi or \
                len(re.findall(r"R_MIPS_LO16\s+" + scalar + r"\b", vsh589c_body)) != lo:
            fail("VSH +58AC helper relocation grammar changed for " + scalar)
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
            ("zeroCtrlTrigger58D4Hits", 2, 4),
            ("zeroCtrlTrigger13F6CHits", 1, 2),
            ("zeroCtrlTrigger14020Hits", 1, 2)):
        if len(re.findall(r"R_MIPS_HI16\s+" + scalar + r"\b",
                trigger58)) != hi_count or len(re.findall(
                r"R_MIPS_LO16\s+" + scalar + r"\b", trigger58)) != lo_count:
            fail("zeroCtrlTrigger58D4 has wrong relocations for " + scalar)
    for scalar, operation in (
            ("zeroCtrlTrigger58D4FunctionalMode", r"\blw\s+t1,"),
            ("zeroCtrlTrigger58D4Request", r"\blw\s+t1,"),
            ("zeroCtrlTrigger58D4Request", r"\bsw\s+zero,"),
            ("zeroCtrlTrigger58D4OriginalTarget", r"\blw\s+t0,"),
            ("zeroCtrlTrigger13F6CHits", r"\blw\s+t1,"),
            ("zeroCtrlTrigger13F6CHits", r"\bsw\s+t1,"),
            ("zeroCtrlTrigger14020Hits", r"\blw\s+t1,"),
            ("zeroCtrlTrigger14020Hits", r"\bsw\s+t1,")):
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
        ("zeroCtrlPostVshCompatMode", 2, 2, None),
        ("zeroCtrlSlidePrefixPafCompatMode", 1, 1, r"\bsw\s+zero,"),
        ("zeroCtrlPostBSManCompatMode", 1, 1, r"\bsw\s+zero,"),
        ("zeroCtrlStateZero15To14CompatMode", 1, 1, r"\bsw\s+zero,"),
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
    for instruction in (r"\blw\s+t1,", r"\bsw\s+zero,"):
        if not re.search(instruction + r"[^\n]*\n[^\n]*R_MIPS_LO16\s+"
                r"zeroCtrlPostVshCompatMode\b", post_vsh_return):
            fail("T31 return does not bind VSH mode load/clear")
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
