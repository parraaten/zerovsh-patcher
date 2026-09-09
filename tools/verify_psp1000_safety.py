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
        'slide_diag.bsman.activation_enabled &&',
        'strcmp(psp1000PafPresentCompat, "Enabled") == 0',
        '_sw(bsman->paf_compat_enabled ? 1 : 0,',
        'psp1000_paf_present_compat=',
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
        'results=bs:0x%08X',
    ):
        if required not in kernel:
            fail("activation localization trace is missing " + required)
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
    if re.search(r"(?:addiu|addu|or|move|lw|lbu)\s+\$v0", return_leaf):
        fail("BSMan return trace modifies the natural result")
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
    if "lbu     $v0, 0x0DCD($s3)" not in post_bs:
        fail("post-BSMan result branch does not reproduce its LBU delay slot")
    if "lw      $v0, %lo(zeroCtrlPostStateDelayValue)" not in post_state:
        fail("post-BSMan state branch does not reproduce its LUI delay value")
    for symbol in ("zeroCtrlPostPafReturnTrace", "zeroCtrlPostVshReturnTrace"):
        start = assembly.find(symbol + ":")
        end = assembly.find(symbol + "End:", start)
        leaf = assembly[start:end]
        if re.search(r"(?:addiu|addu|or|move|lw|lbu)\s+\$v0", leaf):
            fail(symbol + " modifies a natural imported result")
    fast_poll = kernel[kernel.find(
        "if (slide_diag.bsman.activation_enabled)"):kernel.find(
            "#undef WRITE_LATE_FLAG")]
    if "zeroCtrlDiagnosticsMemory" in fast_poll or \
            "zeroCtrlDiagnosticsCapturePartitions" in fast_poll:
        fail("activation fast-poll path performs a memory query")
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


def check_elf(elf):
    nm = subprocess.check_output(["psp-nm", "-n", str(elf)], text=True)
    for symbol in STUBS:
        if not re.search(r"^[0-9a-fA-F]+\s+\w\s+" + symbol + r"$", nm, re.M):
            fail("missing helper trigger stub symbol " + symbol)
    for symbol in (SONY_ENTRY_STUB, SONY_ENTRY_STUB_END,
            SONY_EXIT_STUB, SONY_EXIT_STUB_END, BSMAN_STUB, BSMAN_STUB_END,
            BSMAN_RETURN_TRACE, BSMAN_RETURN_TRACE_END,
            *PREFIX_TRACE_STUBS, *POST_TRACE_STUBS):
        if not re.search(r"^[0-9a-fA-F]+\s+\w\s+" + symbol + r"$", nm, re.M):
            fail("missing Sony module_start wrapper symbol " + symbol)
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
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b", return_trace):
        fail("BSMan return trace uses gp, sp, or a call")
    v0_lines = [line for line in return_trace.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]):
        fail("BSMan return trace does not only record the natural v0")
    if not re.search(r"\blw\s+ra,", return_trace) or \
            not re.search(r"\bjr\s+ra\b", return_trace):
        fail("BSMan return trace does not restore and return through ra")
    for symbol in PREFIX_TRACE_STUBS + POST_TRACE_STUBS:
        prefix_trace = function_body(disassembly, symbol)
        if re.search(r"\bgp\b|\bjalr?\b", prefix_trace):
            fail(symbol + " uses gp or a call")
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
            v0_lines = [line for line in prefix_trace.splitlines()
                        if re.search(r"\bv0\b", line)]
            if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]):
                fail(symbol + " does not only record the natural result")


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
    if re.search(r"\bgp\b|\bsp\b|\bjalr?\b", return_trace):
        fail("BSMan return trace uses gp, sp, or a call")
    v0_lines = [line for line in return_trace.splitlines() if re.search(r"\bv0\b", line)]
    if len(v0_lines) != 1 or not re.search(r"\bsw\s+v0,", v0_lines[0]):
        fail("BSMan return trace does not only record the natural v0")
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
