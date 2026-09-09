#!/usr/bin/env python3
"""Fail the build when statically-verifiable PSP-1000 safety rules regress."""

import argparse
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


def fail(message):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(1)


def check_sources(root):
    kernel = (root / "kernel/main.c").read_text()
    user = (root / "user/main.c").read_text()
    registration_header = (root / "kernel/sony_start_trace.h").read_text()
    assembly = (root / "user/stub.S").read_text()
    build = (root / "build_linux.sh").read_text()
    if '"PSP1000SlideTriggerMode", "Disabled"' not in kernel:
        fail("dangerous trigger selector does not default to Disabled")
    if '"PSP1000Diagnostics", "Disabled"' not in kernel:
        fail("production diagnostics do not default to Disabled")
    if '"PSP1000SonyStartTrace", "Disabled"' not in kernel:
        fail("Sony module_start tracing does not default to Disabled")
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
            SONY_EXIT_STUB, SONY_EXIT_STUB_END):
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
