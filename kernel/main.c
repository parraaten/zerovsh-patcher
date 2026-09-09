/*
 * This file is part of ZeroVSH Patcher.

 * ZeroVSH Patcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * ZeroVSH Patcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ZeroVSH Patcher. If not, see <http://www.gnu.org/licenses/ .
 */

//Headers
#include <pspsdk.h>
#include <psputilsforkernel.h>
#include <pspiofilemgr.h>
#include <pspiofilemgr_fcntl.h>
#include <pspsysmem_kernel.h>
#include <pspctrl.h>
#include <pspreg.h>
#include <pspsuspend.h>
#include <pspdisplay_kernel.h>

// from CFW SDK
#include "pspmodulemgr_kernel.h"
#include "psploadcore.h"
#include "systemctrl.h"
#include "systemctrl_se.h"

#include "logger.h"
#include "blacklist.h"
#include "resolver.h"
#include "hook.h"
#include "sony_start_trace.h"
#include "bsman_closed_shim.h"
#include "minini/minIni.h"

#include "zerovsh_upatcher.h"

PSP_MODULE_INFO("ZeroVSH_Patcher_Kernel", 0x1007, 0, 2);
PSP_MAIN_THREAD_ATTR(0);

#define UNUSED __attribute__((unused))
#define MAKE_CALL(a, f) _sw(0x0C000000 | (((u32)(f) >> 2) & 0x03FFFFFF), a); 
#define REDIRECT_FUNCTION(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a); _sw(0x00000000, a+4); 
#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a);


typedef struct {
	const char *modname;
	const char *modfile;
} modules;

modules g_modules_mod[] = {
        { "vsh_module", "vshmain.prx" },
        { "scePaf_Module", "paf.prx" },
        { "sceVshCommonGui_Module", "common_gui.prx" },
};

const char *exts[] = { ".rco", ".pmf", ".bmp", ".pgf", ".prx", ".dat" };

int model;

PspIoDrv *lflash;
PspIoDrv *fatms;
static PspIoDrvArg * ms_drv = NULL;
STMOD_HANDLER previous = NULL;
int brightness = -1;

enum zeroCtrlSlideState {
        ZERO_SLIDE_LOADING = 1,
        ZERO_SLIDE_STARTING,
        ZERO_SLIDE_STARTED,
        ZERO_SLIDE_STOPPING,
	ZERO_SLIDE_STOPPED,
	ZERO_SLIDE_UNLOADED,
};

static char redir_path[128];
static char useSlide[128];
static char slideContrast[128];
static char ledDisable[128];
static char psp1000SlidePlugin[16];
static char psp1000SlideTriggerMode[40];
static char psp1000Diagnostics[16];
static char psp1000SonyStartTrace[16];
static char psp1000BSManClosedShim[16];
static unsigned long slideStartBtn, slideStopBtn;
static long b_level;

#define VSH_CODE_CAPTURE_BEFORE 0x80
#define VSH_CODE_CAPTURE_AFTER  0x100
#define VSH_CODE_CAPTURE_BYTES  (VSH_CODE_CAPTURE_BEFORE + VSH_CODE_CAPTURE_AFTER)
#define VSH_CODE_CAPTURE_WORDS  (VSH_CODE_CAPTURE_BYTES / sizeof(unsigned int))
#define VSH_REFERENCE_LIMIT     32
#define VSH_REFERENCE_WINDOW_BEFORE 0x30
#define VSH_REFERENCE_WINDOW_AFTER  0x50
#define VSH_REFERENCE_WINDOW_WORDS  \
    ((VSH_REFERENCE_WINDOW_BEFORE + VSH_REFERENCE_WINDOW_AFTER) / 4)
#define VSH_PREDICATE_COUNT 8
#define VSH_STATE_INITIALIZER_CANDIDATE 0x66E0
#define VSH_STATE_IMPORT_OFFSET 0x3F970
#define VSH_STATE_TRACE_LIMIT 16
#define VSH_INITIALIZER_CAPTURE_START 0x6680
#define VSH_INITIALIZER_CAPTURE_SIZE 0xC0
#define VSH_TRIGGER_COUNT 3
#define SLIDE_OBSERVATION_WINDOW_US 12000000
#define SLIDE_OBSERVATION_POLL_US     200000

enum zeroCtrlTriggerMode {
    ZERO_TRIGGER_DISABLED = 0,
    ZERO_TRIGGER_58D4 = 1,
    ZERO_TRIGGER_13F6C = 2,
    ZERO_TRIGGER_14020 = 4
};

static const unsigned int vsh_trigger_offsets[VSH_TRIGGER_COUNT] = {
    0x58D4, 0x13F6C, 0x14020
};

typedef struct {
    unsigned int callsite;
    unsigned int original_word;
    unsigned int original_target;
    unsigned int replacement_word;
    unsigned int stub_addr;
    unsigned int counter_addr;
    unsigned int hit_count;
    int validation;
    int patch_applied;
    int cache_sync;
} ZeroCtrlVshTriggerEvidence;

typedef struct {
    unsigned int target_addr;
    unsigned int original_words[2];
    unsigned int replacement_words[2];
    unsigned int decoded_global_addr;
    unsigned int expected_global_addr;
    unsigned int stub_addr;
    unsigned int counter_addr;
    unsigned int hit_count;
    int validation;
    int structure_valid;
    int patch_applied;
    int cache_sync;
} ZeroCtrlGlobalPredicateEvidence;

enum zeroCtrlSonyStartRegisterReason {
    SONY_START_REGISTER_NONE = 0,
    SONY_START_REGISTER_TRACE_DISABLED = 1,
    SONY_START_REGISTER_ALREADY_REGISTERED = 2,
    SONY_START_REGISTER_HELPER_NOT_FOUND = 3,
    SONY_START_REGISTER_ENTRY_END_ORDER = 4,
    SONY_START_REGISTER_EXIT_END_ORDER = 5,
    SONY_START_REGISTER_ENTRY_STUB_TOO_LARGE = 6,
    SONY_START_REGISTER_EXIT_STUB_TOO_LARGE = 7,
    SONY_START_REGISTER_ENTRY_STUB_OUT_OF_RANGE = 8,
    SONY_START_REGISTER_EXIT_STUB_OUT_OF_RANGE = 9,
    SONY_START_REGISTER_RESUME_SLOT_OUT_OF_RANGE = 10,
    SONY_START_REGISTER_CALLER_RA_SLOT_OUT_OF_RANGE = 11,
    SONY_START_REGISTER_ENTRY_FLAG_OUT_OF_RANGE = 12,
    SONY_START_REGISTER_RETURN_FLAG_OUT_OF_RANGE = 13,
    SONY_START_REGISTER_RESULT_SLOT_OUT_OF_RANGE = 14,
    SONY_START_REGISTER_ENTRY_MISALIGNED = 15,
    SONY_START_REGISTER_EXIT_MISALIGNED = 16,
    SONY_START_REGISTER_DESCRIPTOR_NULL = 17,
    SONY_START_REGISTER_DESCRIPTOR_OUT_OF_RANGE = 18
};

enum zeroCtrlSonyStartGuardReason {
    SONY_START_GUARD_NONE = 0,
    SONY_START_GUARD_TRACE_DISABLED = 1,
    SONY_START_GUARD_TRACE_NOT_REGISTERED = 2,
    SONY_START_GUARD_MODEL_MISMATCH = 3,
    SONY_START_GUARD_NULL_MODULE = 4,
    SONY_START_GUARD_MODULE_NAME_MISMATCH = 5,
    SONY_START_GUARD_DEVKIT_MISMATCH = 6,
    SONY_START_GUARD_TEXT_TOO_SMALL = 7,
    SONY_START_GUARD_ADDRESS_OVERFLOW = 8
};

typedef struct {
    int enabled, registered, attempted, validation, install, cache_sync;
    volatile int registration_called, registration_success;
    volatile int initial_guard_checked;
    int registration_fail_reason, initial_guard_reason;
    unsigned int descriptor_addr, descriptor_size;
    int descriptor_validation;
    unsigned int supplied_addrs[9];
    unsigned int helper_text_addr, helper_text_size;
    unsigned int helper_data_size, helper_bss_size, helper_segment_count;
    unsigned int helper_segment_addr[4], helper_segment_size[4];
    unsigned int original_addr;
    unsigned int entry_stub_addr, entry_stub_size;
    unsigned int exit_stub_addr, exit_stub_size;
    unsigned int resume_slot_addr, caller_ra_slot_addr;
    unsigned int entry_seen_addr, return_seen_addr;
    unsigned int result_addr;
    unsigned int entry_original[3], entry_replacement[2];
    volatile int entry_seen, return_seen;
    int result;
    int return_snapshot_captured;
    ZeroCtrlPartitionSnapshot return_observed;
} ZeroCtrlSonyStartTrace;

typedef struct {
    int enabled, registration_called, registered;
    int attempted, import_found, unique_match, validation, install, cache_sync;
    unsigned int leaf_addr, leaf_size, hit_count_addr;
    unsigned int import_stub_addr, nidtable_addr, stubtable_addr;
    unsigned int original_words[2], replacement_words[2];
    unsigned int caller_addr, caller_words[4];
    unsigned int match_count;
    unsigned int stub_form, syscall_code;
    int closed_value;
} ZeroCtrlBSManEvidence;

enum zeroCtrlBSManStubForm {
    ZERO_BSMAN_STUB_UNKNOWN = 0,
    ZERO_BSMAN_STUB_JUMP_NOP,
    ZERO_BSMAN_STUB_JR_RA_SYSCALL,
    ZERO_BSMAN_STUB_SYSCALL_NOP
};

static const unsigned int vsh_predicate_offsets[VSH_PREDICATE_COUNT] = {
    0x6F04, 0x6F44, 0x6F84, 0x6FC4,
    0x7004, 0x701C, 0x7030, 0x7070
};

typedef struct {
    unsigned int source_addr;
    unsigned int source_offset;
    unsigned int instruction;
    unsigned int window_start_offset;
    unsigned int window_size;
    unsigned int window[VSH_REFERENCE_WINDOW_WORDS];
    unsigned char kind;
    unsigned char predicate_index;
} ZeroCtrlVshDirectReference;

typedef struct {
    unsigned int source_addr;
    unsigned int source_offset;
    unsigned int instruction;
    unsigned int lui_offset;
    unsigned int window_start_offset;
    unsigned int window_size;
    unsigned int window[VSH_REFERENCE_WINDOW_WORDS];
    unsigned char kind;
    unsigned char base_register;
    unsigned char value_register;
} ZeroCtrlVshGlobalReference;

typedef struct {
    unsigned int source_addr;
    unsigned int source_offset;
    unsigned int instruction;
    unsigned int window_start_offset;
    unsigned int window_size;
    unsigned int window[VSH_REFERENCE_WINDOW_WORDS];
    unsigned char kind;
} ZeroCtrlVshStateReference;

typedef struct {
    int armed;
    volatile int saw_request;
    volatile int saw_rco_request;
    volatile int saw_probe;
    volatile int saw_start;
    volatile int deferred_thread_started;
    volatile int writer_alive;
    volatile int probe_callback_entered;
    volatile int probe_callback_returning;
    volatile int start_callback_entered;
    volatile int previous_handler_returned;
    volatile int module_start_target_read;
    volatile int module_start_validation_complete;
    volatile int module_start_validated;
    volatile int module_start_original_saved;
    volatile int module_start_words_written;
    volatile int module_start_cache_sync_complete;
    volatile int start_callback_returning;
    int probe_result;
    int previous_handler_result;
    volatile int vsh_module_seen;
    unsigned int trigger_mode;
    ZeroCtrlVshTriggerEvidence triggers[VSH_TRIGGER_COUNT];
    int global_predicate_enabled;
    ZeroCtrlGlobalPredicateEvidence global_predicate;
    ZeroCtrlSonyStartTrace sony_start_trace;
    ZeroCtrlBSManEvidence bsman;
    int vsh_target_in_text;
    int vsh_modid;
    unsigned int vsh_text_addr;
    unsigned int vsh_text_size;
    unsigned int vsh_module_start_addr;
    unsigned int vsh_elf_entry_addr;
    unsigned int vsh_slide_target;
    int vsh_code_capture_result;
    unsigned int vsh_code_capture_start;
    unsigned int vsh_code_capture_end;
    unsigned int vsh_code_capture_size;
    unsigned int vsh_code_words[VSH_CODE_CAPTURE_WORDS];
    unsigned int vsh_direct_reference_count;
    unsigned int vsh_direct_reference_total;
    unsigned int vsh_direct_reference_overflow;
    unsigned int vsh_predicate_reference_count[VSH_PREDICATE_COUNT];
    ZeroCtrlVshDirectReference vsh_direct_references[VSH_REFERENCE_LIMIT];
    unsigned int vsh_global_reference_count;
    unsigned int vsh_global_reference_total;
    unsigned int vsh_global_reference_overflow;
    unsigned int vsh_shared_global_addr;
    unsigned int vsh_shared_global_offset;
    int vsh_shared_global_decode_valid;
    int vsh_shared_global_segment_valid;
    unsigned int vsh_shared_global_value;
    int vsh_shared_global_value_captured;
    ZeroCtrlVshGlobalReference vsh_global_references[VSH_REFERENCE_LIMIT];
    unsigned int vsh_initializer_capture_size;
    unsigned int vsh_initializer_code[VSH_INITIALIZER_CAPTURE_SIZE / 4];
    unsigned int vsh_initializer_reference_total;
    unsigned int vsh_initializer_reference_count;
    unsigned int vsh_initializer_reference_overflow;
    ZeroCtrlVshStateReference vsh_initializer_references[VSH_STATE_TRACE_LIMIT];
    int vsh_state_import_match;
    int vsh_state_import_library_valid;
    int vsh_state_import_get_model_match;
    unsigned int vsh_state_import_stub;
    unsigned int vsh_state_import_words[2];
    unsigned int vsh_state_import_nid;
    unsigned int vsh_state_import_index;
    unsigned int vsh_state_import_stubtable;
    unsigned int vsh_state_import_nidtable;
    char vsh_state_import_library[32];
    unsigned int module_start_addr;
    unsigned int elf_entry_addr;
    unsigned int module_start_original[2];
    int module_start_in_segment;
    int module_start_patch_result;
    ZeroCtrlPartitionSnapshot at_probe;
    ZeroCtrlPartitionSnapshot pre_start;
    ZeroCtrlPartitionSnapshot delayed_or_timeout;
    SceModule2 module;
} ZeroCtrlSlideDiagnosticState;

static ZeroCtrlSlideDiagnosticState slide_diag;
static int zeroCtrlCreateSlideDiagnosticsThread(void);

static unsigned int zeroCtrlParseTriggerMode(const char *mode) {
    if (strcmp(mode, "Caller13F6C") == 0) return ZERO_TRIGGER_13F6C;
    if (strcmp(mode, "Caller14020") == 0) return ZERO_TRIGGER_14020;
    if (strcmp(mode, "Caller13F6C_14020") == 0)
        return ZERO_TRIGGER_13F6C | ZERO_TRIGGER_14020;
    /* Names containing 58D4 are intentionally conspicuous and never default. */
    if (strcmp(mode, "DangerousCaller58D4") == 0) return ZERO_TRIGGER_58D4;
    if (strcmp(mode, "DangerousCaller58D4_13F6C") == 0)
        return ZERO_TRIGGER_58D4 | ZERO_TRIGGER_13F6C;
    if (strcmp(mode, "DangerousCaller58D4_14020") == 0)
        return ZERO_TRIGGER_58D4 | ZERO_TRIGGER_14020;
    if (strcmp(mode, "DangerousAllCallers") == 0)
        return ZERO_TRIGGER_58D4 | ZERO_TRIGGER_13F6C | ZERO_TRIGGER_14020;
    return ZERO_TRIGGER_DISABLED;
}

static void zeroCtrlCaptureVshReferenceWindow(unsigned int text_addr,
        unsigned int text_size, unsigned int source_offset,
        unsigned int *window_start_offset, unsigned int *window_size,
        unsigned int *window) {
    unsigned int start = source_offset > VSH_REFERENCE_WINDOW_BEFORE ?
            source_offset - VSH_REFERENCE_WINDOW_BEFORE : 0;
    unsigned int end = text_size - source_offset < VSH_REFERENCE_WINDOW_AFTER ?
            text_size : source_offset + VSH_REFERENCE_WINDOW_AFTER;
    unsigned int i;

    start &= ~3U;
    end &= ~3U;
    *window_start_offset = start;
    *window_size = end - start;
    for (i = 0; i < *window_size / 4; i++) {
        window[i] = _lw(text_addr + start + i * 4);
    }
}

static unsigned int zeroCtrlMipsJumpTarget(unsigned int pc,
        unsigned int instruction) {
    return ((pc + 4) & 0xF0000000) |
            ((instruction & 0x03FFFFFF) << 2);
}

static void zeroCtrlScanVshDirectReferences(unsigned int text_addr,
        unsigned int text_size) {
    unsigned int pass;
    unsigned int offset;
    unsigned int predicate;

    /* Two passes retain JAL references before less useful tail J references. */
    for (pass = 0; pass < 2; pass++) {
        unsigned int wanted_opcode = pass == 0 ? 3 : 2;
        for (offset = 0; offset + 4 <= text_size; offset += 4) {
            unsigned int pc = text_addr + offset;
            unsigned int instruction = _lw(pc);
            if (instruction >> 26 != wanted_opcode) continue;
            for (predicate = 0; predicate < VSH_PREDICATE_COUNT; predicate++) {
                if (zeroCtrlMipsJumpTarget(pc, instruction) !=
                        text_addr + vsh_predicate_offsets[predicate]) continue;
                slide_diag.vsh_direct_reference_total++;
                slide_diag.vsh_predicate_reference_count[predicate]++;
                if (slide_diag.vsh_direct_reference_count < VSH_REFERENCE_LIMIT) {
                    ZeroCtrlVshDirectReference *ref =
                            &slide_diag.vsh_direct_references[
                                slide_diag.vsh_direct_reference_count++];
                    ref->source_addr = pc;
                    ref->source_offset = offset;
                    ref->instruction = instruction;
                    ref->kind = wanted_opcode;
                    ref->predicate_index = predicate;
                    zeroCtrlCaptureVshReferenceWindow(text_addr, text_size,
                            offset, &ref->window_start_offset,
                            &ref->window_size, ref->window);
                } else {
                    slide_diag.vsh_direct_reference_overflow++;
                }
                break;
            }
        }
    }
}

static int zeroCtrlVshGlobalAccessKind(unsigned int instruction) {
    unsigned int opcode = instruction >> 26;
    if (opcode == 0x28 || opcode == 0x29 || opcode == 0x2B) return 2;
    if (opcode == 0x20 || opcode == 0x21 || opcode == 0x23 ||
            opcode == 0x24 || opcode == 0x25) return 1;
    return 0;
}

static void zeroCtrlCaptureVshFixedWindow(unsigned int text_addr,
        unsigned int text_size, unsigned int start, unsigned int requested_size,
        unsigned int *captured_size, unsigned int *code) {
    unsigned int size;
    unsigned int i;

    *captured_size = 0;
    if (start >= text_size) return;
    size = text_size - start < requested_size ? text_size - start : requested_size;
    size &= ~3U;
    for (i = 0; i < size / 4; i++) code[i] = _lw(text_addr + start + i * 4);
    *captured_size = size;
}

static void zeroCtrlScanVshStateTarget(unsigned int text_addr,
        unsigned int text_size, unsigned int target_offset,
        unsigned int *total, unsigned int *stored, unsigned int *overflow,
        ZeroCtrlVshStateReference *references) {
    unsigned int pass;
    unsigned int offset;

    for (pass = 0; pass < 2; pass++) {
        unsigned int wanted_opcode = pass == 0 ? 3 : 2;
        for (offset = 0; offset + 4 <= text_size; offset += 4) {
            unsigned int pc = text_addr + offset;
            unsigned int instruction = _lw(pc);
            ZeroCtrlVshStateReference *ref;
            if (instruction >> 26 != wanted_opcode ||
                    zeroCtrlMipsJumpTarget(pc, instruction) !=
                    text_addr + target_offset)
                continue;
            (*total)++;
            if (*stored >= VSH_STATE_TRACE_LIMIT) {
                (*overflow)++;
                continue;
            }
            ref = &references[(*stored)++];
            ref->source_addr = pc;
            ref->source_offset = offset;
            ref->instruction = instruction;
            ref->kind = wanted_opcode;
            zeroCtrlCaptureVshReferenceWindow(text_addr, text_size, offset,
                    &ref->window_start_offset, &ref->window_size, ref->window);
        }
    }
}

static int zeroCtrlInstructionWritesRegister(unsigned int instruction,
        unsigned int reg) {
    unsigned int opcode = instruction >> 26;
    unsigned int function = instruction & 0x3F;

    if (reg == 0) return 0;
    if ((opcode == 0x0F || opcode == 0x0D || opcode == 0x09 ||
            zeroCtrlVshGlobalAccessKind(instruction) == 1) &&
            ((instruction >> 16) & 0x1F) == reg)
        return 1;
    if (opcode == 0 && (function == 0x21 || function == 0x25) &&
            ((instruction >> 11) & 0x1F) == reg)
        return 1;
    return 0;
}

static void zeroCtrlDeriveVshSharedGlobal(unsigned int text_addr,
        unsigned int text_size, unsigned int target_offset) {
    unsigned int lui;
    unsigned int access;
    unsigned int base;
    int displacement;

    slide_diag.vsh_shared_global_decode_valid = 0;
    if (target_offset > text_size || text_size - target_offset < 8) return;
    lui = _lw(text_addr + target_offset);
    access = _lw(text_addr + target_offset + 4);
    base = (lui >> 16) & 0x1F;
    if ((lui >> 26) != 0x0F || zeroCtrlVshGlobalAccessKind(access) != 1 ||
            ((access >> 21) & 0x1F) != base)
        return;

    displacement = (short)(access & 0xFFFF);
    slide_diag.vsh_shared_global_addr =
            ((lui & 0xFFFF) << 16) + (unsigned int)displacement;
    slide_diag.vsh_shared_global_offset =
            slide_diag.vsh_shared_global_addr - text_addr;
    slide_diag.vsh_shared_global_decode_valid = 1;
}

static int zeroCtrlVshModuleRangeValid(SceModule2 *mod, unsigned int addr,
        unsigned int size) {
    unsigned int i;

    if (!mod || mod->nsegment > 4 || size == 0) return 0;
    for (i = 0; i < mod->nsegment; i++) {
        unsigned int start = mod->segmentaddr[i];
        unsigned int segment_size = mod->segmentsize[i];
        if (segment_size >= size && addr >= start &&
                addr - start <= segment_size - size)
            return 1;
    }
    return 0;
}

static int zeroCtrlCopyVshImportLibrary(SceModule2 *mod, const char *source,
        char *destination, unsigned int capacity) {
    unsigned int i;

    if (!source || capacity < 2) return 0;
    for (i = 0; i < capacity - 1; i++) {
        unsigned int addr = (unsigned int)source + i;
        if (addr < (unsigned int)source ||
                !zeroCtrlVshModuleRangeValid(mod, addr, 1))
            return 0;
        destination[i] = *(const volatile char *)addr;
        if (destination[i] == '\0') return 1;
    }
    destination[capacity - 1] = '\0';
    return 0;
}

static void zeroCtrlResolveVshStateImport(SceModule2 *mod) {
    unsigned int table_addr;
    unsigned int table_size;
    unsigned int offset = 0;
    unsigned int target_stub;

    slide_diag.vsh_state_import_match = 0;
    if (!mod || mod->modid != slide_diag.vsh_modid ||
            mod->text_addr != slide_diag.vsh_text_addr ||
            VSH_STATE_IMPORT_OFFSET > mod->text_size ||
            mod->text_size - VSH_STATE_IMPORT_OFFSET < 8)
        return;
    target_stub = mod->text_addr + VSH_STATE_IMPORT_OFFSET;
    slide_diag.vsh_state_import_stub = target_stub;
    slide_diag.vsh_state_import_words[0] = _lw(target_stub);
    slide_diag.vsh_state_import_words[1] = _lw(target_stub + 4);
    table_addr = (unsigned int)mod->stub_top;
    table_size = mod->stub_size;
    if ((table_addr & 3) != 0 ||
            !zeroCtrlVshModuleRangeValid(mod, table_addr, table_size)) return;

    while (offset < table_size) {
        SceLibraryStubTable *entry;
        unsigned int entry_addr;
        unsigned int entry_size;
        unsigned int functions_size;
        unsigned int nids_size;
        unsigned int stubtable;
        unsigned int nidtable;
        unsigned int i;

        if (table_size - offset < 12 || table_addr + offset < table_addr) return;
        entry_addr = table_addr + offset;
        if (!zeroCtrlVshModuleRangeValid(mod, entry_addr, 12)) return;
        entry = (SceLibraryStubTable *)entry_addr;
        if (entry->len == 0) return;
        entry_size = (unsigned int)entry->len * 4;
        if (entry_size < __builtin_offsetof(SceLibraryStubTable, stubtable) + 4 ||
                entry_size > table_size - offset ||
                !zeroCtrlVshModuleRangeValid(mod, entry_addr, entry_size))
            return;
        functions_size = (unsigned int)entry->stubcount * 8;
        nids_size = (unsigned int)entry->stubcount * 4;
        stubtable = (unsigned int)entry->stubtable;
        nidtable = (unsigned int)entry->nidtable;
        if ((stubtable & 3) != 0 || (nidtable & 3) != 0 ||
                !zeroCtrlVshModuleRangeValid(mod, nidtable, nids_size) ||
                !zeroCtrlVshModuleRangeValid(mod, stubtable, functions_size)) {
            offset += entry_size;
            continue;
        }
        for (i = 0; i < entry->stubcount; i++) {
            unsigned int function_stub;
            if (i > (0xFFFFFFFFU - stubtable) / 8) return;
            function_stub = stubtable + i * 8;
            if (function_stub != target_stub) continue;
            slide_diag.vsh_state_import_nid = entry->nidtable[i];
            slide_diag.vsh_state_import_index = i;
            slide_diag.vsh_state_import_stubtable =
                    (unsigned int)entry->stubtable;
            slide_diag.vsh_state_import_nidtable =
                    (unsigned int)entry->nidtable;
            slide_diag.vsh_state_import_library_valid =
                    zeroCtrlCopyVshImportLibrary(mod, entry->libname,
                            slide_diag.vsh_state_import_library,
                            sizeof(slide_diag.vsh_state_import_library));
            if (slide_diag.vsh_state_import_library_valid &&
                    strcmp(slide_diag.vsh_state_import_library,
                        "sceVshBridge") == 0 &&
                    slide_diag.vsh_state_import_nid == 0x21C243FE)
                slide_diag.vsh_state_import_get_model_match = 1;
            slide_diag.vsh_state_import_match = 1;
            return;
        }
        offset += entry_size;
    }
}

static void zeroCtrlValidateVshSharedGlobalSegment(int modid,
        unsigned int text_addr) {
    SceModule2 *mod = sceKernelFindModuleByName("vsh_module");
    unsigned int i;

    slide_diag.vsh_shared_global_segment_valid = 0;
    if (!slide_diag.vsh_shared_global_decode_valid || !mod ||
            mod->modid != modid || mod->text_addr != text_addr ||
            mod->nsegment > 4)
        return;
    for (i = 0; i < mod->nsegment; i++) {
        unsigned int start = mod->segmentaddr[i];
        unsigned int size = mod->segmentsize[i];
        unsigned int addr = slide_diag.vsh_shared_global_addr;
        if (size >= 4 && addr >= start && addr - start <= size - 4) {
            slide_diag.vsh_shared_global_segment_valid = 1;
            return;
        }
    }
}

static int zeroCtrlVshGlobalReferenceStored(unsigned int source_offset) {
    unsigned int i;
    for (i = 0; i < slide_diag.vsh_global_reference_count; i++) {
        if (slide_diag.vsh_global_references[i].source_offset == source_offset)
            return 1;
    }
    return 0;
}

static void zeroCtrlScanVshGlobalReferences(unsigned int text_addr,
        unsigned int text_size) {
    int pass;
    unsigned int offset;

    if (!slide_diag.vsh_shared_global_decode_valid) return;

    /* Store candidates are retained before reads if the fixed array fills. */
    for (pass = 2; pass >= 1; pass--) {
        for (offset = 4; offset + 4 <= text_size; offset += 4) {
            unsigned int instruction = _lw(text_addr + offset);
            unsigned int base = (instruction >> 21) & 0x1F;
            unsigned int distance;
            unsigned int lui_offset = 0;
            int found = 0;
            if (zeroCtrlVshGlobalAccessKind(instruction) != pass)
                continue;
            for (distance = 1; distance <= 4 && distance * 4 <= offset;
                    distance++) {
                unsigned int candidate_offset = offset - distance * 4;
                unsigned int candidate = _lw(text_addr + candidate_offset);
                if ((candidate >> 26) == 0x0F &&
                        ((candidate >> 16) & 0x1F) == base) {
                    int displacement = (short)(instruction & 0xFFFF);
                    unsigned int candidate_addr =
                            ((candidate & 0xFFFF) << 16) +
                            (unsigned int)displacement;
                    if (candidate_addr == slide_diag.vsh_shared_global_addr) {
                        lui_offset = candidate_offset;
                        found = 1;
                    }
                    break;
                }
                if (zeroCtrlInstructionWritesRegister(candidate, base)) break;
            }
            if (!found) continue;
            slide_diag.vsh_global_reference_total++;
            if (slide_diag.vsh_global_reference_count < VSH_REFERENCE_LIMIT &&
                    !zeroCtrlVshGlobalReferenceStored(offset)) {
                ZeroCtrlVshGlobalReference *ref =
                        &slide_diag.vsh_global_references[
                            slide_diag.vsh_global_reference_count++];
                ref->source_addr = text_addr + offset;
                ref->source_offset = offset;
                ref->instruction = instruction;
                ref->lui_offset = lui_offset;
                ref->kind = (unsigned char)pass;
                ref->base_register = base;
                ref->value_register = (instruction >> 16) & 0x1F;
                zeroCtrlCaptureVshReferenceWindow(text_addr, text_size,
                        offset, &ref->window_start_offset,
                        &ref->window_size, ref->window);
            } else {
                slide_diag.vsh_global_reference_overflow++;
            }
        }
    }
}

int zeroCtrlIsPsp1000SlideExperimentEnabled(void) {
    return slide_diag.armed;
}

void zeroCtrlRegisterSonyStartTrace(
        const ZeroCtrlSonyStartTraceRegistration *registration) {
    SceModule2 *helper;
    ZeroCtrlSonyStartTrace *trace = &slide_diag.sony_start_trace;
    ZeroCtrlSonyStartTraceRegistration copied;
    unsigned int descriptor_addr = (unsigned int)registration;
    unsigned int i;
    int k1;

    trace->registration_called = 1;
    trace->registration_success = 0;
    trace->descriptor_addr = descriptor_addr;
    trace->descriptor_size = sizeof(copied);
    trace->descriptor_validation = 0;
    if (!trace->enabled) {
        trace->registration_fail_reason = SONY_START_REGISTER_TRACE_DISABLED;
        return;
    }
    if (trace->registered) {
        trace->registration_fail_reason = SONY_START_REGISTER_ALREADY_REGISTERED;
        return;
    }
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!helper) {
        trace->registration_fail_reason = SONY_START_REGISTER_HELPER_NOT_FOUND;
        return;
    }
    trace->helper_text_addr = helper->text_addr;
    trace->helper_text_size = helper->text_size;
    trace->helper_data_size = helper->data_size;
    trace->helper_bss_size = helper->bss_size;
    trace->helper_segment_count = helper->nsegment;
    for (i = 0; i < helper->nsegment && i < 4; i++) {
        trace->helper_segment_addr[i] = helper->segmentaddr[i];
        trace->helper_segment_size[i] = helper->segmentsize[i];
    }
    if (!registration) {
        trace->registration_fail_reason = SONY_START_REGISTER_DESCRIPTOR_NULL;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, descriptor_addr,
            sizeof(copied))) {
        trace->registration_fail_reason =
                SONY_START_REGISTER_DESCRIPTOR_OUT_OF_RANGE;
        return;
    }
    trace->descriptor_validation = 1;
    k1 = pspSdkSetK1(0);
    memcpy(&copied, registration, sizeof(copied));
    pspSdkSetK1(k1);
    trace->supplied_addrs[0] = copied.entry_addr;
    trace->supplied_addrs[1] = copied.entry_end_addr;
    trace->supplied_addrs[2] = copied.exit_addr;
    trace->supplied_addrs[3] = copied.exit_end_addr;
    trace->supplied_addrs[4] = copied.resume_slot_addr;
    trace->supplied_addrs[5] = copied.caller_ra_slot_addr;
    trace->supplied_addrs[6] = copied.entry_seen_addr;
    trace->supplied_addrs[7] = copied.return_seen_addr;
    trace->supplied_addrs[8] = copied.result_addr;
    if (copied.entry_end_addr <= copied.entry_addr) {
        trace->registration_fail_reason = SONY_START_REGISTER_ENTRY_END_ORDER;
        return;
    }
    if (copied.exit_end_addr <= copied.exit_addr) {
        trace->registration_fail_reason = SONY_START_REGISTER_EXIT_END_ORDER;
        return;
    }
    if (copied.entry_end_addr - copied.entry_addr > 256) {
        trace->registration_fail_reason = SONY_START_REGISTER_ENTRY_STUB_TOO_LARGE;
        return;
    }
    if (copied.exit_end_addr - copied.exit_addr > 256) {
        trace->registration_fail_reason = SONY_START_REGISTER_EXIT_STUB_TOO_LARGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.entry_addr,
            copied.entry_end_addr - copied.entry_addr)) {
        trace->registration_fail_reason = SONY_START_REGISTER_ENTRY_STUB_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.exit_addr,
            copied.exit_end_addr - copied.exit_addr)) {
        trace->registration_fail_reason = SONY_START_REGISTER_EXIT_STUB_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.resume_slot_addr, 4)) {
        trace->registration_fail_reason = SONY_START_REGISTER_RESUME_SLOT_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.caller_ra_slot_addr, 4)) {
        trace->registration_fail_reason = SONY_START_REGISTER_CALLER_RA_SLOT_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.entry_seen_addr, 4)) {
        trace->registration_fail_reason = SONY_START_REGISTER_ENTRY_FLAG_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.return_seen_addr, 4)) {
        trace->registration_fail_reason = SONY_START_REGISTER_RETURN_FLAG_OUT_OF_RANGE;
        return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, copied.result_addr, 4)) {
        trace->registration_fail_reason = SONY_START_REGISTER_RESULT_SLOT_OUT_OF_RANGE;
        return;
    }
    if ((copied.entry_addr & 3) != 0) {
        trace->registration_fail_reason = SONY_START_REGISTER_ENTRY_MISALIGNED;
        return;
    }
    if ((copied.exit_addr & 3) != 0) {
        trace->registration_fail_reason = SONY_START_REGISTER_EXIT_MISALIGNED;
        return;
    }
    trace->entry_stub_addr = copied.entry_addr;
    trace->entry_stub_size = copied.entry_end_addr - copied.entry_addr;
    trace->exit_stub_addr = copied.exit_addr;
    trace->exit_stub_size = copied.exit_end_addr - copied.exit_addr;
    trace->resume_slot_addr = copied.resume_slot_addr;
    trace->caller_ra_slot_addr = copied.caller_ra_slot_addr;
    trace->entry_seen_addr = copied.entry_seen_addr;
    trace->return_seen_addr = copied.return_seen_addr;
    trace->result_addr = copied.result_addr;
    trace->registration_fail_reason = SONY_START_REGISTER_NONE;
    trace->registration_success = 1;
    trace->registered = 1;
}

void zeroCtrlRegisterBSManClosedShim(
        const ZeroCtrlBSManClosedRegistration *registration) {
    SceModule2 *helper;
    ZeroCtrlBSManClosedRegistration copied;
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    int k1;

    bsman->registration_called = 1;
    if (!bsman->enabled || bsman->registered || !registration) return;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!helper || !zeroCtrlVshModuleRangeValid(helper,
                (unsigned int)registration, sizeof(copied))) return;
    k1 = pspSdkSetK1(0);
    memcpy(&copied, registration, sizeof(copied));
    pspSdkSetK1(k1);
    if (copied.leaf_end_addr <= copied.leaf_addr ||
            copied.leaf_end_addr - copied.leaf_addr > 64 ||
            (copied.leaf_addr & 3) != 0 ||
            !zeroCtrlVshModuleRangeValid(helper, copied.leaf_addr,
                copied.leaf_end_addr - copied.leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.hit_count_addr, 4))
        return;
    bsman->leaf_addr = copied.leaf_addr;
    bsman->leaf_size = copied.leaf_end_addr - copied.leaf_addr;
    bsman->hit_count_addr = copied.hit_count_addr;
    bsman->registered = 1;
}

void zeroCtrlRecordVshSlideTarget(int modid, unsigned int text_addr,
        unsigned int text_size, unsigned int module_start_addr,
        unsigned int elf_entry_addr, unsigned int target,
        unsigned int stub_58d4, unsigned int stub_13f6c,
        unsigned int stub_14020, unsigned int counter_58d4,
        unsigned int counter_13f6c, unsigned int counter_14020,
        unsigned int global_stub, unsigned int global_counter) {
    const unsigned int stubs[VSH_TRIGGER_COUNT] = {
        stub_58d4, stub_13f6c, stub_14020
    };
    const unsigned int counters[VSH_TRIGGER_COUNT] = {
        counter_58d4, counter_13f6c, counter_14020
    };
    SceModule2 *helper;
    int all_selected_valid;
    unsigned int target_offset;
    unsigned int start_offset;
    unsigned int end_offset;
    unsigned int i;

    if (!slide_diag.armed || slide_diag.vsh_module_seen) return;
    slide_diag.vsh_modid = modid;
    slide_diag.vsh_text_addr = text_addr;
    slide_diag.vsh_text_size = text_size;
    slide_diag.vsh_module_start_addr = module_start_addr;
    slide_diag.vsh_elf_entry_addr = elf_entry_addr;
    slide_diag.vsh_slide_target = target;
    slide_diag.vsh_code_capture_result = -1;

    if (target >= text_addr) {
        target_offset = target - text_addr;
        if (target_offset < text_size) {
            slide_diag.vsh_target_in_text = 1;
            start_offset = target_offset > VSH_CODE_CAPTURE_BEFORE ?
                    target_offset - VSH_CODE_CAPTURE_BEFORE : 0;
            end_offset = text_size - target_offset < VSH_CODE_CAPTURE_AFTER ?
                    text_size : target_offset + VSH_CODE_CAPTURE_AFTER;
            start_offset &= ~3U;
            end_offset &= ~3U;
            slide_diag.vsh_code_capture_start = start_offset;
            slide_diag.vsh_code_capture_end = end_offset;
            slide_diag.vsh_code_capture_size = end_offset - start_offset;
            for (i = 0; i < slide_diag.vsh_code_capture_size / 4; i++) {
                slide_diag.vsh_code_words[i] =
                        _lw(text_addr + start_offset + i * 4);
            }
            zeroCtrlDeriveVshSharedGlobal(text_addr, text_size, target_offset);
            zeroCtrlValidateVshSharedGlobalSegment(modid, text_addr);
            zeroCtrlResolveVshStateImport(
                    sceKernelFindModuleByName("vsh_module"));
            zeroCtrlScanVshDirectReferences(text_addr, text_size);
            zeroCtrlScanVshGlobalReferences(text_addr, text_size);
            zeroCtrlCaptureVshFixedWindow(text_addr, text_size,
                    VSH_INITIALIZER_CAPTURE_START,
                    VSH_INITIALIZER_CAPTURE_SIZE,
                    &slide_diag.vsh_initializer_capture_size,
                    slide_diag.vsh_initializer_code);
            zeroCtrlScanVshStateTarget(text_addr, text_size,
                    VSH_STATE_INITIALIZER_CANDIDATE,
                    &slide_diag.vsh_initializer_reference_total,
                    &slide_diag.vsh_initializer_reference_count,
                    &slide_diag.vsh_initializer_reference_overflow,
                    slide_diag.vsh_initializer_references);
            slide_diag.vsh_code_capture_result = 0;

            helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
            all_selected_valid =
                    slide_diag.trigger_mode != ZERO_TRIGGER_DISABLED &&
                    target_offset == 0x6F84;
            /* Validation pass: no VSH write may occur in this loop. */
            for (i = 0; i < VSH_TRIGGER_COUNT; i++) {
                ZeroCtrlVshTriggerEvidence *evidence = &slide_diag.triggers[i];
                unsigned int callsite;
                unsigned int word;
                unsigned int original_target;

                evidence->stub_addr = stubs[i];
                evidence->counter_addr = counters[i];
                if (!(slide_diag.trigger_mode & (1U << i))) continue;
                if (text_size < 4 ||
                        vsh_trigger_offsets[i] > text_size - 4 ||
                        text_addr > 0xFFFFFFFFU - vsh_trigger_offsets[i]) {
                    all_selected_valid = 0;
                    continue;
                }
                callsite = text_addr + vsh_trigger_offsets[i];
                evidence->callsite = callsite;
                word = _lw(callsite);
                original_target = ((callsite + 4) & 0xF0000000) |
                        ((word & 0x03FFFFFF) << 2);
                evidence->original_word = word;
                evidence->original_target = original_target;
                if ((word >> 26) == 3 && original_target == target &&
                        zeroCtrlVshModuleRangeValid(helper, stubs[i], 24) &&
                        zeroCtrlVshModuleRangeValid(helper, counters[i], 4) &&
                        (stubs[i] & 3) == 0 &&
                        ((callsite + 4) & 0xF0000000) ==
                                (stubs[i] & 0xF0000000)) {
                    unsigned int patched = 0x0C000000 |
                            ((stubs[i] >> 2) & 0x03FFFFFF);
                    evidence->validation = 1;
                    evidence->replacement_word = patched;
                } else {
                    all_selected_valid = 0;
                }
            }

            /* Commit pass: selected callsites are all valid or none are written. */
            if (all_selected_valid) {
                for (i = 0; i < VSH_TRIGGER_COUNT; i++) {
                    ZeroCtrlVshTriggerEvidence *evidence =
                            &slide_diag.triggers[i];
                    if (!(slide_diag.trigger_mode & (1U << i))) continue;
                    _sw(evidence->replacement_word, evidence->callsite);
                    evidence->patch_applied = 1;
                    sceKernelDcacheWritebackInvalidateRange(
                            (const void *)evidence->callsite,
                            sizeof(unsigned int));
                    sceKernelIcacheInvalidateRange(
                            (const void *)evidence->callsite,
                            sizeof(unsigned int));
                    evidence->cache_sync = 1;
                }
            }

            /* Dangerous global predicate block: never edits direct callers. */
            if (slide_diag.global_predicate_enabled) {
                SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
                ZeroCtrlGlobalPredicateEvidence *global =
                        &slide_diag.global_predicate;
                unsigned int predicate = target;
                unsigned int lui;
                unsigned int load;
                unsigned int upper;
                int displacement;

                global->stub_addr = global_stub;
                global->counter_addr = global_counter;
                if (model == 0 && sceKernelDevkitVersion() == 0x06060110 &&
                        vsh && vsh->modid == modid &&
                        vsh->text_addr == text_addr &&
                        vsh->text_size == text_size &&
                        target_offset == 0x6F84 && text_size >= 0x6F8C &&
                        text_addr <= 0xFFFFFFFFU - 0x6F8B &&
                        zeroCtrlVshModuleRangeValid(vsh, predicate, 8)) {
                    global->target_addr = predicate;
                    global->original_words[0] = _lw(predicate);
                    global->original_words[1] = _lw(predicate + 4);
                    lui = global->original_words[0];
                    load = global->original_words[1];
                    upper = (lui & 0xFFFF) << 16;
                    displacement = (short)(load & 0xFFFF);
                    global->decoded_global_addr =
                            upper + (unsigned int)displacement;
                    global->expected_global_addr =
                            slide_diag.vsh_shared_global_addr;
                    if ((lui >> 26) == 0x0F && ((lui >> 16) & 0x1F) == 2 &&
                            (load >> 26) == 0x23 &&
                            ((load >> 21) & 0x1F) == 2 &&
                            ((load >> 16) & 0x1F) == 4)
                        global->structure_valid = 1;
                }
                if (global->structure_valid &&
                        slide_diag.vsh_shared_global_decode_valid &&
                        slide_diag.vsh_shared_global_segment_valid &&
                        slide_diag.vsh_shared_global_addr >= text_addr &&
                        slide_diag.vsh_shared_global_addr - text_addr == 0x56CE0 &&
                        global->decoded_global_addr ==
                                slide_diag.vsh_shared_global_addr &&
                        zeroCtrlVshModuleRangeValid(helper, global_stub, 24) &&
                        zeroCtrlVshModuleRangeValid(helper, global_counter, 4) &&
                        (global_stub & 3) == 0 &&
                        ((predicate + 4) & 0xF0000000) ==
                                (global_stub & 0xF0000000)) {
                    global->replacement_words[0] = 0x08000000 |
                            ((global_stub >> 2) & 0x03FFFFFF);
                    global->replacement_words[1] = 0;
                    if ((((predicate + 4) & 0xF0000000) |
                            ((global->replacement_words[0] & 0x03FFFFFF)
                            << 2)) == global_stub)
                        global->validation = 1;
                }
                if (global->validation) {
                    _sw(global->replacement_words[0], predicate);
                    _sw(global->replacement_words[1], predicate + 4);
                    global->patch_applied = 1;
                    sceKernelDcacheWritebackInvalidateRange(
                            (const void *)predicate, 8);
                    sceKernelIcacheInvalidateRange((const void *)predicate, 8);
                    global->cache_sync = 1;
                }
            }
        }
    }
    slide_diag.vsh_module_seen = 1;
}

int (*msIoOpen)(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode);
int (*msIoGetstat)(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat);

int (*IoOpen)(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode);
int (*IoGetstat)(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat);

int (* scePowerGetBusClockFrequency)(void) = NULL;
int (* scePowerGetCpuClockFrequency)(void) = NULL;

int vshImposeGetParam(u32 value);
int sctrlHENSetSpeed(int cpufreq, int busfreq);
int sceSysconCtrlLED(int SceLED, int state);
int sceKernelPowerTick (int type);

int slideState;
int cpuOld = -1, busOld = -1;

//OK
void *zeroCtrlAllocUserBuffer(SceUID *uid, int size) {
    void *addr;
    int k1 = pspSdkSetK1(0);

    *uid = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_USER, "zeroCtrlUserBuffer",
            PSP_SMEM_High, size, NULL);
    addr = (*uid >= 0) ? sceKernelGetBlockHeadAddr(*uid) : NULL;
    if (!addr && *uid >= 0) {
        sceKernelFreePartitionMemory(*uid);
        *uid = -1;
    }
    pspSdkSetK1(k1);
    return addr;
}
//OK
void zeroCtrlFreeUserBuffer(SceUID uid) {
    if (uid >= 0) {
        int k1 = pspSdkSetK1(0);
        sceKernelFreePartitionMemory(uid);
        pspSdkSetK1(k1);
    }
}
//OK
inline void zeroCtrlIcacheClearAll(void) {
    __asm__ volatile("\
	.word 0x40088000; .word 0x24091000; .word 0x7D081240;\
	.word 0x01094804; .word 0x4080E000; .word 0x4080E800;\
	.word 0x00004021; .word 0xBD010000; .word 0xBD030000;\
	.word 0x25080040; .word 0x1509FFFC; .word 0x00000000;\
	"::);
}
//OK
inline void zeroCtrlDcacheWritebackAll(void) {
    __asm__ volatile("\
	.word 0x40088000; .word 0x24090800; .word 0x7D081180;\
	.word 0x01094804; .word 0x00004021; .word 0xBD140000;\
	.word 0xBD140000; .word 0x25080040; .word 0x1509FFFC;\
	.word 0x00000000; .word 0x0000000F; .word 0x00000000;\
	"::);
}
//OK
void ClearCaches(void) {
    zeroCtrlIcacheClearAll();
    zeroCtrlDcacheWritebackAll();
}
//OK
int zeroCtrlIsValidFileType(const char *file) {
    int ret = 0;
    const char *ext;
    if (!file) {
        //zeroCtrlWriteDebug("--> Is NULL\n");
        return 0;
    }

    //zeroCtrlWriteDebug("file: %s\n", file);
    int k1 = pspSdkSetK1(0);
    ext = strrchr(file, '.');
    if (!ext) {
        //zeroCtrlWriteDebug("--> No Extension\n");
    } else {
        for (int i = 0; i < ITEMSOF(exts); i++) {
            if (strcmp(ext, exts[i]) == 0) {
                //zeroCtrlWriteDebug("Success\n");
                ret = 1;
                break;
            }
        }
    }
    pspSdkSetK1(k1);
    return ret;
}
//OK
const char *zeroCtrlGetFileName(const char *file) {
    char *ret = NULL;

    if (!file) {
        //zeroCtrlWriteDebug("--> Is NULL\n");
        return ret;
    }

    //zeroCtrlWriteDebug("file: %s\n", file);
    int k1 = pspSdkSetK1(0);
    ret = strrchr(file, '/');
    pspSdkSetK1(k1);

    // blacklist this one
    if (strcmp(file, "/codepage/cptbl.dat") == 0) {
        ret = NULL;
    }

    if (!ret) {
        //zeroCtrlWriteDebug("--> No path\n");
    } else {
        //zeroCtrlWriteDebug("Success\n");
    }
    return ret;
}
//OK
char *zeroCtrlSwapFile(const char *file, SceUID *block_id) {
    const char *oldfile;
    char *newfile = zeroCtrlAllocUserBuffer(block_id, 256);

    if (!newfile) {
        //zeroCtrlWriteDebug("Cannot allocate 256 bytes of memory, abort\n");
        return NULL;
    }

    int k1 = pspSdkSetK1(0);

    *newfile = '\0';
    oldfile = zeroCtrlGetFileName(file);
    if (!oldfile) {
        //zeroCtrlWriteDebug("-> File not found, abort\n\n");
        pspSdkSetK1(k1);
        zeroCtrlFreeUserBuffer(*block_id);
        *block_id = -1;
        return NULL;
    }

    if (zeroCtrlIsBlacklistedFound()) {
        if (strcmp(oldfile, "/ltn0.pgf") == 0) {
            //zeroCtrlWriteDebug("-> File is blacklisted, abort\n\n");
            pspSdkSetK1(k1);
            zeroCtrlFreeUserBuffer(*block_id);
            *block_id = -1;
            return NULL;
        }
    }

    sprintf(newfile, "%s%s", redir_path, oldfile);
    pspSdkSetK1(k1);

    //zeroCtrlWriteDebug("-> Redirected file: %s\n", newfile);
    return newfile;
}
//OK
int zeroCtrlIoGetstatEX(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat) {
    int ret;
    char *new_path;
    PspIoDrvArg *drv;
    SceUID path_id = -1;

    new_path = zeroCtrlSwapFile(file, &path_id);
    if (!new_path) {
        return IoGetstat(arg, file, stat);
    }

    drv = arg->drv;
    arg->drv = ms_drv;
    ret = msIoGetstat(arg, new_path, stat);

    if (ret >= 0) {
        //zeroCtrlWriteDebug("--> %s found, using custom file\n\n", new_path);
    } else {
        //zeroCtrlWriteDebug("--> %s not found, using default file\n\n", file);
        arg->drv = drv;
        ret = IoGetstat(arg, file, stat);
    }

    zeroCtrlFreeUserBuffer(path_id);
    return ret;
}
//OK
int zeroCtrlIoOpenEX(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode) {
    int ret;
    char *new_path;
    PspIoDrvArg *drv;
    SceUID path_id = -1;

    if ((new_path = zeroCtrlSwapFile(file, &path_id)) == NULL) {
        return IoOpen(arg, file, flags, mode);
    }

    drv = arg->drv;
    arg->drv = ms_drv;
    ret = msIoOpen(arg, new_path, flags, mode);

    if (ret >= 0) {
        //zeroCtrlWriteDebug("--> %s found, using custom file\n\n", new_path);
    } else {
        //zeroCtrlWriteDebug("--> %s not found, using default file\n\n", file);
        arg->drv = drv;
        ret = IoOpen(arg, file, flags, mode);
    }

    zeroCtrlFreeUserBuffer(path_id);
    return ret;
}

int zeroCtrlMsIoOpen(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode) {
    // do not add logging in this function to avoid infinite recursion
    ms_drv = arg->drv;
    return msIoOpen(arg, file, flags, mode);
}

int zeroCtrlMsIoGetstat(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat) {
    // do not use sceIoGetstat in this function to avoid infinite recursion
    return msIoGetstat(arg, file, stat);
}
//OK
int zeroCtrlIoOpen(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode) {          
    if (slide_diag.armed && file) {
        const char *name;
        int k1 = pspSdkSetK1(0);
        name = strrchr(file, '/');
        name = name ? name + 1 : file;
        if (strcmp(name, "slide_plugin.prx") == 0) {
            slide_diag.saw_request = 1;
        } else if (strcmp(name, "slide_plugin.rco") == 0) {
            slide_diag.saw_rco_request = 1;
        }
        pspSdkSetK1(k1);
    }
    if (ms_drv && zeroCtrlIsValidFileType(file)) {
        return zeroCtrlIoOpenEX(arg, file, flags, mode);
    } else {
        //zeroCtrlWriteDebug("cannot redirect file: %s\n\n", file);
    }
    return IoOpen(arg, file, flags, mode);
}
//OK
int zeroCtrlIoGetstat(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat) {	   
    if (ms_drv && zeroCtrlIsValidFileType(file)) {
        return zeroCtrlIoGetstatEX(arg, file, stat);
    } else {
        //zeroCtrlWriteDebug("cannot redirect file: %s\n\n", file);
    }
    return IoGetstat(arg, file, stat);
}
//OK
int zeroCtrlHookDriver(void) {
    int intr;
    SceUID fd;

    fatms = sctrlHENFindDriver(model == 4 ? "fatef" : "fatms");
    lflash = sctrlHENFindDriver("flashfat");

    if (!lflash || !fatms) {
        //zeroCtrlWriteDebug("failed to hook drivers: lflash: %08X, fatms: %08X\n", (u32)lflash, (u32)fatms);
        return 0;
    }  

    msIoOpen = fatms->funcs->IoOpen;
    msIoGetstat = fatms->funcs->IoGetstat;

    IoOpen = lflash->funcs->IoOpen;
    IoGetstat = lflash->funcs->IoGetstat;

    //zeroCtrlWriteDebug("suspending interrupts\n");
    intr = sceKernelCpuSuspendIntr();

    fatms->funcs->IoOpen = zeroCtrlMsIoOpen;
    fatms->funcs->IoGetstat = zeroCtrlMsIoGetstat;

    lflash->funcs->IoOpen = zeroCtrlIoOpen;
    lflash->funcs->IoGetstat = zeroCtrlIoGetstat;

    sceKernelCpuResumeIntr(intr);
    ClearCaches();
    //zeroCtrlWriteDebug("interrupts restored\n");

    fd = sceIoOpen(model == 4 ? "ef0:/_dummy.prx" : "ms0:/_dummy.prx", PSP_O_RDONLY, 0644);

    // just in case that someone has a file like this
    if (fd >= 0) {
        sceIoClose(fd);
    }

    //zeroCtrlWriteDebug("ms_drv addr: %08X\n", (u32)ms_drv);

    return 1;
}
//The 2nd arg is a SceLoadCoreExecFileInfo *, but we don't need it for now
int zeroCtrlModuleProbe(void *data, void *exec_info) {
    char filename[256];
    SceSize size;
    SceUID fd;
    int result;
    int is_slide;

    char *modname = (char *) data + (((u32 *) data)[0x10] & 0x7FFFFFFF) + 4;

    is_slide = slide_diag.armed &&
            strcmp(modname, "slide_plugin_module") == 0;
    if (is_slide && !slide_diag.saw_probe) {
        slide_diag.probe_callback_entered = 1;
        zeroCtrlDiagnosticsCapturePartitions(&slide_diag.at_probe);
        slide_diag.saw_probe = 1;
    }

    zeroCtrlSetBlackListItems(modname);

    for (int i = 0; i < ITEMSOF(g_modules_mod); i++) {
        if (strcmp(modname, g_modules_mod[i].modname) == 0) {
            //zeroCtrlWriteDebug("probing: %s\n", g_modules_mod[i].modfile);
            sprintf(filename, "%s%s/%s", model == 4 ? "ef0:" : "ms0:", redir_path, g_modules_mod[i].modfile);
            fd = sceIoOpen(filename, PSP_O_RDONLY, 0644);
            if (fd >= 0) {
                //zeroCtrlWriteDebug("writting %s into buffer\n", filename);
                size = sceIoLseek(fd, 0, PSP_SEEK_END);
                sceIoLseek(fd, 0, PSP_SEEK_SET);
                sceIoRead(fd, data, size);
                sceIoClose(fd);
                ClearCaches();
            } else {
                //zeroCtrlWriteDebug("%s not found, leaving buffer untouched\n", filename);
            }
            break;
        }
    }
    result = sceKernelProbeExecutableObject(data, exec_info);
    if (is_slide) {
        slide_diag.probe_result = result;
        slide_diag.probe_callback_returning = 1;
    }
    return result;
}
//OK
int zeroCtrlHookModule(void) {
    SceModule2 *module = (SceModule2 *) sceKernelFindModuleByName("sceModuleManager");

    if (!module || hook_import_bynid(module, "LoadCoreForKernel", moduleprobe_nid, zeroCtrlModuleProbe, 0) < 0) {
        //zeroCtrlWriteDebug("failed to hook ProbeExecutableObject, nid: %08X\n", moduleprobe_nid);
        return 0;
    } else {
        //zeroCtrlWriteDebug("ProbeExecutableObject nid: %08X, addr: %08X\n", moduleprobe_nid, (u32)sceKernelProbeExecutableObject);
    }
    return 1;
}
//OK
int zeroCtrlGetSlideState(void) {
	return slideState;
}
//OK
void zeroCtrlSetSlideState(int state) {
	slideState = state;
}
//OK
int zeroCtrlDummyFunc(void) {
        int k1 = pspSdkSetK1(0);               
	
	if(zeroCtrlGetSlideState() == ZERO_SLIDE_STOPPING) {
		//zeroCtrlWriteDebug("Unloading slide 1\n");
		zeroCtrlSetSlideState(ZERO_SLIDE_STOPPED);
		
		pspSdkSetK1(k1);
		return -1;
	} else if(zeroCtrlGetSlideState() == ZERO_SLIDE_STOPPED) {
		//zeroCtrlWriteDebug("Unloading slide 2\n");

		pspSdkSetK1(k1);
		return -1;
		
	}
	
        pspSdkSetK1(k1);
        return 0;
}
//OK
int zeroCtrlGetParam(u32 value) {
        int k1 = pspSdkSetK1(0);
        
        if(value == 0x8000000D) {	
		if(zeroCtrlGetSlideState() == ZERO_SLIDE_STARTING) {			
			//zeroCtrlWriteDebug("Starting slide\n");			
			zeroCtrlSetSlideState(ZERO_SLIDE_STARTED);
			
			pspSdkSetK1(k1);
			return 0;         
		} else if(zeroCtrlGetSlideState() == ZERO_SLIDE_STOPPED) {	
			pspSdkSetK1(k1);
			return 0;      
		}
        } else {
                //zeroCtrlWriteDebug("Not our param: 0x%08X\n\n", value);                
        }
        
        pspSdkSetK1(k1);
        return vshImposeGetParam(value);
}
//OK
int set_registry_value(const char *dir, const char *name, unsigned int val)
{
	int ret = 0;
	struct RegParam reg;
	REGHANDLE h;

	memset(&reg, 0, sizeof(reg));
	reg.regtype = 1;
	reg.namelen = strlen("/system");
	reg.unk2 = 1;
	reg.unk3 = 1;
	strcpy(reg.name, "/system");
	if(sceRegOpenRegistry(&reg, 2, &h) == 0)
	{
		REGHANDLE hd;
		if(!sceRegOpenCategory(h, dir, 2, &hd))
		{
			if(!sceRegSetKeyValue(hd, name, &val, 4))
			{
				ret = 1;
				sceRegFlushCategory(hd);
			}
			sceRegCloseCategory(hd);
		}
		sceRegFlushRegistry(h);
		sceRegCloseRegistry(h);
	}

	return ret;
}
//OK
#define SLIDE_CHECKPOINT_REQUEST             (1 << 0)
#define SLIDE_CHECKPOINT_RCO                 (1 << 1)
#define SLIDE_CHECKPOINT_PROBE_ENTERED       (1 << 2)
#define SLIDE_CHECKPOINT_PROBE_RETURNING     (1 << 3)
#define SLIDE_CHECKPOINT_START_ENTERED       (1 << 4)
#define SLIDE_CHECKPOINT_PREVIOUS_RETURNED   (1 << 5)
#define SLIDE_CHECKPOINT_TARGET_READ         (1 << 6)
#define SLIDE_CHECKPOINT_VALIDATED           (1 << 7)
#define SLIDE_CHECKPOINT_ORIGINAL_SAVED      (1 << 8)
#define SLIDE_CHECKPOINT_WORDS_WRITTEN       (1 << 9)
#define SLIDE_CHECKPOINT_CACHE_SYNC          (1 << 10)
#define SLIDE_CHECKPOINT_START_RETURNING     (1 << 11)
#define SLIDE_CHECKPOINT_VSH_SEEN            (1 << 12)

static void zeroCtrlWriteSlideCheckpoints(unsigned int *written) {
    char line[128];
#define WRITE_CHECKPOINT(flag, bit, text) \
    if ((flag) && !(*written & (bit))) { \
        zeroCtrlDiagnosticsText("[checkpoint] " text "\n"); \
        *written |= (bit); \
    }
    WRITE_CHECKPOINT(slide_diag.vsh_module_seen, SLIDE_CHECKPOINT_VSH_SEEN,
            "vsh_module_seen");
    WRITE_CHECKPOINT(slide_diag.saw_request, SLIDE_CHECKPOINT_REQUEST,
            "slide_request_observed");
    WRITE_CHECKPOINT(slide_diag.saw_rco_request, SLIDE_CHECKPOINT_RCO,
            "slide_rco_request_observed");
    WRITE_CHECKPOINT(slide_diag.probe_callback_entered,
            SLIDE_CHECKPOINT_PROBE_ENTERED, "slide_probe_callback_entered");
    if (slide_diag.probe_callback_returning &&
            !(*written & SLIDE_CHECKPOINT_PROBE_RETURNING)) {
        snprintf(line, sizeof(line),
                "[checkpoint] slide_probe_callback_returning result=0x%08X\n",
                (unsigned int)slide_diag.probe_result);
        zeroCtrlDiagnosticsText(line);
        *written |= SLIDE_CHECKPOINT_PROBE_RETURNING;
    }
    WRITE_CHECKPOINT(slide_diag.start_callback_entered,
            SLIDE_CHECKPOINT_START_ENTERED, "slide_start_callback_entered");
    if (slide_diag.previous_handler_returned &&
            !(*written & SLIDE_CHECKPOINT_PREVIOUS_RETURNED)) {
        snprintf(line, sizeof(line),
                "[checkpoint] slide_previous_handler_returned result=0x%08X\n",
                (unsigned int)slide_diag.previous_handler_result);
        zeroCtrlDiagnosticsText(line);
        *written |= SLIDE_CHECKPOINT_PREVIOUS_RETURNED;
    }
    if (slide_diag.module_start_target_read &&
            !(*written & SLIDE_CHECKPOINT_TARGET_READ)) {
        snprintf(line, sizeof(line),
                "[checkpoint] slide_module_start_target_read addr=0x%08X\n",
                slide_diag.module_start_addr);
        zeroCtrlDiagnosticsText(line);
        *written |= SLIDE_CHECKPOINT_TARGET_READ;
    }
    if (slide_diag.module_start_validation_complete &&
            !(*written & SLIDE_CHECKPOINT_VALIDATED)) {
        snprintf(line, sizeof(line),
                "[checkpoint] slide_module_start_validated result=%d\n",
                slide_diag.module_start_patch_result);
        zeroCtrlDiagnosticsText(line);
        *written |= SLIDE_CHECKPOINT_VALIDATED;
    }
    WRITE_CHECKPOINT(slide_diag.module_start_original_saved,
            SLIDE_CHECKPOINT_ORIGINAL_SAVED,
            "slide_module_start_original_saved");
    WRITE_CHECKPOINT(slide_diag.module_start_words_written,
            SLIDE_CHECKPOINT_WORDS_WRITTEN, "slide_module_start_words_written");
    WRITE_CHECKPOINT(slide_diag.module_start_cache_sync_complete,
            SLIDE_CHECKPOINT_CACHE_SYNC,
            "slide_module_start_cache_sync_complete");
    WRITE_CHECKPOINT(slide_diag.start_callback_returning,
            SLIDE_CHECKPOINT_START_RETURNING, "slide_start_callback_returning");
#undef WRITE_CHECKPOINT
}

static void zeroCtrlCaptureVshSharedGlobalValue(void) {
    zeroCtrlValidateVshSharedGlobalSegment(slide_diag.vsh_modid,
            slide_diag.vsh_text_addr);
    if (!slide_diag.vsh_shared_global_segment_valid) return;
    slide_diag.vsh_shared_global_value = _lw(slide_diag.vsh_shared_global_addr);
    slide_diag.vsh_shared_global_value_captured = 1;
}

static void zeroCtrlWriteVshStateReferences(const char *name,
        unsigned int target_offset, unsigned int total, unsigned int stored,
        unsigned int overflow, ZeroCtrlVshStateReference *references) {
    char line[224];
    unsigned int i;
    unsigned int j;

    snprintf(line, sizeof(line),
            "[vshstate_target] name=%s offset=0x%05X refs=%u stored=%u overflow=%u\n",
            name, target_offset, total, stored, overflow);
    zeroCtrlDiagnosticsText(line);
    for (i = 0; i < stored; i++) {
        ZeroCtrlVshStateReference *ref = &references[i];
        snprintf(line, sizeof(line),
                "[vshstate_ref] name=%s index=%u source=0x%08X offset=0x%05X word=0x%08X kind=%s\n",
                name, i, ref->source_addr, ref->source_offset,
                ref->instruction, ref->kind == 3 ? "JAL" : "J");
        zeroCtrlDiagnosticsText(line);
        for (j = 0; j < ref->window_size / 4; j++) {
            snprintf(line, sizeof(line),
                    "[vshstate_refcode] name=%s index=%u addr=0x%08X word=0x%08X\n",
                    name, i, slide_diag.vsh_text_addr +
                    ref->window_start_offset + j * 4, ref->window[j]);
            zeroCtrlDiagnosticsText(line);
        }
    }
}

static void zeroCtrlWriteVshFixedCode(const char *name, unsigned int start,
        unsigned int size, unsigned int *code) {
    char line[128];
    unsigned int i;

    snprintf(line, sizeof(line),
            "[vshstate_window] name=%s start=0x%05X size=0x%03X\n",
            name, start, size);
    zeroCtrlDiagnosticsText(line);
    for (i = 0; i < size / 4; i++) {
        snprintf(line, sizeof(line),
                "[vshstate_code] name=%s addr=0x%08X word=0x%08X\n",
                name, slide_diag.vsh_text_addr + start + i * 4, code[i]);
        zeroCtrlDiagnosticsText(line);
    }
}

static void zeroCtrlWriteVshSlideEvidence(void) {
    unsigned int i;
    unsigned int j;
    char line[224];
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");

    if (!slide_diag.vsh_module_seen) return;
    zeroCtrlCaptureVshSharedGlobalValue();
    zeroCtrlDiagnosticsEvent("vsh_modid", slide_diag.vsh_modid);
    zeroCtrlDiagnosticsEvent("vsh_text_addr", slide_diag.vsh_text_addr);
    zeroCtrlDiagnosticsEvent("vsh_text_size", slide_diag.vsh_text_size);
    zeroCtrlDiagnosticsEvent("vsh_module_start_func_addr",
            slide_diag.vsh_module_start_addr);
    zeroCtrlDiagnosticsEvent("vsh_elf_entry_addr", slide_diag.vsh_elf_entry_addr);
    zeroCtrlDiagnosticsEvent("vsh_slide_target", slide_diag.vsh_slide_target);
    zeroCtrlDiagnosticsEvent("vsh_slide_target_in_text",
            slide_diag.vsh_target_in_text);
    for (i = 0; i < VSH_TRIGGER_COUNT; i++) {
        ZeroCtrlVshTriggerEvidence *evidence = &slide_diag.triggers[i];
        if (!(slide_diag.trigger_mode & (1U << i))) continue;
        if (evidence->validation &&
                zeroCtrlVshModuleRangeValid(helper, evidence->counter_addr, 4))
            evidence->hit_count = *(volatile unsigned int *)evidence->counter_addr;
        snprintf(line, sizeof(line),
                "[trigger] caller_offset=0x%05X original_word=0x%08X "
                "target=0x%08X validation=%d replacement=0x%08X "
                "patch_applied=%d cache_sync=%d hit_count=%u\n",
                vsh_trigger_offsets[i], evidence->original_word,
                evidence->original_target, evidence->validation,
                evidence->replacement_word, evidence->patch_applied,
                evidence->cache_sync, evidence->hit_count);
        zeroCtrlDiagnosticsText(line);
    }
    if (slide_diag.global_predicate_enabled) {
        ZeroCtrlGlobalPredicateEvidence *global =
                &slide_diag.global_predicate;
        if (global->validation && zeroCtrlVshModuleRangeValid(helper,
                global->counter_addr, 4))
            global->hit_count =
                    *(volatile unsigned int *)global->counter_addr;
        snprintf(line, sizeof(line),
                "[global6f84] validation=%d structure_valid=%d "
                "decoded_global_addr=0x%08X expected_global_addr=0x%08X "
                "original_words=0x%08X,0x%08X "
                "replacement_words=0x%08X,0x%08X patch_applied=%d "
                "cache_sync=%d hit_count=%u\n",
                global->validation, global->structure_valid,
                global->decoded_global_addr, global->expected_global_addr,
                global->original_words[0],
                global->original_words[1], global->replacement_words[0],
                global->replacement_words[1], global->patch_applied,
                global->cache_sync, global->hit_count);
        zeroCtrlDiagnosticsText(line);
    }
    zeroCtrlDiagnosticsEvent("vsh_code_capture_start",
            slide_diag.vsh_code_capture_start);
    zeroCtrlDiagnosticsEvent("vsh_code_capture_end",
            slide_diag.vsh_code_capture_end);
    zeroCtrlDiagnosticsEvent("vsh_code_capture_size",
            slide_diag.vsh_code_capture_size);
    zeroCtrlDiagnosticsEvent("vsh_code_capture_result",
            slide_diag.vsh_code_capture_result);
    if (slide_diag.vsh_code_capture_result < 0) return;
    for (i = 0; i < slide_diag.vsh_code_capture_size / 4; i++) {
        snprintf(line, sizeof(line),
                "[vshcode] addr=0x%08X word=0x%08X\n",
                slide_diag.vsh_text_addr + slide_diag.vsh_code_capture_start + i * 4,
                slide_diag.vsh_code_words[i]);
        zeroCtrlDiagnosticsText(line);
    }
    zeroCtrlDiagnosticsEvent("vsh_direct_reference_total",
            slide_diag.vsh_direct_reference_total);
    zeroCtrlDiagnosticsEvent("vsh_direct_reference_stored",
            slide_diag.vsh_direct_reference_count);
    zeroCtrlDiagnosticsEvent("vsh_direct_reference_overflow",
            slide_diag.vsh_direct_reference_overflow);
    for (i = 0; i < VSH_PREDICATE_COUNT; i++) {
        snprintf(line, sizeof(line),
                "[vshmatrix] predicate=0x%04X references=%u\n",
                vsh_predicate_offsets[i],
                slide_diag.vsh_predicate_reference_count[i]);
        zeroCtrlDiagnosticsText(line);
    }
    for (i = 0; i < slide_diag.vsh_direct_reference_count; i++) {
        ZeroCtrlVshDirectReference *ref = &slide_diag.vsh_direct_references[i];
        if (ref->predicate_index != 2) continue;
        snprintf(line, sizeof(line),
                "[vshref] source=0x%08X offset=0x%05X word=0x%08X kind=%s predicate=0x%04X\n",
                ref->source_addr, ref->source_offset, ref->instruction,
                ref->kind == 3 ? "JAL" : "J",
                vsh_predicate_offsets[ref->predicate_index]);
        zeroCtrlDiagnosticsText(line);
        snprintf(line, sizeof(line),
                "[vshref_window] index=%u start=0x%05X size=0x%02X\n",
                i, ref->window_start_offset, ref->window_size);
        zeroCtrlDiagnosticsText(line);
        for (j = 0; j < ref->window_size / 4; j++) {
            snprintf(line, sizeof(line),
                    "[vshrefcode] index=%u addr=0x%08X word=0x%08X\n",
                    i, slide_diag.vsh_text_addr + ref->window_start_offset + j * 4,
                    ref->window[j]);
            zeroCtrlDiagnosticsText(line);
        }
    }
    zeroCtrlDiagnosticsEvent("vsh_shared_global_addr",
            slide_diag.vsh_shared_global_addr);
    zeroCtrlDiagnosticsEvent("vsh_shared_global_offset",
            slide_diag.vsh_shared_global_offset);
    zeroCtrlDiagnosticsEvent("vsh_shared_global_decode_valid",
            slide_diag.vsh_shared_global_decode_valid);
    zeroCtrlDiagnosticsEvent("vsh_shared_global_segment_valid",
            slide_diag.vsh_shared_global_segment_valid);
    if (slide_diag.vsh_shared_global_value_captured)
        zeroCtrlDiagnosticsEvent("vsh_shared_global_value",
                slide_diag.vsh_shared_global_value);
    zeroCtrlDiagnosticsEvent("vsh_global_reference_total",
            slide_diag.vsh_global_reference_total);
    zeroCtrlDiagnosticsEvent("vsh_global_reference_stored",
            slide_diag.vsh_global_reference_count);
    zeroCtrlDiagnosticsEvent("vsh_global_reference_overflow",
            slide_diag.vsh_global_reference_overflow);
    for (i = 0; i < slide_diag.vsh_global_reference_count; i++) {
        ZeroCtrlVshGlobalReference *ref = &slide_diag.vsh_global_references[i];
        if (ref->kind != 2) continue;
        snprintf(line, sizeof(line),
                "[vshglobal] source=0x%08X offset=0x%05X word=0x%08X kind=%s base=%u value=%u lui=0x%05X\n",
                ref->source_addr, ref->source_offset, ref->instruction,
                ref->kind == 2 ? "STORE" : "LOAD", ref->base_register,
                ref->value_register, ref->lui_offset);
        zeroCtrlDiagnosticsText(line);
        snprintf(line, sizeof(line),
                "[vshglobal_window] index=%u start=0x%05X size=0x%02X\n",
                i, ref->window_start_offset, ref->window_size);
        zeroCtrlDiagnosticsText(line);
        for (j = 0; j < ref->window_size / 4; j++) {
            snprintf(line, sizeof(line),
                    "[vshglobalcode] index=%u addr=0x%08X word=0x%08X\n",
                    i, slide_diag.vsh_text_addr + ref->window_start_offset + j * 4,
                    ref->window[j]);
            zeroCtrlDiagnosticsText(line);
        }
    }
    zeroCtrlDiagnosticsEvent("vsh_state_initializer_offset",
            VSH_STATE_INITIALIZER_CANDIDATE);
    zeroCtrlDiagnosticsEvent("vsh_state_initializer_refs",
            slide_diag.vsh_initializer_reference_total);
    zeroCtrlDiagnosticsEvent("vsh_state_import_offset",
            VSH_STATE_IMPORT_OFFSET);
    zeroCtrlDiagnosticsEvent("vsh_state_import_match",
            slide_diag.vsh_state_import_match);
    zeroCtrlDiagnosticsEvent("vsh_state_import_get_model_match",
            slide_diag.vsh_state_import_get_model_match);
    zeroCtrlDiagnosticsEvent("vsh_state_import_library_valid",
            slide_diag.vsh_state_import_library_valid);
    zeroCtrlDiagnosticsEvent("vsh_state_import_word0",
            slide_diag.vsh_state_import_words[0]);
    zeroCtrlDiagnosticsEvent("vsh_state_import_word1",
            slide_diag.vsh_state_import_words[1]);
    if (slide_diag.vsh_state_import_match) {
        snprintf(line, sizeof(line),
                "[vshimport] stub=0x%08X offset=0x%05X library=%s index=%u nid=0x%08X stubtable=0x%08X nidtable=0x%08X\n",
                slide_diag.vsh_state_import_stub, VSH_STATE_IMPORT_OFFSET,
                slide_diag.vsh_state_import_library_valid ?
                    slide_diag.vsh_state_import_library : "<invalid>",
                slide_diag.vsh_state_import_index,
                slide_diag.vsh_state_import_nid,
                slide_diag.vsh_state_import_stubtable,
                slide_diag.vsh_state_import_nidtable);
        zeroCtrlDiagnosticsText(line);
    }
    zeroCtrlWriteVshFixedCode("initializer_context",
            VSH_INITIALIZER_CAPTURE_START,
            slide_diag.vsh_initializer_capture_size,
            slide_diag.vsh_initializer_code);
    zeroCtrlWriteVshStateReferences("initializer_candidate",
            VSH_STATE_INITIALIZER_CANDIDATE,
            slide_diag.vsh_initializer_reference_total,
            slide_diag.vsh_initializer_reference_count,
            slide_diag.vsh_initializer_reference_overflow,
            slide_diag.vsh_initializer_references);
}

static unsigned int zeroCtrlReadTriggerHits(unsigned int index) {
    SceModule2 *helper;
    ZeroCtrlVshTriggerEvidence *evidence;

    if (index >= VSH_TRIGGER_COUNT) return 0;
    evidence = &slide_diag.triggers[index];
    if (!evidence->validation || !evidence->counter_addr) return 0;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!zeroCtrlVshModuleRangeValid(helper, evidence->counter_addr, 4))
        return 0;
    return *(volatile unsigned int *)evidence->counter_addr;
}

static unsigned int zeroCtrlReadGlobalPredicateHits(void) {
    SceModule2 *helper;
    ZeroCtrlGlobalPredicateEvidence *global = &slide_diag.global_predicate;

    if (!global->validation || !global->counter_addr) return 0;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!zeroCtrlVshModuleRangeValid(helper, global->counter_addr, 4)) return 0;
    return *(volatile unsigned int *)global->counter_addr;
}

static void zeroCtrlRefreshSonyStartTrace(void) {
    SceModule2 *helper;
    ZeroCtrlSonyStartTrace *trace = &slide_diag.sony_start_trace;
    if (!trace->registered) return;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!zeroCtrlVshModuleRangeValid(helper, trace->entry_seen_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->return_seen_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->result_addr, 4)) return;
    trace->entry_seen = *(volatile int *)trace->entry_seen_addr;
    trace->return_seen = *(volatile int *)trace->return_seen_addr;
    trace->result = *(volatile int *)trace->result_addr;
}

static unsigned int zeroCtrlReadBSManHits(void) {
    SceModule2 *helper;
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    if (!bsman->registered || !bsman->hit_count_addr) return 0;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!zeroCtrlVshModuleRangeValid(helper, bsman->hit_count_addr, 4)) return 0;
    return *(volatile unsigned int *)bsman->hit_count_addr;
}

static const char *zeroCtrlBSManStubFormName(unsigned int form) {
    static const char *names[] = {
        "UNKNOWN", "JUMP_NOP", "JR_RA_SYSCALL", "SYSCALL_NOP"
    };
    if (form >= sizeof(names) / sizeof(names[0])) return "UNKNOWN";
    return names[form];
}

static const char *zeroCtrlSonyRegisterReasonName(int reason) {
    static const char *names[] = {
        "NONE", "TRACE_DISABLED", "ALREADY_REGISTERED", "HELPER_NOT_FOUND",
        "ENTRY_END_ORDER", "EXIT_END_ORDER", "ENTRY_STUB_TOO_LARGE",
        "EXIT_STUB_TOO_LARGE", "ENTRY_STUB_OUT_OF_RANGE",
        "EXIT_STUB_OUT_OF_RANGE", "RESUME_SLOT_OUT_OF_RANGE",
        "CALLER_RA_SLOT_OUT_OF_RANGE", "ENTRY_FLAG_OUT_OF_RANGE",
        "RETURN_FLAG_OUT_OF_RANGE", "RESULT_SLOT_OUT_OF_RANGE",
        "ENTRY_MISALIGNED", "EXIT_MISALIGNED", "DESCRIPTOR_NULL",
        "DESCRIPTOR_OUT_OF_RANGE"
    };
    if (reason < 0 || (unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "UNKNOWN";
    return names[reason];
}

static const char *zeroCtrlSonyGuardReasonName(int reason) {
    static const char *names[] = {
        "NONE", "TRACE_DISABLED", "TRACE_NOT_REGISTERED", "MODEL_MISMATCH",
        "NULL_MODULE", "MODULE_NAME_MISMATCH", "DEVKIT_MISMATCH",
        "TEXT_TOO_SMALL", "ADDRESS_OVERFLOW"
    };
    if (reason < 0 || (unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "UNKNOWN";
    return names[reason];
}

static void zeroCtrlWriteLateTransition(unsigned int elapsed,
        const char *name, unsigned int value) {
    char line[112];

    snprintf(line, sizeof(line), "[late] elapsed_us=%u %s=%u\n",
            elapsed, name, value);
    zeroCtrlDiagnosticsText(line);
}

static int zeroCtrlWriteSlideDiagnostics(SceSize args UNUSED, void *argp UNUSED) {
    unsigned int elapsed = 0;
    unsigned int written = 0;
    unsigned int observed_hits[VSH_TRIGGER_COUNT] = { 0, 0, 0 };
    int observed_request = 0;
    int observed_rco_request = 0;
    int observed_probe = 0;
    int observed_start = 0;
    unsigned int observed_global_hits = 0;
    int observed_trace_attempt = 0, observed_trace_validation = 0;
    int observed_trace_install = 0, observed_start_entry = 0;
    int observed_start_return = 0;
    int observed_registration_called = 0, observed_guard_checked = 0;
    unsigned int observed_bsman_hits = 0;
    int observed_bsman_attempted = 0;
    char line[256];
    unsigned int i;

    slide_diag.writer_alive = 1;
    zeroCtrlDiagnosticsText("[checkpoint] slide_diag_writer_alive\n");
    while (elapsed < SLIDE_OBSERVATION_WINDOW_US) {
        zeroCtrlWriteSlideCheckpoints(&written);
        for (i = 0; i < VSH_TRIGGER_COUNT; i++) {
            unsigned int hits = zeroCtrlReadTriggerHits(i);
            if (hits != observed_hits[i]) {
                static const char *names[VSH_TRIGGER_COUNT] = {
                    "caller_58d4_hit_count", "caller_13f6c_hit_count",
                    "caller_14020_hit_count"
                };
                observed_hits[i] = hits;
                zeroCtrlWriteLateTransition(elapsed, names[i], hits);
            }
        }
        if (slide_diag.global_predicate_enabled) {
            unsigned int hits = zeroCtrlReadGlobalPredicateHits();
            if (hits != observed_global_hits) {
                observed_global_hits = hits;
                zeroCtrlWriteLateTransition(elapsed,
                        "global_6f84_hit_count", hits);
            }
        }
#define WRITE_LATE_FLAG(field, observed, name) \
        if ((field) != (observed)) { \
            (observed) = (field); \
            zeroCtrlWriteLateTransition(elapsed, (name), (unsigned int)(observed)); \
        }
        WRITE_LATE_FLAG(slide_diag.saw_request, observed_request, "request");
        WRITE_LATE_FLAG(slide_diag.saw_rco_request, observed_rco_request,
                "rco_request");
        WRITE_LATE_FLAG(slide_diag.saw_probe, observed_probe, "probe");
        WRITE_LATE_FLAG(slide_diag.saw_start, observed_start, "start");
        if (slide_diag.sony_start_trace.enabled) {
            ZeroCtrlSonyStartTrace *trace = &slide_diag.sony_start_trace;
            zeroCtrlRefreshSonyStartTrace();
            if (trace->registration_called && !observed_registration_called) {
                snprintf(line, sizeof(line),
                        "[sony-start-register-descriptor] address=0x%08X "
                        "size=%u validation=%d\n",
                        trace->descriptor_addr, trace->descriptor_size,
                        trace->descriptor_validation);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[sony-start-register] called=1 success=%d "
                        "fail_reason=%s(%d)\n",
                        trace->registration_success,
                        zeroCtrlSonyRegisterReasonName(
                            trace->registration_fail_reason),
                        trace->registration_fail_reason);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[sony-start-register-addresses] entry=0x%08X "
                        "entry_end=0x%08X exit=0x%08X exit_end=0x%08X\n",
                        trace->supplied_addrs[0], trace->supplied_addrs[1],
                        trace->supplied_addrs[2], trace->supplied_addrs[3]);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[sony-start-register-slots] resume=0x%08X caller_ra=0x%08X "
                        "entry_seen=0x%08X return_seen=0x%08X result=0x%08X\n",
                        trace->supplied_addrs[4], trace->supplied_addrs[5],
                        trace->supplied_addrs[6], trace->supplied_addrs[7],
                        trace->supplied_addrs[8]);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[sony-start-register-helper] text=0x%08X text_size=0x%X "
                        "data_size=0x%X bss_size=0x%X segments=%u\n",
                        trace->helper_text_addr, trace->helper_text_size,
                        trace->helper_data_size, trace->helper_bss_size,
                        trace->helper_segment_count);
                zeroCtrlDiagnosticsText(line);
                for (i = 0; i < trace->helper_segment_count && i < 4; i++) {
                    snprintf(line, sizeof(line),
                            "[sony-start-register-segment] index=%u "
                            "start=0x%08X size=0x%X\n", i,
                            trace->helper_segment_addr[i],
                            trace->helper_segment_size[i]);
                    zeroCtrlDiagnosticsText(line);
                }
                observed_registration_called = 1;
            }
            if (trace->initial_guard_checked && !observed_guard_checked) {
                snprintf(line, sizeof(line),
                        "[sony-start-guard] checked=1 reason=%s(%d)\n",
                        zeroCtrlSonyGuardReasonName(trace->initial_guard_reason),
                        trace->initial_guard_reason);
                zeroCtrlDiagnosticsText(line);
                observed_guard_checked = 1;
            }
            if (trace->attempted != observed_trace_attempt ||
                    trace->validation != observed_trace_validation ||
                    trace->install != observed_trace_install) {
                snprintf(line, sizeof(line),
                        "[sony-start-ra] attempted=%d validation=%d "
                        "install=%d cache_sync=%d original=0x%08X\n",
                        trace->attempted, trace->validation, trace->install,
                        trace->cache_sync, trace->original_addr);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[sony-start-entry] original_words=0x%08X,0x%08X,0x%08X "
                        "replacement_words=0x%08X,0x%08X resume=0x%08X "
                        "exit_stub=0x%08X\n",
                        trace->entry_original[0], trace->entry_original[1],
                        trace->entry_original[2], trace->entry_replacement[0],
                        trace->entry_replacement[1], trace->original_addr + 8,
                        trace->exit_stub_addr);
                zeroCtrlDiagnosticsText(line);
                observed_trace_attempt = trace->attempted;
                observed_trace_validation = trace->validation;
                observed_trace_install = trace->install;
            }
            WRITE_LATE_FLAG(trace->entry_seen, observed_start_entry,
                    "sony_module_start_entered");
            if (trace->return_seen != observed_start_return) {
                observed_start_return = trace->return_seen;
                zeroCtrlWriteLateTransition(elapsed,
                        "sony_module_start_returned",
                        (unsigned int)observed_start_return);
                if (observed_start_return) {
                    zeroCtrlDiagnosticsCapturePartitions(
                            &trace->return_observed);
                    trace->return_snapshot_captured = 1;
                    snprintf(line, sizeof(line),
                            "[sony-start] result=0x%08X\n",
                            (unsigned int)trace->result);
                    zeroCtrlDiagnosticsText(line);
                    zeroCtrlDiagnosticsWritePartitions(
                            "sony_module_start_return_observed",
                            &trace->return_observed);
                }
            }
        }
        if (slide_diag.bsman.enabled) {
            ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
            unsigned int hits = zeroCtrlReadBSManHits();
            if (bsman->attempted && !observed_bsman_attempted) {
                snprintf(line, sizeof(line),
                        "[bsman] attempted=%d import_found=%d unique_match=%d "
                        "validation=%d install=%d cache_sync=%d\n",
                        bsman->attempted, bsman->import_found,
                        bsman->unique_match, bsman->validation,
                        bsman->install, bsman->cache_sync);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[bsman] library=sceBSMan nid=0x23E3A9B6 "
                        "stub=0x%08X closed_value=%d\n",
                        bsman->import_stub_addr, bsman->closed_value);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[bsman] stub_form=%s syscall_code=0x%05X\n",
                        zeroCtrlBSManStubFormName(bsman->stub_form),
                        bsman->syscall_code);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[bsman] original_words=0x%08X,0x%08X "
                        "replacement_words=0x%08X,0x%08X\n",
                        bsman->original_words[0], bsman->original_words[1],
                        bsman->replacement_words[0],
                        bsman->replacement_words[1]);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[bsman-caller] address=0x%08X "
                        "words=0x%08X,0x%08X,0x%08X,0x%08X "
                        "semantics=beq_v0_zero_closed confidence=STRONG_INFERENCE\n",
                        bsman->caller_addr, bsman->caller_words[0],
                        bsman->caller_words[1], bsman->caller_words[2],
                        bsman->caller_words[3]);
                zeroCtrlDiagnosticsText(line);
                observed_bsman_attempted = 1;
            }
            if (hits != observed_bsman_hits) {
                observed_bsman_hits = hits;
                zeroCtrlWriteLateTransition(elapsed, "bsman_hit_count", hits);
            }
        }
#undef WRITE_LATE_FLAG
        sceKernelDelayThread(SLIDE_OBSERVATION_POLL_US);
        elapsed += SLIDE_OBSERVATION_POLL_US;
    }
    zeroCtrlWriteSlideCheckpoints(&written);
    zeroCtrlDiagnosticsCapturePartitions(&slide_diag.delayed_or_timeout);

    for (i = 0; i < VSH_TRIGGER_COUNT; i++)
        observed_hits[i] = zeroCtrlReadTriggerHits(i);
    observed_global_hits = zeroCtrlReadGlobalPredicateHits();
    snprintf(line, sizeof(line),
            "[final] observation_window_us=%u\n"
            "[final] caller_58d4_hit_count=%u caller_13f6c_hit_count=%u "
            "caller_14020_hit_count=%u\n"
            "[final] global_6f84_hit_count=%u\n"
            "[final] request=%d rco_request=%d probe=%d start=%d\n",
            SLIDE_OBSERVATION_WINDOW_US, observed_hits[0], observed_hits[1],
            observed_hits[2], observed_global_hits, slide_diag.saw_request,
            slide_diag.saw_rco_request, slide_diag.saw_probe,
            slide_diag.saw_start);
    zeroCtrlDiagnosticsText(line);
    if (slide_diag.sony_start_trace.enabled) {
        ZeroCtrlSonyStartTrace *trace = &slide_diag.sony_start_trace;
        zeroCtrlRefreshSonyStartTrace();
        snprintf(line, sizeof(line),
                "[sony-start] final attempted=%d validation=%d install=%d "
                "cache_sync=%d entered=%d returned=%d result=0x%08X\n",
                trace->attempted, trace->validation, trace->install,
                trace->cache_sync, trace->entry_seen, trace->return_seen,
                (unsigned int)trace->result);
        zeroCtrlDiagnosticsText(line);
    }
    if (slide_diag.bsman.enabled) {
        snprintf(line, sizeof(line),
                "[bsman] final install=%d validation=%d hit_count=%u\n",
                slide_diag.bsman.install, slide_diag.bsman.validation,
                zeroCtrlReadBSManHits());
        zeroCtrlDiagnosticsText(line);
    }

    zeroCtrlWriteVshSlideEvidence();
    if (slide_diag.saw_request) zeroCtrlDiagnosticsText("[event] slide_request_seen\n");
    if (slide_diag.saw_rco_request) zeroCtrlDiagnosticsText("[event] slide_rco_request_seen\n");
    if (slide_diag.saw_probe) {
        zeroCtrlDiagnosticsText("[event] slide_probe_seen\n");
        zeroCtrlDiagnosticsEvent("slide_probe_result", slide_diag.probe_result);
        zeroCtrlDiagnosticsWritePartitions("at_slide_plugin_probe",
                &slide_diag.at_probe);
    } else {
        zeroCtrlDiagnosticsText(
                "[event] slide_probe_not_seen timeout_us=12000000\n");
    }
    if (slide_diag.saw_start) {
        zeroCtrlDiagnosticsText("[event] slide_module_start_seen\n");
        zeroCtrlDiagnosticsEvent("slide_module_modid", slide_diag.module.modid);
        zeroCtrlDiagnosticsWritePartitions("slide_plugin_pre_start", &slide_diag.pre_start);
        zeroCtrlDiagnosticsModule(&slide_diag.module);
        zeroCtrlDiagnosticsEvent("slide_module_start_func_addr",
                slide_diag.module_start_addr);
        zeroCtrlDiagnosticsEvent("slide_elf_entry_addr", slide_diag.elf_entry_addr);
        zeroCtrlDiagnosticsText("[experiment] sony_module_start_control=natural\n");
        zeroCtrlDiagnosticsWritePartitions("slide_plugin_delayed",
                &slide_diag.delayed_or_timeout);
    } else {
        zeroCtrlDiagnosticsText(
                "[event] slide_module_start_not_seen timeout_us=12000000\n");
        zeroCtrlDiagnosticsWritePartitions("slide_plugin_start_timeout",
                &slide_diag.delayed_or_timeout);
    }
    slide_diag.deferred_thread_started = 0;
    sceKernelExitDeleteThread(0);
    return 0;
}

static int zeroCtrlCreateSlideDiagnosticsThread(void) {
    SceUID thid;
    int result;

    if (slide_diag.deferred_thread_started) return 0;
    thid = sceKernelCreateThread("zeroctrl_slide_diag", zeroCtrlWriteSlideDiagnostics,
            0x18, 0x2000, 0, NULL);
    if (thid < 0) return thid;
    slide_diag.deferred_thread_started = 1;
    result = sceKernelStartThread(thid, 0, NULL);
    if (result < 0) {
        sceKernelDeleteThread(thid);
        slide_diag.deferred_thread_started = 0;
    }
    return result;
}

static void zeroCtrlInstallSonyStartTrace(SceModule2 *mod) {
    ZeroCtrlSonyStartTrace *trace = &slide_diag.sony_start_trace;
    SceModule2 *helper;
    unsigned int start;

    trace->initial_guard_checked = 1;
    if (!trace->enabled) {
        trace->initial_guard_reason = SONY_START_GUARD_TRACE_DISABLED;
        return;
    }
    if (!trace->registered) {
        trace->initial_guard_reason = SONY_START_GUARD_TRACE_NOT_REGISTERED;
        return;
    }
    if (model != 0) {
        trace->initial_guard_reason = SONY_START_GUARD_MODEL_MISMATCH;
        return;
    }
    if (!mod) {
        trace->initial_guard_reason = SONY_START_GUARD_NULL_MODULE;
        return;
    }
    if (strcmp(mod->modname, "slide_plugin_module") != 0) {
        trace->initial_guard_reason = SONY_START_GUARD_MODULE_NAME_MISMATCH;
        return;
    }
    if (sceKernelDevkitVersion() != 0x06060110) {
        trace->initial_guard_reason = SONY_START_GUARD_DEVKIT_MISMATCH;
        return;
    }
    if (mod->text_size < 0xFA4) {
        trace->initial_guard_reason = SONY_START_GUARD_TEXT_TOO_SMALL;
        return;
    }
    if (mod->text_addr > 0xFFFFFFFFU - 0xF98) {
        trace->initial_guard_reason = SONY_START_GUARD_ADDRESS_OVERFLOW;
        return;
    }
    trace->initial_guard_reason = SONY_START_GUARD_NONE;
    trace->attempted = 1;
    start = mod->module_start_func;
    trace->original_addr = start;
    if (start != mod->text_addr + 0xF98 || (start & 3) != 0 ||
            !zeroCtrlVshModuleRangeValid(mod, start, 12)) return;

    trace->entry_original[0] = _lw(start);
    trace->entry_original[1] = _lw(start + 4);
    trace->entry_original[2] = _lw(start + 8);
    if ((trace->entry_original[0] >> 26) != 9 ||
            ((trace->entry_original[0] >> 21) & 0x1F) != 29 ||
            ((trace->entry_original[0] >> 16) & 0x1F) != 29 ||
            (short)(trace->entry_original[0] & 0xFFFF) != -16 ||
            (trace->entry_original[1] >> 26) != 0x2B ||
            ((trace->entry_original[1] >> 21) & 0x1F) != 29 ||
            ((trace->entry_original[1] >> 16) & 0x1F) != 16 ||
            (trace->entry_original[1] & 0xFFFF) != 0 ||
            (trace->entry_original[2] >> 26) != 0x2B ||
            ((trace->entry_original[2] >> 21) & 0x1F) != 29 ||
            ((trace->entry_original[2] >> 16) & 0x1F) != 31 ||
            (trace->entry_original[2] & 0xFFFF) != 4) return;

    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!zeroCtrlVshModuleRangeValid(helper, trace->entry_stub_addr,
                trace->entry_stub_size) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->exit_stub_addr,
                trace->exit_stub_size) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->resume_slot_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->caller_ra_slot_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->entry_seen_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->return_seen_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, trace->result_addr, 4) ||
            ((start + 4) & 0xF0000000) !=
                (trace->entry_stub_addr & 0xF0000000)) return;

    trace->entry_replacement[0] = 0x08000000 |
            ((trace->entry_stub_addr >> 2) & 0x03FFFFFF);
    trace->entry_replacement[1] = 0;
    if ((((start + 4) & 0xF0000000) |
                ((trace->entry_replacement[0] & 0x03FFFFFF) << 2)) !=
                    trace->entry_stub_addr) return;
    trace->validation = 1;

    _sw(start + 8, trace->resume_slot_addr);
    _sw(0, trace->caller_ra_slot_addr);
    _sw(0, trace->entry_seen_addr);
    _sw(0, trace->return_seen_addr);
    _sw(0, trace->result_addr);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)trace->resume_slot_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)trace->caller_ra_slot_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)trace->entry_seen_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)trace->return_seen_addr, 4);
    sceKernelDcacheWritebackInvalidateRange((const void *)trace->result_addr, 4);

    /* Transaction commit: the complete entry interposition validated above. */
    _sw(trace->entry_replacement[0], start);
    _sw(trace->entry_replacement[1], start + 4);
    sceKernelDcacheWritebackInvalidateRange((const void *)start, 8);
    sceKernelIcacheInvalidateRange((const void *)start, 8);
    trace->install = 1;
    trace->cache_sync = 1;
}

static int zeroCtrlBSManLibraryNameValid(SceModule2 *mod, const char *name) {
    static const char expected[] = "sceBSMan";
    unsigned int i;
    if (!zeroCtrlVshModuleRangeValid(mod, (unsigned int)name,
                sizeof(expected))) return 0;
    for (i = 0; i < sizeof(expected); i++)
        if (name[i] != expected[i]) return 0;
    return 1;
}

static unsigned int zeroCtrlBSManOriginalStubForm(unsigned int word0,
        unsigned int word1) {
    unsigned int opcode = word0 >> 26;
    if ((opcode == 2 || opcode == 3) && word1 == 0)
        return ZERO_BSMAN_STUB_JUMP_NOP;
    if (word0 == 0x03E00008 &&
            (word1 & 0xFC00003F) == 0x0000000C)
        return ZERO_BSMAN_STUB_JR_RA_SYSCALL;
    if ((word0 & 0xFC00003F) == 0x0000000C && word1 == 0)
        return ZERO_BSMAN_STUB_SYSCALL_NOP;
    return ZERO_BSMAN_STUB_UNKNOWN;
}

static void zeroCtrlInstallBSManClosedShim(SceModule2 *mod) {
    const unsigned int target_nid = 0x23E3A9B6;
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    unsigned int cursor, end, offset, caller_matches = 0;

    if (!bsman->enabled || !bsman->registered || model != 0 || !mod ||
            strcmp(mod->modname, "slide_plugin_module") != 0 ||
            sceKernelDevkitVersion() != 0x06060110) return;
    bsman->attempted = 1;
    cursor = (unsigned int)mod->stub_top;
    end = cursor + mod->stub_size;
    if (end < cursor || !zeroCtrlVshModuleRangeValid(mod, cursor,
                mod->stub_size)) return;

    while (cursor < end) {
        SceLibraryStubTable *table = (SceLibraryStubTable *)cursor;
        unsigned int bytes, i;
        if ((cursor & 3) != 0 || end - cursor < 12) return;
        bytes = (unsigned int)table->len * 4;
        if (bytes < __builtin_offsetof(SceLibraryStubTable, stubtable) + 4 ||
                bytes > end - cursor ||
                !zeroCtrlVshModuleRangeValid(mod, cursor, bytes)) return;
        if (zeroCtrlBSManLibraryNameValid(mod, table->libname)) {
            bsman->import_found = 1;
            if (!zeroCtrlVshModuleRangeValid(mod, (unsigned int)table->nidtable,
                        (unsigned int)table->stubcount * 4) ||
                    !zeroCtrlVshModuleRangeValid(mod,
                        (unsigned int)table->stubtable,
                        (unsigned int)table->stubcount * 8)) return;
            for (i = 0; i < table->stubcount; i++) {
                if (table->nidtable[i] != target_nid) continue;
                bsman->match_count++;
                bsman->nidtable_addr = (unsigned int)&table->nidtable[i];
                bsman->stubtable_addr = (unsigned int)table->stubtable;
                bsman->import_stub_addr =
                        (unsigned int)table->stubtable + i * 8;
            }
        }
        cursor += bytes;
    }
    bsman->unique_match = bsman->match_count == 1;
    if (!bsman->unique_match || (bsman->import_stub_addr & 7) != 0 ||
            !zeroCtrlVshModuleRangeValid(mod, bsman->import_stub_addr, 8) ||
            ((bsman->import_stub_addr + 4) & 0xF0000000) !=
                (bsman->leaf_addr & 0xF0000000)) return;

    bsman->original_words[0] = _lw(bsman->import_stub_addr);
    bsman->original_words[1] = _lw(bsman->import_stub_addr + 4);
    bsman->stub_form = zeroCtrlBSManOriginalStubForm(
            bsman->original_words[0], bsman->original_words[1]);
    if (bsman->stub_form == ZERO_BSMAN_STUB_UNKNOWN) return;
    if (bsman->stub_form == ZERO_BSMAN_STUB_SYSCALL_NOP)
        bsman->syscall_code = (bsman->original_words[0] >> 6) & 0xFFFFF;
    else if (bsman->stub_form == ZERO_BSMAN_STUB_JR_RA_SYSCALL)
        bsman->syscall_code = (bsman->original_words[1] >> 6) & 0xFFFFF;

    /* Runtime caller proof: require one direct call and a strict zero test. */
    for (offset = 0; offset + 12 <= mod->text_size; offset += 4) {
        unsigned int pc = mod->text_addr + offset;
        unsigned int instruction = _lw(pc);
        unsigned int branch;
        if ((instruction >> 26) != 3 ||
                zeroCtrlMipsJumpTarget(pc, instruction) !=
                    bsman->import_stub_addr) continue;
        bsman->caller_addr = pc;
        bsman->caller_words[0] = offset >= 4 ? _lw(pc - 4) : 0;
        bsman->caller_words[1] = instruction;
        bsman->caller_words[2] = _lw(pc + 4);
        bsman->caller_words[3] = _lw(pc + 8);
        branch = bsman->caller_words[3];
        if ((branch >> 26) == 4 && ((branch >> 21) & 0x1F) == 2 &&
                ((branch >> 16) & 0x1F) == 0)
            bsman->closed_value = 0;
        else
            return;
        caller_matches++;
    }
    if (caller_matches != 1 || !bsman->caller_addr) return;

    bsman->replacement_words[0] = 0x08000000 |
            ((bsman->leaf_addr >> 2) & 0x03FFFFFF);
    bsman->replacement_words[1] = 0;
    if ((((bsman->import_stub_addr + 4) & 0xF0000000) |
                ((bsman->replacement_words[0] & 0x03FFFFFF) << 2)) !=
                    bsman->leaf_addr) return;
    bsman->validation = 1;

    /* Transaction commit: no BSMan code write occurs before every check. */
    _sw(bsman->replacement_words[0], bsman->import_stub_addr);
    _sw(bsman->replacement_words[1], bsman->import_stub_addr + 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->import_stub_addr, 8);
    sceKernelIcacheInvalidateRange((const void *)bsman->import_stub_addr, 8);
    bsman->install = 1;
    bsman->cache_sync = 1;
}

int OnModuleStart(SceModule2 *mod) {
        zeroCtrlWriteDebug("Module: %s\n", mod->modname);

        if (zeroCtrlIsPsp1000SlideExperimentEnabled() &&
                strcmp(mod->modname, "slide_plugin_module") == 0) {
                int previous_result;

                slide_diag.start_callback_entered = 1;
                zeroCtrlDiagnosticsCapturePartitions(&slide_diag.pre_start);
                memcpy(&slide_diag.module, mod, sizeof(slide_diag.module));
                previous_result = previous ? previous(mod) : 0;
                slide_diag.previous_handler_result = previous_result;
                slide_diag.previous_handler_returned = 1;
                slide_diag.module_start_addr = mod->module_start_func;
                slide_diag.elf_entry_addr = mod->entry_addr;
                zeroCtrlInstallSonyStartTrace(mod);
                zeroCtrlInstallBSManClosedShim(mod);
                slide_diag.start_callback_returning = 1;
                slide_diag.saw_start = 1;
                return previous_result;
        }
        
        if(strcmp(mod->modname, "slide_plugin_module") == 0) {            
                hook_import_bynid(mod, "sceBSMan", 0x23E3A9B6, zeroCtrlDummyFunc, 1);
                hook_import_bynid(mod, "sceVshBridge", 0x639C3CB3, zeroCtrlGetParam, 1);				
        }
        
       ClearCaches();
       return previous ? previous(mod) : 0;
}
//OK
int zeroCtrlLoadStartModule(SceSize args UNUSED, void *argp UNUSED) {	
	SceUID modid;
	int start_result = 0;
	int wait_iterations = 0;
	ZeroCtrlPartitionSnapshot after_load;
	ZeroCtrlPartitionSnapshot after_start;
	
	//zeroCtrlWriteDebug("Thread\n");
	
	do {
		sceKernelDelayThread(100000);
		wait_iterations++;
	} while(!sceKernelFindModuleByName("sceKernelLibrary"));
	modid = sceKernelLoadModuleBuffer(
			size_zerovsh_user_module, zerovsh_user_module, 0, NULL);
	if (model == 0) {
		zeroCtrlDiagnosticsCapturePartitions(&after_load);
	}
	if(modid >= 0) {
		start_result = sceKernelStartModule(modid, 0, NULL, 0, NULL);
		if (model == 0) {
			zeroCtrlDiagnosticsCapturePartitions(&after_start);
		}
	}

	zeroCtrlDiagnosticsLoaderControl(wait_iterations);
	if (modid >= 0) {
		zeroCtrlDiagnosticsStartControl();
	}
	zeroCtrlDiagnosticsEvent("user_module_load", modid);
	if (model == 0) {
		zeroCtrlDiagnosticsWritePartitions("after_user_module_load", &after_load);
	}
	
	if(modid >= 0) {
		zeroCtrlDiagnosticsEvent("user_module_start", start_result);
		if (model == 0) {
			zeroCtrlDiagnosticsWritePartitions(start_result < 0 ?
					"after_user_module_start_failed" : "after_user_module_start",
					&after_start);
			zeroCtrlDiagnosticsModule(sceKernelFindModuleByName("ZeroVSH_Patcher_User"));
		}
		if (start_result < 0) {
			sceKernelUnloadModule(modid);
		}
	} else {
		//zeroCtrlWriteDebug("Module ID: 0x%08X\n", modid);
	}
	
	sceKernelExitDeleteThread(0);
	return 0;
}
//OK
void zeroCtrlCreatePatchThread(void) {	
	SceUID thid;
	int start_result;
	
	thid = sceKernelCreateThread("zeroctrl_umod", zeroCtrlLoadStartModule, 0x10, 0x10000, 0, NULL);
	zeroCtrlDiagnosticsEvent("user_thread_create", thid);
	
	if(thid >= 0) {
		start_result = sceKernelStartThread(thid, 0, NULL);
		zeroCtrlDiagnosticsEvent("user_thread_start", start_result);
		if (start_result < 0) {
			sceKernelDeleteThread(thid);
		}
	} else {
		//zeroCtrlWriteDebug("Thread ID: 0x%08X\n", thid);	
	}	
}
//OK
int zeroCtrlGetSlideConfig(const char *item, char *value) {
	int k1 = pspSdkSetK1(0);
	SceUID cfg_id = -1;
	char *usermem = zeroCtrlAllocUserBuffer(&cfg_id, 256);
	
	if(!usermem) {
		pspSdkSetK1(k1);
		return -1;
	}
	
	memset(usermem, 0, 256);
	ini_gets("SlidePlugin", item, "Disabled", usermem, 256, "ms0:/seplugins/zerovsh.ini");
	strcpy(value, usermem);
	
	zeroCtrlFreeUserBuffer(cfg_id);
	pspSdkSetK1(k1);
	return 0;
}
//OK
void zeroCtrlSetSlideConfig(const char *item, const char *value) {
	int k1 = pspSdkSetK1(0);
	ini_puts("SlidePlugin", item,  value, "ms0:/seplugins/zerovsh.ini");
	pspSdkSetK1(k1);
}
//OK
int zeroCtrlGetModel(void) {
	int ret;
	int k1 = pspSdkSetK1(0);
	
	ret = sceKernelGetModel();
	
	pspSdkSetK1(k1);
	return ret;
}
//OK
int zeroCtrlContrast2Hour(void) {		
	if(strcmp(slideContrast, "Disabled") == 0) {
		return -1;
	} else if(strcmp(slideContrast, "1") == 0) {
		return 6;
	}  else if(strcmp(slideContrast, "2") == 0) {
		return 9;
	}  else if(strcmp(slideContrast, "3") == 0) {
		return 12;
	}  else if(strcmp(slideContrast, "4") == 0) {
		return 15;
	}  else if(strcmp(slideContrast, "5") == 0) {
		return 18;
	}  else if(strcmp(slideContrast, "6") == 0) {
		return 21;
	}  else if(strcmp(slideContrast, "7") == 0) {
		return 3;
	}  else if(strcmp(slideContrast, "8") == 0) {
		return 0;
	} 
	
	return -1;
}
//OK
void GetSpeed(int *cpufreq, int *busfreq) {
	if(scePowerGetCpuClockFrequency == NULL) {
		scePowerGetCpuClockFrequency = (void *)sctrlHENFindFunction("scePower_Service", "scePower", 0xFEE03A2F);		
	} 
	
	zeroCtrlWriteDebug("Found getCpu\n\n");
	
	if(scePowerGetBusClockFrequency == NULL) {
		scePowerGetBusClockFrequency = (void *)sctrlHENFindFunction("scePower_Service", "scePower", 0x478FE6F5);
		
	}	
	
	zeroCtrlWriteDebug("Found getBus\n\n");
	
	*cpufreq = scePowerGetCpuClockFrequency();
	*busfreq = scePowerGetBusClockFrequency();	
}
//OK
void zeroCtrlSetLEDState(void) {
	int k1 = pspSdkSetK1(0);
	
	if(strcmp(ledDisable, "Enabled") == 0) {
		sceSysconCtrlLED(0, 0);
		sceSysconCtrlLED(1, 0);
		sceSysconCtrlLED(2, 0);
		sceSysconCtrlLED(3, 0);
		sceSysconCtrlLED(4, 0);
	}
	
	pspSdkSetK1(k1);
}
//OK
void zeroCtrlRestoreLEDState(void) {
	if(strcmp(ledDisable, "Enabled") == 0) {
		sceSysconCtrlLED(0, 1);
		sceSysconCtrlLED(1, 1);
		sceSysconCtrlLED(2, 1);
		sceSysconCtrlLED(3, 1);
		sceSysconCtrlLED(4, 1);
	}
}
//OK
void zeroCtrlSetBrightness(void) {
	int k1 = pspSdkSetK1(0);
	
	if(b_level != -1) {
		sceDisplayGetBrightness(&brightness, NULL);
		sceDisplaySetBrightness(b_level, 0);	
	}
	
	pspSdkSetK1(k1);
}
//OK
void zeroCtrlSetClockSpeed(void) {
	int k1 = pspSdkSetK1(0);
	
	GetSpeed(&cpuOld, &busOld);				
	sctrlHENSetSpeed(333, 166);	
	
	pspSdkSetK1(k1);
}

#define ALL_ALLOW    (PSP_CTRL_UP|PSP_CTRL_RIGHT|PSP_CTRL_DOWN|PSP_CTRL_LEFT)
#define ALL_BUTTON   (PSP_CTRL_TRIANGLE|PSP_CTRL_CIRCLE|PSP_CTRL_CROSS|PSP_CTRL_SQUARE)
#define ALL_TRIGGER  (PSP_CTRL_LTRIGGER|PSP_CTRL_RTRIGGER)
#define ALL_FUNCTION (PSP_CTRL_SELECT|PSP_CTRL_START|PSP_CTRL_HOME|PSP_CTRL_HOLD|PSP_CTRL_NOTE)
#define ALL_CTRL  (ALL_ALLOW|ALL_BUTTON|ALL_TRIGGER|ALL_FUNCTION)

//OK
void zeroCtrlReadButtons(SceSize args UNUSED, void *argp UNUSED) {
	SceCtrlLatch data;	
	
	while(1) {		
		sceCtrlReadLatch(&data);
	
		if(zeroCtrlGetSlideState() == ZERO_SLIDE_STOPPED) {
			if((data.uiMake & ALL_CTRL) == slideStartBtn) {     
				zeroCtrlWriteDebug("Starting slide\n\n");		
				
				zeroCtrlSetSlideState(ZERO_SLIDE_STARTING); 								
			}
		} else if(zeroCtrlGetSlideState() == ZERO_SLIDE_STARTED) {
			if((data.uiMake & ALL_CTRL) == slideStopBtn) {         		
				zeroCtrlWriteDebug("Stopping slide\n\n");			
				
				zeroCtrlSetSlideState(ZERO_SLIDE_STOPPING);			
				
				if(b_level != -1) {
					sceDisplaySetBrightness(brightness, 0);
				}
				
				zeroCtrlRestoreLEDState();
				
				if((cpuOld != -1) && (busOld != -1)) {
					sceKernelDelayThread(1000000);
					sctrlHENSetSpeed(cpuOld, busOld);
				}
			}
		}
		
		if((zeroCtrlGetSlideState() == ZERO_SLIDE_STARTING) || (zeroCtrlGetSlideState() == ZERO_SLIDE_STARTED)) {
			sceKernelPowerTick(6);
		}
		
		sceKernelDelayThread(10000);
	}        
}
//OK
void zeroCtrlCreateBtnThread(void) {	
	SceUID thid;
	
	thid = sceKernelCreateThread("zeroctrl_btn", (void *)zeroCtrlReadButtons, 0x10, 0x10000, 0, NULL);
	
	if(thid >= 0) {
		if (sceKernelStartThread(thid, 0, NULL) < 0) {
			sceKernelDeleteThread(thid);
		}
	} else {
		//zeroCtrlWriteDebug("Thread ID: 0x%08X\n", thid);	
	}	
}
//OK
int module_start(SceSize args UNUSED, void *argp UNUSED) {
	unsigned int startup_total;
	unsigned int startup_largest;
	int module_hooked;
	int driver_hooked;
	unsigned int devkit;
	char legacySelective58D4[16];

	model = sceKernelGetModel();
	devkit = sceKernelDevkitVersion();
	startup_total = sceKernelPartitionTotalFreeMemSize(
			PSP_MEMORY_PARTITION_USER);
	startup_largest = sceKernelPartitionMaxFreeMemSize(
			PSP_MEMORY_PARTITION_USER);

	zeroCtrlWriteDebug("ZeroVSH Patcher v0.4\n");
	zeroCtrlWriteDebug("Copyright 2011-2015 (C) NightStar3 and codestation\n");
	zeroCtrlWriteDebug("[--- Full version ---]\n\n");

	zeroCtrlResolveNids();

	const char *config = (model == 4) ? "ef0:/seplugins/zerovsh.ini" : "ms0:/seplugins/zerovsh.ini";

	ini_gets("General", "RedirPath", "/PSP/VSH", redir_path, sizeof(redir_path), config);
	
	ini_gets("SlidePlugin", "ClockAndCalendar", "Disabled", useSlide, sizeof(useSlide), config);	
	slideStartBtn = ini_getlhex("SlidePlugin", "StartBtn", PSP_CTRL_HOME, config);
	slideStopBtn = ini_getlhex("SlidePlugin", "StopBtn", PSP_CTRL_HOME, config);
	ini_gets("SlidePlugin", "Contrast", "Disabled", slideContrast, sizeof(slideContrast), config);
	ini_gets("PowerSave", "LED", "Disabled", ledDisable, sizeof(ledDisable), config);
	b_level = ini_getl("PowerSave", "Brightness", -1, config);
	ini_gets("Experimental", "PSP1000SlidePlugin", "Disabled",
			psp1000SlidePlugin, sizeof(psp1000SlidePlugin), config);
	ini_gets("Experimental", "PSP1000SlideTriggerMode", "Disabled",
			psp1000SlideTriggerMode, sizeof(psp1000SlideTriggerMode), config);
	ini_gets("Experimental", "PSP1000Diagnostics", "Disabled",
			psp1000Diagnostics, sizeof(psp1000Diagnostics), config);
	ini_gets("Experimental", "PSP1000SonyStartTrace", "Disabled",
			psp1000SonyStartTrace, sizeof(psp1000SonyStartTrace), config);
	ini_gets("Experimental", "PSP1000BSManClosedShim", "Disabled",
			psp1000BSManClosedShim, sizeof(psp1000BSManClosedShim), config);
	ini_gets("Experimental", "PSP1000SelectiveSlideTrigger58D4", "Disabled",
			legacySelective58D4, sizeof(legacySelective58D4), config);
	if (strcmp(psp1000SlideTriggerMode, "Disabled") == 0 &&
			strcmp(legacySelective58D4, "Enabled") == 0)
		strcpy(psp1000SlideTriggerMode, "DangerousCaller58D4");
	if (model == 0 && strcmp(psp1000SlidePlugin, "Enabled") == 0 &&
			strcmp(useSlide, "Disabled") == 0) {
		memset(&slide_diag, 0, sizeof(slide_diag));
		slide_diag.armed = 1;
		slide_diag.global_predicate_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000SlideTriggerMode,
				"DangerousGlobalPredicate6F84") == 0;
		slide_diag.trigger_mode =
			devkit == 0x06060110 &&
			!slide_diag.global_predicate_enabled ?
			zeroCtrlParseTriggerMode(psp1000SlideTriggerMode) :
			ZERO_TRIGGER_DISABLED;
		slide_diag.sony_start_trace.enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000SonyStartTrace, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0;
		slide_diag.bsman.enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000BSManClosedShim, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0;
	}

	zeroCtrlDiagnosticsInit(strcmp(psp1000Diagnostics, "Enabled") == 0,
			model, devkit, useSlide, redir_path,
			startup_total, startup_largest);
	if (slide_diag.armed && strcmp(psp1000Diagnostics, "Enabled") == 0) {
		zeroCtrlDiagnosticsText("[phase] psp1000_slide_phase3\n"
				"[experiment] psp1000_slide_optin=enabled\n"
				"[experiment] clock_and_calendar=disabled\n"
				"[experiment] vsh_reference_scan=read_only\n"
				"[experiment] vsh_direct_windows=predicate_6f84_only\n"
				"[experiment] vsh_state_import_resolution=read_only\n"
				"[experiment] button_thread=disabled\n");
		if (slide_diag.global_predicate_enabled) {
			zeroCtrlDiagnosticsText(
					"[experiment] global_predicate_6f84_patch=enabled_dangerous\n"
					"[experiment] psp1000_vsh_slide_trigger="
					"DangerousGlobalPredicate6F84\n");
		} else if (slide_diag.trigger_mode != ZERO_TRIGGER_DISABLED) {
			char line[96];
			zeroCtrlDiagnosticsText(
					"[experiment] global_predicate_6f84_patch=disabled\n");
			snprintf(line, sizeof(line),
					"[experiment] psp1000_vsh_slide_trigger=%s mask=0x%X\n",
					psp1000SlideTriggerMode, slide_diag.trigger_mode);
			zeroCtrlDiagnosticsText(line);
		} else {
			zeroCtrlDiagnosticsText(
					"[experiment] global_predicate_6f84_patch=disabled\n"
					"[experiment] psp1000_vsh_slide_trigger=disabled_control\n");
		}
		if (slide_diag.sony_start_trace.enabled)
			zeroCtrlDiagnosticsText(
					"[experiment] psp1000_sony_start_trace=enabled_natural\n");
		if (slide_diag.bsman.enabled)
			zeroCtrlDiagnosticsText(
					"[experiment] psp1000_bsman_closed_shim=enabled_unverified\n");
	}
	zeroCtrlDiagnosticsMemory("after_nid_resolution_and_config");
	
	//zeroCtrlWriteDebug("using [%s] as RedirPath\n", redir_path); 
	//zeroCtrlWriteDebug("using [%s] as SlidePlugin\n", useSlide); 

	module_hooked = zeroCtrlHookModule();
	zeroCtrlDiagnosticsEvent("module_hook", module_hooked);
	driver_hooked = zeroCtrlHookDriver();
	zeroCtrlDiagnosticsEvent("driver_hook", driver_hooked);
	zeroCtrlDiagnosticsMemory("after_driver_and_module_hooks");
    
	zeroCtrlSetSlideState(ZERO_SLIDE_STOPPED);
			
	//Cool animation after reset vsh with no wallpaper enabled
	if (!slide_diag.sony_start_trace.enabled)
		set_registry_value("/CONFIG/SYSTEM", "slide_welcome", 1);
	
	if (slide_diag.armed && strcmp(psp1000Diagnostics, "Enabled") == 0) {
		zeroCtrlDiagnosticsEvent("slide_diagnostic_thread_start",
				zeroCtrlCreateSlideDiagnosticsThread());
	}
	zeroCtrlCreatePatchThread();
	zeroCtrlDiagnosticsMemory("kernel_initialization_complete");
	
	if((model != 4) && (model != 0) && (sceKernelDevkitVersion() >= 0x06000010)) {
	    if(strcmp(useSlide, "Enabled") == 0) {					
		zeroCtrlCreateBtnThread();
		previous = sctrlHENSetStartModuleHandler(OnModuleStart);    
	    }
    }

	if (slide_diag.armed) {
		/* Observation only: no button, power, clock, or Sony-module hooks. */
		previous = sctrlHENSetStartModuleHandler(OnModuleStart);
	}
    
    return 0;
}
//OK
int module_stop(SceSize args UNUSED, void *argp UNUSED) {
    return 0;
}
