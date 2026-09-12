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
static char psp1000ActivationTrace[16];
static char psp1000PafPresentCompat[16];
static char psp1000BSManNotLinkedCompat[16];
static char psp1000Consumer14020Compat[16];
static char psp1000Consumer13F6CCompat[16];
static char psp1000PafCapabilityMaskCompat[16];
static char psp1000StateZero15To14Compat[16];
static char psp1000ImposeParam8000000DCompat[16];
static char psp1000PostImposeVCallTrace[16];
static char psp1000PostMinusOneVCall64Trace[16];
static char psp1000PostVCall64CollectionTrace[16];
static char psp1000CollectionPafFCF265D8Trace[16];
static char psp1000CollectionPaf9A285882Trace[16];
static char psp1000PostCollectionPafFCF265D8Trace[16];
static char psp1000MaskedPafC59FC3D0Trace[16];
static char psp1000MaskedPafC59FC3D0SecondTrace[16];
static char psp1000ActivationWideTrace[16];
static unsigned long slideStartBtn, slideStopBtn;
static long b_level;

#define VSH_CODE_CAPTURE_BEFORE 0x80
#define VSH_CODE_CAPTURE_AFTER  0x100
#define STATE_ZERO_VCALL_CODE_WORDS 10
#define VSH_CODE_CAPTURE_BYTES  (VSH_CODE_CAPTURE_BEFORE + VSH_CODE_CAPTURE_AFTER)
#define VSH_CODE_CAPTURE_WORDS  (VSH_CODE_CAPTURE_BYTES / sizeof(unsigned int))

#define T37_FAIL_LUI_SHAPE            0x001
#define T37_FAIL_CALL_OPCODE          0x002
#define T37_FAIL_CALL_TARGET          0x004
#define T37_FAIL_ARG_LOAD_WORD        0x008
#define T37_FAIL_DECISION_WORD        0x010
#define T37_FAIL_RA_DELAY_WORD        0x020
#define T37_FAIL_REPLACEMENT_OPCODE   0x040
#define T37_FAIL_REPLACEMENT_TARGET   0x080
#define T37_FAIL_HELPER_RANGE         0x100
#define T37_FAIL_PSEUDODIRECT_REGION  0x200
#define T37_FAIL_ARG_LOAD_TARGET      0x400
#define T37_FAIL_SEGMENT1_MISSING     0x800
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
    int activation_enabled, activation_validation, activation_install;
    int paf_compat_enabled;
    int bsman_not_linked_compat_enabled;
    int activation_cache_sync;
    unsigned int activation_addr, activation_original[2];
    unsigned int activation_replacement[2];
    unsigned int activation_leaf_addr, activation_leaf_size;
    unsigned int activation_resume_addr, activation_hits_addr;
    int activation_caller_ra_registered, activation_caller_ra_validation;
    unsigned int activation_caller_ra_addr[3];
    unsigned int call_leaf_addr, call_leaf_size, call_target_addr, call_hits_addr;
    unsigned int call_original, call_replacement;
    unsigned int trace_stage_addr, call_ra_addr;
    unsigned int return_leaf_addr, return_leaf_size;
    unsigned int prefix_result_leaf_addr, prefix_result_leaf_size;
    unsigned int prefix_result_zero_addr, prefix_result_nonzero_addr;
    unsigned int prefix_flag_leaf_addr, prefix_flag_leaf_size;
    unsigned int prefix_flag_zero_addr, prefix_flag_nonzero_addr;
    unsigned int prefix_mask_leaf_addr, prefix_mask_leaf_size;
    unsigned int prefix_mask_equal_addr, prefix_mask_unequal_addr;
    unsigned int prefix_mask_delay_value_addr, prefix_path_mask_addr;
    unsigned int prefix_counter_addr[6];
    unsigned int prefix_paf_call_leaf_addr, prefix_paf_call_leaf_size;
    unsigned int prefix_paf_return_leaf_addr, prefix_paf_return_leaf_size;
    unsigned int prefix_paf_target_addr, prefix_paf_ra_addr;
    unsigned int prefix_paf_compat_mode_addr;
    unsigned int prefix_paf_natural_result_addr;
    unsigned int prefix_paf_substitution_hits_addr;
    unsigned int prefix_paf_return_hits_addr;
    unsigned int prefix_original[8], prefix_replacement[4];
    unsigned int post_path_mask_addr, bsman_natural_result_addr;
    unsigned int bsman_compat_mode_addr, bsman_substitution_hits_addr;
    unsigned int bsman_effective_result_addr;
    unsigned int bsman_return_hits_addr;
    unsigned int post_bs_leaf_addr, post_bs_leaf_size;
    unsigned int post_bs_target_addr[2], post_bs_counter_addr[2];
    unsigned int post_state_leaf_addr, post_state_leaf_size;
    unsigned int post_state_target_addr[2], post_state_counter_addr[2];
    unsigned int post_state_delay_value_addr;
    unsigned int post_state_natural_value_addr;
    unsigned int post_paf_call_leaf_addr, post_paf_call_leaf_size;
    unsigned int post_paf_return_leaf_addr, post_paf_return_leaf_size;
    unsigned int post_paf_target_addr, post_paf_call_ra_addr[2];
    unsigned int post_paf_saved_ra_addr, post_paf_result_addr[2];
    unsigned int post_paf_return_counter_addr[2];
    unsigned int post_vsh_call_leaf_addr, post_vsh_call_leaf_size;
    unsigned int post_vsh_return_leaf_addr, post_vsh_return_leaf_size;
    unsigned int post_vsh_target_addr, post_vsh_saved_ra_addr;
    unsigned int post_vsh_natural_result_addr, post_vsh_return_hits_addr;
    unsigned int post_vsh_argument_addr, post_vsh_compat_mode_addr;
    unsigned int post_vsh_effective_result_addr, post_vsh_substitution_hits_addr;
    int post_vsh_compat_enabled;
    unsigned int post_impose_vcall_leaf_addr, post_impose_vcall_leaf_size;
    unsigned int post_impose_vcall_return_leaf_addr;
    unsigned int post_impose_vcall_return_leaf_size;
    unsigned int post_impose_vcall_target_addr, post_impose_vcall_saved_ra_addr;
    unsigned int post_impose_vcall_natural_result_addr;
    unsigned int post_impose_vcall_hits_addr, post_impose_vcall_return_hits_addr;
    int post_impose_vcall_enabled, post_impose_vcall_validation;
    int post_impose_vcall_install, post_impose_vcall_cache_sync;
    unsigned int post_impose_vcall_original[2], post_impose_vcall_replacement;
    unsigned int post_minus_one_vcall64_leaf_addr;
    unsigned int post_minus_one_vcall64_leaf_size;
    unsigned int post_minus_one_vcall64_return_leaf_addr;
    unsigned int post_minus_one_vcall64_return_leaf_size;
    unsigned int post_minus_one_vcall64_target_addr;
    unsigned int post_minus_one_vcall64_saved_ra_addr;
    unsigned int post_minus_one_vcall64_natural_result_addr;
    unsigned int post_minus_one_vcall64_hits_addr;
    unsigned int post_minus_one_vcall64_return_hits_addr;
    int post_minus_one_vcall64_enabled, post_minus_one_vcall64_validation;
    int post_minus_one_vcall64_install, post_minus_one_vcall64_cache_sync;
    unsigned int post_minus_one_vcall64_original[2];
    unsigned int post_minus_one_vcall64_replacement;
    unsigned int post_minus_one_vcall64_collection_enabled_addr;
    unsigned int post_minus_one_vcall64_count_snapshot_addr;
    unsigned int post_minus_one_vcall64_array_snapshot_addr;
    unsigned int post_minus_one_vcall64_array_read_hits_addr;
    int post_vcall64_collection_enabled;
    unsigned int collection_paf_fcf265d8_leaf_addr;
    unsigned int collection_paf_fcf265d8_leaf_size;
    unsigned int collection_paf_fcf265d8_last_item_addr;
    unsigned int collection_paf_fcf265d8_natural_result_addr;
    unsigned int collection_paf_fcf265d8_hits_addr;
    unsigned int collection_paf_fcf265d8_nonzero_hits_addr;
    int collection_paf_fcf265d8_enabled, collection_paf_fcf265d8_validation;
    int collection_paf_fcf265d8_install, collection_paf_fcf265d8_cache_sync;
    unsigned int collection_paf_fcf265d8_original[2];
    unsigned int collection_paf_fcf265d8_replacement;
    unsigned int collection_paf_9a285882_leaf_addr, collection_paf_9a285882_leaf_size;
    unsigned int collection_paf_9a285882_last_item_addr;
    unsigned int collection_paf_9a285882_natural_result_addr;
    unsigned int collection_paf_9a285882_hits_addr, collection_paf_9a285882_nonzero_hits_addr;
    unsigned int collection_paf_9a285882_zero_resume_target_addr;
    unsigned int collection_paf_9a285882_nonzero_target_addr;
    int collection_paf_9a285882_enabled, collection_paf_9a285882_validation;
    int collection_paf_9a285882_install, collection_paf_9a285882_cache_sync;
    unsigned int collection_paf_9a285882_original[2];
    unsigned int collection_paf_9a285882_replacement;
    unsigned int post_collection_paf_fcf265d8_leaf_addr;
    unsigned int post_collection_paf_fcf265d8_leaf_size;
    unsigned int post_collection_paf_fcf265d8_natural_result_addr;
    unsigned int post_collection_paf_fcf265d8_hits_addr;
    unsigned int post_collection_paf_fcf265d8_nonzero_hits_addr;
    unsigned int post_collection_paf_fcf265d8_zero_resume_target_addr;
    unsigned int post_collection_paf_fcf265d8_nonzero_target_addr;
    int post_collection_paf_fcf265d8_enabled, post_collection_paf_fcf265d8_validation;
    int post_collection_paf_fcf265d8_install, post_collection_paf_fcf265d8_cache_sync;
    unsigned int post_collection_paf_fcf265d8_original[5];
    unsigned int post_collection_paf_fcf265d8_replacement;
    unsigned int post_collection_paf_fcf265d8_guard_checked;
    unsigned int post_collection_paf_fcf265d8_fail_mask;
    unsigned int post_collection_paf_fcf265d8_decoded_call_target;
    unsigned int post_collection_paf_fcf265d8_expected_call_target;
    unsigned int post_collection_paf_fcf265d8_decoded_replacement_target;
    unsigned int post_collection_paf_fcf265d8_observed_arg_target;
    unsigned int post_collection_paf_fcf265d8_expected_arg_target;
    unsigned int masked_paf_c59fc3d0_leaf_addr, masked_paf_c59fc3d0_leaf_size;
    unsigned int masked_paf_c59fc3d0_decision_value_addr;
    unsigned int masked_paf_c59fc3d0_hits_addr, masked_paf_c59fc3d0_nonzero_hits_addr;
    unsigned int masked_paf_c59fc3d0_zero_resume_target_addr;
    unsigned int masked_paf_c59fc3d0_nonzero_target_addr;
    int masked_paf_c59fc3d0_enabled, masked_paf_c59fc3d0_validation;
    int masked_paf_c59fc3d0_install, masked_paf_c59fc3d0_cache_sync;
    unsigned int masked_paf_c59fc3d0_original[7];
    unsigned int masked_paf_c59fc3d0_replacement;
    unsigned int masked_paf_c59fc3d0_second_leaf_addr;
    unsigned int masked_paf_c59fc3d0_second_leaf_size;
    unsigned int masked_paf_c59fc3d0_second_decision_value_addr;
    unsigned int masked_paf_c59fc3d0_second_hits_addr;
    unsigned int masked_paf_c59fc3d0_second_nonzero_hits_addr;
    unsigned int masked_paf_c59fc3d0_second_zero_resume_target_addr;
    unsigned int masked_paf_c59fc3d0_second_nonzero_target_addr;
    int masked_paf_c59fc3d0_second_enabled, masked_paf_c59fc3d0_second_validation;
    int masked_paf_c59fc3d0_second_install, masked_paf_c59fc3d0_second_cache_sync;
    unsigned int masked_paf_c59fc3d0_second_original[8];
    unsigned int masked_paf_c59fc3d0_second_replacement;
    int activation_wide_enabled, activation_wide_validation;
    int activation_wide_install, activation_wide_cache_sync;
    unsigned int activation_wide_leaf_addr[11], activation_wide_leaf_size[11];
    unsigned int activation_wide_scalar_addr[54];
    unsigned int activation_wide_original[6], activation_wide_replacement[6];
    unsigned int activation_wide_pre_original, activation_wide_pre_replacement;
    unsigned int post_paf_entry_counter_addr[2], post_vsh_entry_hits_addr;
    unsigned int post_original[12], post_replacement[6];
    unsigned int state_zero_leaf_addr[8], state_zero_leaf_size[8];
    unsigned int state_zero_path_mask_addr, state_zero_value_addr[7];
    unsigned int state_zero_counter_addr[4], state_zero_target_addr[12];
    unsigned int state_zero_15to14_compat_mode_addr;
    unsigned int state_zero_15to14_effective_result_addr;
    unsigned int state_zero_15to14_substitution_hits_addr;
    int state_zero_15to14_compat_enabled;
    int field12c_write_validation, field12c_write_install;
    int field12c_write_cache_sync;
    unsigned int field12c_write_leaf_addr, field12c_write_leaf_size;
    unsigned int field12c_write_resume_addr, field12c_write_scalar_addr[5];
    int case14_validation, case14_install, case14_cache_sync;
    unsigned int case14_leaf_addr, case14_leaf_size;
    unsigned int case14_resume_addr, case14_scalar_addr[4];
    int dispatch_entry_validation, dispatch_entry_install;
    int dispatch_entry_cache_sync;
    unsigned int dispatch_entry_leaf_addr, dispatch_entry_leaf_size;
    unsigned int dispatch_entry_resume_addr, dispatch_entry_scalar_addr[5];
    int dispatch_entry_early_attempted, dispatch_entry_pre_slide_captured;
    unsigned int dispatch_entry_pre_slide[5];
    int consumer_validation[2], consumer_install[2], consumer_cache_sync[2];
    unsigned int consumer_leaf_addr[2], consumer_leaf_size[2];
    unsigned int consumer_target_addr, consumer_hits_addr[2], consumer_result_addr[2];
    unsigned int consumer_14020_compat_mode_addr;
    unsigned int consumer_14020_effective_result_addr;
    unsigned int consumer_14020_substitution_hits_addr;
    int consumer_14020_compat_enabled;
    unsigned int consumer_13f6c_compat_mode_addr;
    unsigned int consumer_13f6c_effective_result_addr;
    unsigned int consumer_13f6c_substitution_hits_addr;
    int consumer_13f6c_compat_enabled;
    int consumer_early_attempted, shared_global_early_valid;
    unsigned int shared_global_early_value;
    int consumer_pre_slide_captured, shared_global_pre_slide_valid;
    unsigned int consumer_pre_slide_hits[2], consumer_pre_slide_result[2];
    unsigned int consumer_14020_pre_slide_effective;
    unsigned int consumer_14020_pre_slide_substitutions;
    unsigned int consumer_13f6c_pre_slide_effective;
    unsigned int consumer_13f6c_pre_slide_substitutions;
    unsigned int shared_global_pre_slide_value;
    int consumer_guard_reason;
    unsigned int consumer_vsh_text, consumer_vsh_text_size;
    unsigned int consumer_vsh_nsegment, consumer_segment_count;
    unsigned int consumer_segment_addr[4], consumer_segment_size[4];
    unsigned int consumer_shared_global_addr;
    int consumer_predicate_validation, consumer_predicate_first_bad;
    unsigned int consumer_predicate_words[16];
    unsigned int consumer_predicate_actual, consumer_predicate_expected;
    unsigned int consumer_predicate_decoded_addr;
    unsigned int consumer_callsite_words[2][2], consumer_callsite_target[2];
    int consumer_leaf_range_valid[2], consumer_counter_range_valid[2];
    int consumer_target_scalar_range_valid;
    unsigned int capability_leaf_addr[3], capability_leaf_size[3];
    unsigned int capability_target_addr[3], capability_hits_addr[3];
    unsigned int capability_result_addr[3];
    unsigned int paf_mask_leaf_addr, paf_mask_leaf_size, paf_mask_target_addr;
    unsigned int paf_mask_hits_addr, paf_mask_natural_addr;
    unsigned int paf_mask_compat_mode_addr, paf_mask_effective_addr;
    unsigned int paf_mask_substitution_hits_addr;
    int paf_mask_compat_enabled;
    int capability_validation[4], capability_install[4], capability_cache_sync[4];
    unsigned int capability_original[4][2], capability_decoded_target[4];
    unsigned int capability_hits[3], capability_result[3];
    unsigned int paf_mask_hits, paf_mask_natural, paf_mask_effective;
    unsigned int paf_mask_substitutions;
    int capability_captured;
    unsigned int state_zero_original[14], state_zero_replacement[7];
} ZeroCtrlBSManEvidence;

enum zeroCtrlConsumerGuardReason {
    ZERO_CONSUMER_GUARD_NOT_ATTEMPTED = 0, ZERO_CONSUMER_GUARD_NONE,
    ZERO_CONSUMER_GUARD_MODEL_MISMATCH, ZERO_CONSUMER_GUARD_DEVKIT_MISMATCH,
    ZERO_CONSUMER_GUARD_VSH_NOT_FOUND, ZERO_CONSUMER_GUARD_HELPER_NOT_FOUND,
    ZERO_CONSUMER_GUARD_VSH_TEXT_SIZE_MISMATCH,
    ZERO_CONSUMER_GUARD_SHARED_GLOBAL_DECODE_INVALID,
    ZERO_CONSUMER_GUARD_SHARED_GLOBAL_SEGMENT_INVALID,
    ZERO_CONSUMER_GUARD_PREDICATE_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_SHARED_GLOBAL_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_TARGET_SCALAR_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_PREDICATE_FINGERPRINT_MISMATCH,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_HELPER_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_COUNTER_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_NOT_JAL,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_TARGET_MISMATCH,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_DELAY_MISMATCH,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_PSEUDODIRECT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_HELPER_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_COUNTER_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_NOT_JAL,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_TARGET_MISMATCH,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_DELAY_MISMATCH,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_PSEUDODIRECT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_RESULT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_RESULT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_COMPAT_MODE_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_EFFECTIVE_RESULT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_14020_SUBSTITUTION_HITS_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_COMPAT_MODE_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_EFFECTIVE_RESULT_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_CALLSITE_13F6C_SUBSTITUTION_HITS_RANGE_INVALID,
    ZERO_CONSUMER_GUARD_REPLACEMENT_TARGET_MISMATCH
};

static const char *zeroCtrlConsumerGuardReasonName(int reason) {
    static const char *names[] = {
        "NOT_ATTEMPTED", "NONE", "MODEL_MISMATCH", "DEVKIT_MISMATCH",
        "VSH_NOT_FOUND", "HELPER_NOT_FOUND", "VSH_TEXT_SIZE_MISMATCH",
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
        "REPLACEMENT_TARGET_MISMATCH"
    };
    if (reason < 0 || (unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "UNKNOWN";
    return names[reason];
}

static void zeroCtrlInstallDispatchEntryTrace(void);
static void zeroCtrlInstall6F84ConsumerTraces(void);
static void zeroCtrlInstallCapabilityMaskTraces(void);

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
    int state_zero_vcall_resolve_attempted;
    int state_zero_vcall_owner_found;
    int state_zero_vcall_text_valid;
    int state_zero_vcall_segment_valid;
    int state_zero_vcall_fingerprint_valid;
    int state_zero_vcall_resolve_reason;
    unsigned int state_zero_vcall_candidates_found;
    unsigned int state_zero_vcall_containing_candidates;
    unsigned int state_zero_vcall_target;
    char state_zero_vcall_module[28];
    unsigned int state_zero_vcall_text_addr;
    unsigned int state_zero_vcall_text_size;
    unsigned int state_zero_vcall_offset;
    unsigned int state_zero_vcall_segment_index;
    unsigned int state_zero_vcall_segment_addr;
    unsigned int state_zero_vcall_segment_size;
    unsigned int state_zero_vcall_code[STATE_ZERO_VCALL_CODE_WORDS];
    int topmenu_validation;
    int topmenu_failure_reason;
    unsigned int topmenu_global_slot;
    unsigned int topmenu_context;
    unsigned int topmenu_first[3];
    unsigned int topmenu_last[3];
    unsigned int topmenu_transition_count;
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

enum ZeroCtrlStateZeroVCallResolveReason {
    ZERO_VCALL_RESOLVE_NONE = 0,
    ZERO_VCALL_RESOLVE_NO_KNOWN_OWNER,
    ZERO_VCALL_RESOLVE_AMBIGUOUS_OWNER,
    ZERO_VCALL_RESOLVE_INVALID_CANDIDATE_POINTER,
    ZERO_VCALL_RESOLVE_SEGMENT_NOT_FOUND,
    ZERO_VCALL_RESOLVE_FINGERPRINT_RANGE_INVALID
};

static const char *state_zero_vcall_candidates[] = {
    "scePaf_Module",
    "sceVshCommonGui_Module",
    "vsh_module",
    "slide_plugin_module",
    "impose_plugin_module",
    "launcher_plugin_module"
};

enum ZeroCtrlTopMenuStateReason {
    ZERO_TOPMENU_NONE = 0,
    ZERO_TOPMENU_TARGET_MISMATCH,
    ZERO_TOPMENU_CODE_MISMATCH,
    ZERO_TOPMENU_SLOT_OUT_OF_SEGMENT,
    ZERO_TOPMENU_CONTEXT_OUT_OF_PARTITION
};

static int zeroCtrlRangeInSnapshot(const ZeroCtrlPartitionSnapshot *snapshot,
        unsigned int address, unsigned int size) {
    unsigned int i;
    if (!snapshot || size == 0) return 0;
    for (i = 0; i < ZEROCTRL_PARTITION_COUNT; i++) {
        const ZeroCtrlPartitionEntry *entry = &snapshot->entries[i];
        if (entry->valid && entry->memsize >= size &&
                address >= entry->startaddr &&
                address - entry->startaddr <= entry->memsize - size)
            return 1;
    }
    return 0;
}

static void zeroCtrlValidateTopMenuState(void) {
    unsigned int lui, load, upper, slot;
    SceModule2 *vsh;
    int displacement;
    unsigned int i;

    if (!slide_diag.state_zero_vcall_fingerprint_valid ||
            slide_diag.state_zero_vcall_offset != 0x1E2B0) {
        slide_diag.topmenu_failure_reason = ZERO_TOPMENU_TARGET_MISMATCH;
        return;
    }
    lui = slide_diag.state_zero_vcall_code[0];
    load = slide_diag.state_zero_vcall_code[1];
    if ((lui >> 26) != 0x0F || ((lui >> 16) & 0x1F) != 2 ||
            (load >> 26) != 0x23 || ((load >> 21) & 0x1F) != 2 ||
            ((load >> 16) & 0x1F) != 3 ||
            slide_diag.state_zero_vcall_code[2] != 0x90620150 ||
            slide_diag.state_zero_vcall_code[3] != 0x14400002 ||
            slide_diag.state_zero_vcall_code[4] != 0x2404000F ||
            slide_diag.state_zero_vcall_code[5] != 0x8C64012C ||
            slide_diag.state_zero_vcall_code[6] != 0x03E00008 ||
            slide_diag.state_zero_vcall_code[7] != 0x00801021) {
        slide_diag.topmenu_failure_reason = ZERO_TOPMENU_CODE_MISMATCH;
        return;
    }
    upper = (lui & 0xFFFF) << 16;
    displacement = (short)(load & 0xFFFF);
    slot = upper + (unsigned int)displacement;
    vsh = sceKernelFindModuleByName("vsh_module");
    if (!vsh || ((unsigned int)vsh & 3) != 0 ||
            (unsigned int)vsh < 0x88000000 ||
            (unsigned int)vsh >= 0x8C000000 ||
            vsh->text_addr != slide_diag.state_zero_vcall_text_addr ||
            vsh->text_size != slide_diag.state_zero_vcall_text_size ||
            vsh->nsegment == 0 || vsh->nsegment > 4) {
        slide_diag.topmenu_failure_reason =
                ZERO_TOPMENU_SLOT_OUT_OF_SEGMENT;
        return;
    }
    for (i = 0; i < vsh->nsegment; i++) {
        unsigned int start = vsh->segmentaddr[i];
        unsigned int size = vsh->segmentsize[i];
        if (size >= sizeof(unsigned int) && slot >= start &&
                slot - start <= size - sizeof(unsigned int)) {
            slide_diag.topmenu_global_slot = slot;
            slide_diag.topmenu_validation = 1;
            return;
        }
    }
    slide_diag.topmenu_failure_reason = ZERO_TOPMENU_SLOT_OUT_OF_SEGMENT;
}

static void zeroCtrlCaptureTopMenuState(void) {
    unsigned int context, values[3];
    if (!slide_diag.topmenu_validation) return;
    context = _lw(slide_diag.topmenu_global_slot);
    if ((context & 3) != 0 || !zeroCtrlRangeInSnapshot(
            &slide_diag.pre_start, context, 0x154)) {
        slide_diag.topmenu_failure_reason =
                ZERO_TOPMENU_CONTEXT_OUT_OF_PARTITION;
        slide_diag.topmenu_validation = 0;
        return;
    }
    values[0] = _lw(context + 0x128);
    values[1] = _lw(context + 0x12C);
    values[2] = _lb(context + 0x150) & 0xFF;
    if (slide_diag.topmenu_context == 0) {
        memcpy(slide_diag.topmenu_first, values, sizeof(values));
    } else if (slide_diag.topmenu_context != context ||
            memcmp(slide_diag.topmenu_last, values, sizeof(values)) != 0) {
        slide_diag.topmenu_transition_count++;
    }
    slide_diag.topmenu_context = context;
    memcpy(slide_diag.topmenu_last, values, sizeof(values));
}

static const char *zeroCtrlTopMenuReasonName(int reason) {
    static const char *names[] = {
        "NONE", "TARGET_MISMATCH", "CODE_MISMATCH", "SLOT_OUT_OF_SEGMENT",
        "CONTEXT_OUT_OF_PARTITION"
    };
    if (reason < 0 || (unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "UNKNOWN";
    return names[reason];
}

/*
 * T16 resolves the observed virtual target through LoadCore metadata.  The
 * fingerprint read is deliberately last: no target-derived address is read
 * until both the module text range and one reported segment contain it.
 */
static void zeroCtrlCaptureStateZeroVCallOwner(unsigned int target) {
    SceModule2 *owner = NULL;
    unsigned int bytes = sizeof(slide_diag.state_zero_vcall_code);
    unsigned int i, segment_index = 0;

    if (slide_diag.state_zero_vcall_resolve_attempted || target == 0) return;
    slide_diag.state_zero_vcall_resolve_attempted = 1;
    slide_diag.state_zero_vcall_target = target;

    for (i = 0; i < sizeof(state_zero_vcall_candidates) /
            sizeof(state_zero_vcall_candidates[0]); i++) {
        SceModule2 *candidate = sceKernelFindModuleByName(
                state_zero_vcall_candidates[i]);
        unsigned int candidate_addr = (unsigned int)candidate;
        if (!candidate) continue;
        slide_diag.state_zero_vcall_candidates_found++;
        /* SceModule2 metadata returned by LoadCore must be aligned KSEG0 RAM. */
        if ((candidate_addr & 3) != 0 || candidate_addr < 0x88000000 ||
                candidate_addr >= 0x8C000000) {
            slide_diag.state_zero_vcall_resolve_reason =
                    ZERO_VCALL_RESOLVE_INVALID_CANDIDATE_POINTER;
            return;
        }
        if (candidate->text_size >= sizeof(unsigned int) &&
                target >= candidate->text_addr &&
                target - candidate->text_addr <=
                        candidate->text_size - sizeof(unsigned int)) {
            owner = candidate;
            slide_diag.state_zero_vcall_containing_candidates++;
        }
    }
    if (slide_diag.state_zero_vcall_containing_candidates == 0) {
        slide_diag.state_zero_vcall_resolve_reason =
                ZERO_VCALL_RESOLVE_NO_KNOWN_OWNER;
        return;
    }
    if (slide_diag.state_zero_vcall_containing_candidates != 1) {
        slide_diag.state_zero_vcall_resolve_reason =
                ZERO_VCALL_RESOLVE_AMBIGUOUS_OWNER;
        return;
    }
    slide_diag.state_zero_vcall_owner_found = 1;
    slide_diag.state_zero_vcall_text_addr = owner->text_addr;
    slide_diag.state_zero_vcall_text_size = owner->text_size;
    slide_diag.state_zero_vcall_offset = target - owner->text_addr;
    memcpy(slide_diag.state_zero_vcall_module, owner->modname,
            sizeof(slide_diag.state_zero_vcall_module) - 1);
    slide_diag.state_zero_vcall_module[
            sizeof(slide_diag.state_zero_vcall_module) - 1] = '\0';
    if (owner->nsegment == 0 || owner->nsegment > 4) {
        slide_diag.state_zero_vcall_resolve_reason =
                ZERO_VCALL_RESOLVE_SEGMENT_NOT_FOUND;
        return;
    }
    slide_diag.state_zero_vcall_text_valid = 1;

    for (i = 0; i < owner->nsegment; i++) {
        unsigned int start = owner->segmentaddr[i];
        unsigned int size = owner->segmentsize[i];
        if (size >= sizeof(unsigned int) && target >= start &&
                target - start <= size - sizeof(unsigned int)) {
            segment_index = i;
            slide_diag.state_zero_vcall_segment_addr = start;
            slide_diag.state_zero_vcall_segment_size = size;
            slide_diag.state_zero_vcall_segment_valid = 1;
            break;
        }
    }
    if (!slide_diag.state_zero_vcall_segment_valid) {
        slide_diag.state_zero_vcall_resolve_reason =
                ZERO_VCALL_RESOLVE_SEGMENT_NOT_FOUND;
        return;
    }
    slide_diag.state_zero_vcall_segment_index = segment_index;
    if (owner->text_size < bytes ||
            target - owner->text_addr > owner->text_size - bytes ||
            slide_diag.state_zero_vcall_segment_size < bytes ||
            target - slide_diag.state_zero_vcall_segment_addr >
                    slide_diag.state_zero_vcall_segment_size - bytes) {
        slide_diag.state_zero_vcall_resolve_reason =
                ZERO_VCALL_RESOLVE_FINGERPRINT_RANGE_INVALID;
        return;
    }
    for (i = 0; i < STATE_ZERO_VCALL_CODE_WORDS; i++)
        slide_diag.state_zero_vcall_code[i] =
                _lw(target + i * sizeof(unsigned int));
    slide_diag.state_zero_vcall_fingerprint_valid = 1;
    slide_diag.state_zero_vcall_resolve_reason = ZERO_VCALL_RESOLVE_NONE;
    zeroCtrlValidateTopMenuState();
}

static const char *zeroCtrlStateZeroVCallReasonName(int reason) {
    static const char *names[] = {
        "NONE", "NO_KNOWN_OWNER", "AMBIGUOUS_OWNER",
        "INVALID_CANDIDATE_POINTER",
        "SEGMENT_NOT_FOUND", "FINGERPRINT_RANGE_INVALID"
    };
    if (reason < 0 || (unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "UNKNOWN";
    return names[reason];
}

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

static unsigned int zeroCtrlMipsBranchTarget(unsigned int pc,
        unsigned int instruction) {
    return pc + 4 + ((int)(short)(instruction & 0xFFFF) << 2);
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

static unsigned int zeroCtrlDecodeLuiSignedLowAddress(unsigned int lui,
        unsigned int low_instruction) {
    int displacement = (short)(low_instruction & 0xFFFF);
    return ((lui & 0xFFFF) << 16) + (unsigned int)displacement;
}

static void zeroCtrlDeriveVshSharedGlobal(unsigned int text_addr,
        unsigned int text_size, unsigned int target_offset) {
    unsigned int lui;
    unsigned int access;
    unsigned int base;

    slide_diag.vsh_shared_global_decode_valid = 0;
    if (target_offset > text_size || text_size - target_offset < 8) return;
    lui = _lw(text_addr + target_offset);
    access = _lw(text_addr + target_offset + 4);
    base = (lui >> 16) & 0x1F;
    if ((lui >> 26) != 0x0F || zeroCtrlVshGlobalAccessKind(access) != 1 ||
            ((access >> 21) & 0x1F) != base)
        return;

    slide_diag.vsh_shared_global_addr =
            zeroCtrlDecodeLuiSignedLowAddress(lui, access);
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

static int zeroCtrlRegistrationLeafValid(SceModule2 *helper,
        unsigned int start, unsigned int end) {
    return end > start && (start & 3) == 0 &&
            zeroCtrlVshModuleRangeValid(helper, start, end - start);
}

void zeroCtrlRegisterBSManClosedShim(
        const ZeroCtrlBSManClosedRegistration *registration) {
    SceModule2 *helper;
    ZeroCtrlBSManClosedRegistration copied;
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    int k1;
    unsigned int i;

    bsman->registration_called = 1;
    if ((!bsman->enabled && !bsman->activation_enabled) ||
            bsman->registered || !registration) return;
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
            !zeroCtrlVshModuleRangeValid(helper, copied.hit_count_addr, 4) ||
            copied.activation_leaf_end_addr <= copied.activation_leaf_addr ||
            copied.bsman_call_leaf_end_addr <= copied.bsman_call_leaf_addr ||
            !zeroCtrlVshModuleRangeValid(helper, copied.activation_leaf_addr,
                copied.activation_leaf_end_addr - copied.activation_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.activation_resume_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.activation_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.bsman_call_leaf_addr,
                copied.bsman_call_leaf_end_addr - copied.bsman_call_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.bsman_call_target_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.bsman_call_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.trace_stage_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.bsman_call_ra_addr, 4) ||
            copied.bsman_return_leaf_end_addr <= copied.bsman_return_leaf_addr ||
            !zeroCtrlVshModuleRangeValid(helper, copied.bsman_return_leaf_addr,
                copied.bsman_return_leaf_end_addr -
                    copied.bsman_return_leaf_addr) ||
            copied.prefix_result_leaf_end_addr <= copied.prefix_result_leaf_addr ||
            copied.prefix_flag_leaf_end_addr <= copied.prefix_flag_leaf_addr ||
            copied.prefix_mask_leaf_end_addr <= copied.prefix_mask_leaf_addr ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_result_leaf_addr,
                copied.prefix_result_leaf_end_addr - copied.prefix_result_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_flag_leaf_addr,
                copied.prefix_flag_leaf_end_addr - copied.prefix_flag_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_mask_leaf_addr,
                copied.prefix_mask_leaf_end_addr - copied.prefix_mask_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_result_zero_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_result_nonzero_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_flag_zero_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_flag_nonzero_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_mask_equal_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_mask_unequal_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_mask_delay_value_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_path_mask_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_result_zero_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_result_nonzero_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_flag_zero_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_flag_nonzero_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_mask_equal_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_mask_unequal_hits_addr, 4) ||
            copied.prefix_paf_call_leaf_end_addr <=
                copied.prefix_paf_call_leaf_addr ||
            copied.prefix_paf_return_leaf_end_addr <=
                copied.prefix_paf_return_leaf_addr ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_call_leaf_addr,
                copied.prefix_paf_call_leaf_end_addr -
                    copied.prefix_paf_call_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_return_leaf_addr,
                copied.prefix_paf_return_leaf_end_addr -
                    copied.prefix_paf_return_leaf_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_paf_target_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.prefix_paf_ra_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_compat_mode_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_natural_result_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_substitution_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.prefix_paf_return_hits_addr, 4))
        return;
    if (!zeroCtrlRegistrationLeafValid(helper, copied.post_bs_branch_leaf_addr,
                copied.post_bs_branch_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper,
                copied.post_state_branch_leaf_addr,
                copied.post_state_branch_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper, copied.post_paf_call_leaf_addr,
                copied.post_paf_call_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper,
                copied.post_paf_return_leaf_addr,
                copied.post_paf_return_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper, copied.post_vsh_call_leaf_addr,
                copied.post_vsh_call_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper,
                copied.post_vsh_return_leaf_addr,
                copied.post_vsh_return_leaf_end_addr)) return;
#define CHECK_POST_SCALAR(field) \
    if (!zeroCtrlVshModuleRangeValid(helper, copied.field, 4)) return
    CHECK_POST_SCALAR(post_path_mask_addr);
    CHECK_POST_SCALAR(bsman_natural_result_addr);
    CHECK_POST_SCALAR(bsman_compat_mode_addr);
    CHECK_POST_SCALAR(bsman_substitution_hits_addr);
    CHECK_POST_SCALAR(bsman_effective_result_addr);
    CHECK_POST_SCALAR(bsman_return_hits_addr);
    CHECK_POST_SCALAR(post_bs_zero_addr);
    CHECK_POST_SCALAR(post_bs_nonzero_addr);
    CHECK_POST_SCALAR(post_bs_zero_hits_addr);
    CHECK_POST_SCALAR(post_bs_nonzero_hits_addr);
    CHECK_POST_SCALAR(post_state_zero_addr);
    CHECK_POST_SCALAR(post_state_nonzero_addr);
    CHECK_POST_SCALAR(post_state_delay_value_addr);
    CHECK_POST_SCALAR(post_state_natural_value_addr);
    CHECK_POST_SCALAR(post_state_zero_hits_addr);
    CHECK_POST_SCALAR(post_state_nonzero_hits_addr);
    CHECK_POST_SCALAR(post_paf_target_addr);
    CHECK_POST_SCALAR(post_paf_call0_ra_addr);
    CHECK_POST_SCALAR(post_paf_call1_ra_addr);
    CHECK_POST_SCALAR(post_paf_saved_ra_addr);
    CHECK_POST_SCALAR(post_paf_result0_addr);
    CHECK_POST_SCALAR(post_paf_result1_addr);
    CHECK_POST_SCALAR(post_paf_return0_hits_addr);
    CHECK_POST_SCALAR(post_paf_return1_hits_addr);
    CHECK_POST_SCALAR(post_vsh_target_addr);
    CHECK_POST_SCALAR(post_vsh_saved_ra_addr);
    CHECK_POST_SCALAR(post_vsh_natural_result_addr);
    CHECK_POST_SCALAR(post_vsh_return_hits_addr);
    CHECK_POST_SCALAR(post_paf_entry0_hits_addr);
    CHECK_POST_SCALAR(post_paf_entry1_hits_addr);
    CHECK_POST_SCALAR(post_vsh_entry_hits_addr);
    CHECK_POST_SCALAR(post_vsh_argument_addr);
    CHECK_POST_SCALAR(post_vsh_compat_mode_addr);
    CHECK_POST_SCALAR(post_vsh_effective_result_addr);
    CHECK_POST_SCALAR(post_vsh_substitution_hits_addr);
    if (!zeroCtrlRegistrationLeafValid(helper, copied.post_impose_vcall_leaf_addr,
                copied.post_impose_vcall_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper,
                copied.post_impose_vcall_return_leaf_addr,
                copied.post_impose_vcall_return_leaf_end_addr)) return;
    CHECK_POST_SCALAR(post_impose_vcall_target_addr);
    CHECK_POST_SCALAR(post_impose_vcall_saved_ra_addr);
    CHECK_POST_SCALAR(post_impose_vcall_natural_result_addr);
    CHECK_POST_SCALAR(post_impose_vcall_hits_addr);
    CHECK_POST_SCALAR(post_impose_vcall_return_hits_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.post_minus_one_vcall64_leaf_addr,
                copied.post_minus_one_vcall64_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper,
                copied.post_minus_one_vcall64_return_leaf_addr,
                copied.post_minus_one_vcall64_return_leaf_end_addr)) return;
    CHECK_POST_SCALAR(post_minus_one_vcall64_target_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_saved_ra_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_natural_result_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_hits_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_return_hits_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_collection_enabled_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_count_snapshot_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_array_snapshot_addr);
    CHECK_POST_SCALAR(post_minus_one_vcall64_array_read_hits_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.collection_paf_fcf265d8_leaf_addr,
                copied.collection_paf_fcf265d8_leaf_end_addr)) return;
    CHECK_POST_SCALAR(collection_paf_fcf265d8_last_item_addr);
    CHECK_POST_SCALAR(collection_paf_fcf265d8_natural_result_addr);
    CHECK_POST_SCALAR(collection_paf_fcf265d8_hits_addr);
    CHECK_POST_SCALAR(collection_paf_fcf265d8_nonzero_hits_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.collection_paf_9a285882_leaf_addr,
                copied.collection_paf_9a285882_leaf_end_addr)) return;
    CHECK_POST_SCALAR(collection_paf_9a285882_last_item_addr);
    CHECK_POST_SCALAR(collection_paf_9a285882_natural_result_addr);
    CHECK_POST_SCALAR(collection_paf_9a285882_hits_addr);
    CHECK_POST_SCALAR(collection_paf_9a285882_nonzero_hits_addr);
    CHECK_POST_SCALAR(collection_paf_9a285882_zero_resume_target_addr);
    CHECK_POST_SCALAR(collection_paf_9a285882_nonzero_target_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.post_collection_paf_fcf265d8_leaf_addr,
                copied.post_collection_paf_fcf265d8_leaf_end_addr)) return;
    CHECK_POST_SCALAR(post_collection_paf_fcf265d8_natural_result_addr);
    CHECK_POST_SCALAR(post_collection_paf_fcf265d8_hits_addr);
    CHECK_POST_SCALAR(post_collection_paf_fcf265d8_nonzero_hits_addr);
    CHECK_POST_SCALAR(post_collection_paf_fcf265d8_zero_resume_target_addr);
    CHECK_POST_SCALAR(post_collection_paf_fcf265d8_nonzero_target_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.masked_paf_c59fc3d0_leaf_addr,
                copied.masked_paf_c59fc3d0_leaf_end_addr)) return;
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_decision_value_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_hits_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_nonzero_hits_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_zero_resume_target_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_nonzero_target_addr);
    if (!zeroCtrlRegistrationLeafValid(helper,
                copied.masked_paf_c59fc3d0_second_leaf_addr,
                copied.masked_paf_c59fc3d0_second_leaf_end_addr)) return;
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_second_decision_value_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_second_hits_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_second_nonzero_hits_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_second_zero_resume_target_addr);
    CHECK_POST_SCALAR(masked_paf_c59fc3d0_second_nonzero_target_addr);
#define CHECK_STATE_ZERO_LEAF(field) \
    if (!zeroCtrlRegistrationLeafValid(helper, copied.field##_addr, \
                copied.field##_end_addr)) return
    CHECK_STATE_ZERO_LEAF(state_zero_cmp_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_word_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_byte_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_vcall_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_vreturn_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_class15_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_class17_leaf);
    CHECK_STATE_ZERO_LEAF(state_zero_class18_leaf);
#undef CHECK_STATE_ZERO_LEAF
    CHECK_POST_SCALAR(state_zero_path_mask_addr);
    CHECK_POST_SCALAR(state_zero_cmp_left_addr);
    CHECK_POST_SCALAR(state_zero_cmp_right_addr);
    CHECK_POST_SCALAR(state_zero_word_value_addr);
    CHECK_POST_SCALAR(state_zero_byte_value_addr);
    CHECK_POST_SCALAR(state_zero_vcall_target_addr);
    CHECK_POST_SCALAR(state_zero_vcall_ra_addr);
    CHECK_POST_SCALAR(state_zero_vcall_result_addr);
    CHECK_POST_SCALAR(state_zero_entry_hits_addr);
    CHECK_POST_SCALAR(state_zero_vcall_hits_addr);
    CHECK_POST_SCALAR(state_zero_vreturn_hits_addr);
    CHECK_POST_SCALAR(state_zero_rejoin_hits_addr);
    CHECK_POST_SCALAR(state_zero_cmp_equal_addr);
    CHECK_POST_SCALAR(state_zero_cmp_unequal_addr);
    CHECK_POST_SCALAR(state_zero_word_zero_addr);
    CHECK_POST_SCALAR(state_zero_word_nonzero_addr);
    CHECK_POST_SCALAR(state_zero_byte_zero_addr);
    CHECK_POST_SCALAR(state_zero_byte_nonzero_addr);
    CHECK_POST_SCALAR(state_zero_class15_true_addr);
    CHECK_POST_SCALAR(state_zero_class15_false_addr);
    CHECK_POST_SCALAR(state_zero_class17_true_addr);
    CHECK_POST_SCALAR(state_zero_class17_false_addr);
    CHECK_POST_SCALAR(state_zero_class18_equal_addr);
    CHECK_POST_SCALAR(state_zero_class18_unequal_addr);
    if (!zeroCtrlRegistrationLeafValid(helper, copied.field12c_write_leaf_addr,
                copied.field12c_write_leaf_end_addr)) return;
    CHECK_POST_SCALAR(field12c_write_resume_addr);
    CHECK_POST_SCALAR(field12c_write_hits_addr);
    CHECK_POST_SCALAR(field12c_write_first_addr);
    CHECK_POST_SCALAR(field12c_write_last_addr);
    CHECK_POST_SCALAR(field12c_write_changes_addr);
    CHECK_POST_SCALAR(field12c_write_context_addr);
    if (!zeroCtrlRegistrationLeafValid(helper, copied.case14_leaf_addr,
                copied.case14_leaf_end_addr)) return;
    CHECK_POST_SCALAR(case14_resume_addr);
    CHECK_POST_SCALAR(case14_hits_addr);
    CHECK_POST_SCALAR(case14_first_ra_addr);
    CHECK_POST_SCALAR(case14_last_ra_addr);
    CHECK_POST_SCALAR(case14_ra_changes_addr);
    if (!zeroCtrlRegistrationLeafValid(helper, copied.dispatch_entry_leaf_addr,
                copied.dispatch_entry_leaf_end_addr)) return;
    CHECK_POST_SCALAR(dispatch_entry_resume_addr);
    CHECK_POST_SCALAR(dispatch_entry_hits_addr);
    CHECK_POST_SCALAR(dispatch_case14_hits_addr);
    CHECK_POST_SCALAR(dispatch_case14_first_ra_addr);
    CHECK_POST_SCALAR(dispatch_case14_last_ra_addr);
    CHECK_POST_SCALAR(dispatch_case14_ra_changes_addr);
    if (!zeroCtrlRegistrationLeafValid(helper, copied.consumer_13f6c_leaf_addr,
                copied.consumer_13f6c_leaf_end_addr) ||
            !zeroCtrlRegistrationLeafValid(helper, copied.consumer_14020_leaf_addr,
                copied.consumer_14020_leaf_end_addr)) return;
    CHECK_POST_SCALAR(consumer_6f84_target_addr);
    CHECK_POST_SCALAR(consumer_13f6c_hits_addr);
    CHECK_POST_SCALAR(consumer_14020_hits_addr);
    CHECK_POST_SCALAR(consumer_13f6c_result_addr);
    CHECK_POST_SCALAR(consumer_14020_result_addr);
    CHECK_POST_SCALAR(consumer_14020_compat_mode_addr);
    CHECK_POST_SCALAR(consumer_14020_effective_result_addr);
    CHECK_POST_SCALAR(consumer_14020_substitution_hits_addr);
    CHECK_POST_SCALAR(consumer_13f6c_compat_mode_addr);
    CHECK_POST_SCALAR(consumer_13f6c_effective_result_addr);
    CHECK_POST_SCALAR(consumer_13f6c_substitution_hits_addr);
    CHECK_POST_SCALAR(state_zero_15to14_compat_mode_addr);
    CHECK_POST_SCALAR(state_zero_15to14_effective_result_addr);
    CHECK_POST_SCALAR(state_zero_15to14_substitution_hits_addr);
    for (i = 0; i < 3; i++) {
        if (!zeroCtrlRegistrationLeafValid(helper, copied.capability_leaf_addr[i],
                    copied.capability_leaf_end_addr[i])) return;
        if (!zeroCtrlVshModuleRangeValid(helper, copied.capability_target_addr[i], 4) ||
                !zeroCtrlVshModuleRangeValid(helper, copied.capability_hits_addr[i], 4) ||
                !zeroCtrlVshModuleRangeValid(helper, copied.capability_result_addr[i], 4)) return;
    }
    if (!zeroCtrlRegistrationLeafValid(helper, copied.paf_mask_leaf_addr,
                copied.paf_mask_leaf_end_addr) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.paf_mask_target_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.paf_mask_hits_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.paf_mask_natural_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.paf_mask_compat_mode_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, copied.paf_mask_effective_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                copied.paf_mask_substitution_hits_addr, 4)) return;
#undef CHECK_POST_SCALAR
    bsman->leaf_addr = copied.leaf_addr;
    bsman->leaf_size = copied.leaf_end_addr - copied.leaf_addr;
    bsman->hit_count_addr = copied.hit_count_addr;
    bsman->activation_leaf_addr = copied.activation_leaf_addr;
    bsman->activation_leaf_size = copied.activation_leaf_end_addr - copied.activation_leaf_addr;
    bsman->activation_resume_addr = copied.activation_resume_addr;
    bsman->activation_hits_addr = copied.activation_hits_addr;
    bsman->call_leaf_addr = copied.bsman_call_leaf_addr;
    bsman->call_leaf_size = copied.bsman_call_leaf_end_addr - copied.bsman_call_leaf_addr;
    bsman->call_target_addr = copied.bsman_call_target_addr;
    bsman->call_hits_addr = copied.bsman_call_hits_addr;
    bsman->trace_stage_addr = copied.trace_stage_addr;
    bsman->call_ra_addr = copied.bsman_call_ra_addr;
    bsman->return_leaf_addr = copied.bsman_return_leaf_addr;
    bsman->return_leaf_size = copied.bsman_return_leaf_end_addr -
            copied.bsman_return_leaf_addr;
    bsman->prefix_result_leaf_addr = copied.prefix_result_leaf_addr;
    bsman->prefix_result_leaf_size = copied.prefix_result_leaf_end_addr -
            copied.prefix_result_leaf_addr;
    bsman->prefix_result_zero_addr = copied.prefix_result_zero_addr;
    bsman->prefix_result_nonzero_addr = copied.prefix_result_nonzero_addr;
    bsman->prefix_flag_leaf_addr = copied.prefix_flag_leaf_addr;
    bsman->prefix_flag_leaf_size = copied.prefix_flag_leaf_end_addr -
            copied.prefix_flag_leaf_addr;
    bsman->prefix_flag_zero_addr = copied.prefix_flag_zero_addr;
    bsman->prefix_flag_nonzero_addr = copied.prefix_flag_nonzero_addr;
    bsman->prefix_mask_leaf_addr = copied.prefix_mask_leaf_addr;
    bsman->prefix_mask_leaf_size = copied.prefix_mask_leaf_end_addr -
            copied.prefix_mask_leaf_addr;
    bsman->prefix_mask_equal_addr = copied.prefix_mask_equal_addr;
    bsman->prefix_mask_unequal_addr = copied.prefix_mask_unequal_addr;
    bsman->prefix_mask_delay_value_addr = copied.prefix_mask_delay_value_addr;
    bsman->prefix_path_mask_addr = copied.prefix_path_mask_addr;
    bsman->prefix_counter_addr[0] = copied.prefix_result_zero_hits_addr;
    bsman->prefix_counter_addr[1] = copied.prefix_result_nonzero_hits_addr;
    bsman->prefix_counter_addr[2] = copied.prefix_flag_zero_hits_addr;
    bsman->prefix_counter_addr[3] = copied.prefix_flag_nonzero_hits_addr;
    bsman->prefix_counter_addr[4] = copied.prefix_mask_equal_hits_addr;
    bsman->prefix_counter_addr[5] = copied.prefix_mask_unequal_hits_addr;
    bsman->prefix_paf_call_leaf_addr = copied.prefix_paf_call_leaf_addr;
    bsman->prefix_paf_call_leaf_size = copied.prefix_paf_call_leaf_end_addr -
            copied.prefix_paf_call_leaf_addr;
    bsman->prefix_paf_return_leaf_addr = copied.prefix_paf_return_leaf_addr;
    bsman->prefix_paf_return_leaf_size = copied.prefix_paf_return_leaf_end_addr -
            copied.prefix_paf_return_leaf_addr;
    bsman->prefix_paf_target_addr = copied.prefix_paf_target_addr;
    bsman->prefix_paf_ra_addr = copied.prefix_paf_ra_addr;
    bsman->prefix_paf_compat_mode_addr = copied.prefix_paf_compat_mode_addr;
    bsman->prefix_paf_natural_result_addr =
            copied.prefix_paf_natural_result_addr;
    bsman->prefix_paf_substitution_hits_addr =
            copied.prefix_paf_substitution_hits_addr;
    bsman->prefix_paf_return_hits_addr = copied.prefix_paf_return_hits_addr;
    bsman->post_path_mask_addr = copied.post_path_mask_addr;
    bsman->bsman_natural_result_addr = copied.bsman_natural_result_addr;
    bsman->bsman_compat_mode_addr = copied.bsman_compat_mode_addr;
    bsman->bsman_substitution_hits_addr = copied.bsman_substitution_hits_addr;
    bsman->bsman_effective_result_addr = copied.bsman_effective_result_addr;
    bsman->bsman_return_hits_addr = copied.bsman_return_hits_addr;
    bsman->post_bs_leaf_addr = copied.post_bs_branch_leaf_addr;
    bsman->post_bs_leaf_size = copied.post_bs_branch_leaf_end_addr -
            copied.post_bs_branch_leaf_addr;
    bsman->post_bs_target_addr[0] = copied.post_bs_zero_addr;
    bsman->post_bs_target_addr[1] = copied.post_bs_nonzero_addr;
    bsman->post_bs_counter_addr[0] = copied.post_bs_zero_hits_addr;
    bsman->post_bs_counter_addr[1] = copied.post_bs_nonzero_hits_addr;
    bsman->post_state_leaf_addr = copied.post_state_branch_leaf_addr;
    bsman->post_state_leaf_size = copied.post_state_branch_leaf_end_addr -
            copied.post_state_branch_leaf_addr;
    bsman->post_state_target_addr[0] = copied.post_state_zero_addr;
    bsman->post_state_target_addr[1] = copied.post_state_nonzero_addr;
    bsman->post_state_delay_value_addr = copied.post_state_delay_value_addr;
    bsman->post_state_natural_value_addr = copied.post_state_natural_value_addr;
    bsman->post_state_counter_addr[0] = copied.post_state_zero_hits_addr;
    bsman->post_state_counter_addr[1] = copied.post_state_nonzero_hits_addr;
    bsman->post_paf_call_leaf_addr = copied.post_paf_call_leaf_addr;
    bsman->post_paf_call_leaf_size = copied.post_paf_call_leaf_end_addr -
            copied.post_paf_call_leaf_addr;
    bsman->post_paf_return_leaf_addr = copied.post_paf_return_leaf_addr;
    bsman->post_paf_return_leaf_size = copied.post_paf_return_leaf_end_addr -
            copied.post_paf_return_leaf_addr;
    bsman->post_paf_target_addr = copied.post_paf_target_addr;
    bsman->post_paf_call_ra_addr[0] = copied.post_paf_call0_ra_addr;
    bsman->post_paf_call_ra_addr[1] = copied.post_paf_call1_ra_addr;
    bsman->post_paf_saved_ra_addr = copied.post_paf_saved_ra_addr;
    bsman->post_paf_result_addr[0] = copied.post_paf_result0_addr;
    bsman->post_paf_result_addr[1] = copied.post_paf_result1_addr;
    bsman->post_paf_return_counter_addr[0] = copied.post_paf_return0_hits_addr;
    bsman->post_paf_return_counter_addr[1] = copied.post_paf_return1_hits_addr;
    bsman->post_vsh_call_leaf_addr = copied.post_vsh_call_leaf_addr;
    bsman->post_vsh_call_leaf_size = copied.post_vsh_call_leaf_end_addr -
            copied.post_vsh_call_leaf_addr;
    bsman->post_vsh_return_leaf_addr = copied.post_vsh_return_leaf_addr;
    bsman->post_vsh_return_leaf_size = copied.post_vsh_return_leaf_end_addr -
            copied.post_vsh_return_leaf_addr;
    bsman->post_vsh_target_addr = copied.post_vsh_target_addr;
    bsman->post_vsh_saved_ra_addr = copied.post_vsh_saved_ra_addr;
    bsman->post_vsh_natural_result_addr = copied.post_vsh_natural_result_addr;
    bsman->post_vsh_return_hits_addr = copied.post_vsh_return_hits_addr;
    bsman->post_paf_entry_counter_addr[0] = copied.post_paf_entry0_hits_addr;
    bsman->post_paf_entry_counter_addr[1] = copied.post_paf_entry1_hits_addr;
    bsman->post_vsh_entry_hits_addr = copied.post_vsh_entry_hits_addr;
    bsman->post_vsh_argument_addr = copied.post_vsh_argument_addr;
    bsman->post_vsh_compat_mode_addr = copied.post_vsh_compat_mode_addr;
    bsman->post_vsh_effective_result_addr = copied.post_vsh_effective_result_addr;
    bsman->post_vsh_substitution_hits_addr = copied.post_vsh_substitution_hits_addr;
    bsman->post_impose_vcall_leaf_addr = copied.post_impose_vcall_leaf_addr;
    bsman->post_impose_vcall_leaf_size = copied.post_impose_vcall_leaf_end_addr -
            copied.post_impose_vcall_leaf_addr;
    bsman->post_impose_vcall_return_leaf_addr =
            copied.post_impose_vcall_return_leaf_addr;
    bsman->post_impose_vcall_return_leaf_size =
            copied.post_impose_vcall_return_leaf_end_addr -
            copied.post_impose_vcall_return_leaf_addr;
    bsman->post_impose_vcall_target_addr = copied.post_impose_vcall_target_addr;
    bsman->post_impose_vcall_saved_ra_addr = copied.post_impose_vcall_saved_ra_addr;
    bsman->post_impose_vcall_natural_result_addr =
            copied.post_impose_vcall_natural_result_addr;
    bsman->post_impose_vcall_hits_addr = copied.post_impose_vcall_hits_addr;
    bsman->post_impose_vcall_return_hits_addr =
            copied.post_impose_vcall_return_hits_addr;
    bsman->post_minus_one_vcall64_leaf_addr =
            copied.post_minus_one_vcall64_leaf_addr;
    bsman->post_minus_one_vcall64_leaf_size =
            copied.post_minus_one_vcall64_leaf_end_addr -
            copied.post_minus_one_vcall64_leaf_addr;
    bsman->post_minus_one_vcall64_return_leaf_addr =
            copied.post_minus_one_vcall64_return_leaf_addr;
    bsman->post_minus_one_vcall64_return_leaf_size =
            copied.post_minus_one_vcall64_return_leaf_end_addr -
            copied.post_minus_one_vcall64_return_leaf_addr;
    bsman->post_minus_one_vcall64_target_addr =
            copied.post_minus_one_vcall64_target_addr;
    bsman->post_minus_one_vcall64_saved_ra_addr =
            copied.post_minus_one_vcall64_saved_ra_addr;
    bsman->post_minus_one_vcall64_natural_result_addr =
            copied.post_minus_one_vcall64_natural_result_addr;
    bsman->post_minus_one_vcall64_hits_addr =
            copied.post_minus_one_vcall64_hits_addr;
    bsman->post_minus_one_vcall64_return_hits_addr =
            copied.post_minus_one_vcall64_return_hits_addr;
    bsman->post_minus_one_vcall64_collection_enabled_addr =
            copied.post_minus_one_vcall64_collection_enabled_addr;
    bsman->post_minus_one_vcall64_count_snapshot_addr =
            copied.post_minus_one_vcall64_count_snapshot_addr;
    bsman->post_minus_one_vcall64_array_snapshot_addr =
            copied.post_minus_one_vcall64_array_snapshot_addr;
    bsman->post_minus_one_vcall64_array_read_hits_addr =
            copied.post_minus_one_vcall64_array_read_hits_addr;
    bsman->collection_paf_fcf265d8_leaf_addr =
            copied.collection_paf_fcf265d8_leaf_addr;
    bsman->collection_paf_fcf265d8_leaf_size =
            copied.collection_paf_fcf265d8_leaf_end_addr -
            copied.collection_paf_fcf265d8_leaf_addr;
    bsman->collection_paf_fcf265d8_last_item_addr =
            copied.collection_paf_fcf265d8_last_item_addr;
    bsman->collection_paf_fcf265d8_natural_result_addr =
            copied.collection_paf_fcf265d8_natural_result_addr;
    bsman->collection_paf_fcf265d8_hits_addr =
            copied.collection_paf_fcf265d8_hits_addr;
    bsman->collection_paf_fcf265d8_nonzero_hits_addr =
            copied.collection_paf_fcf265d8_nonzero_hits_addr;
    bsman->collection_paf_9a285882_leaf_addr = copied.collection_paf_9a285882_leaf_addr;
    bsman->collection_paf_9a285882_leaf_size = copied.collection_paf_9a285882_leaf_end_addr - copied.collection_paf_9a285882_leaf_addr;
    bsman->collection_paf_9a285882_last_item_addr = copied.collection_paf_9a285882_last_item_addr;
    bsman->collection_paf_9a285882_natural_result_addr = copied.collection_paf_9a285882_natural_result_addr;
    bsman->collection_paf_9a285882_hits_addr = copied.collection_paf_9a285882_hits_addr;
    bsman->collection_paf_9a285882_nonzero_hits_addr = copied.collection_paf_9a285882_nonzero_hits_addr;
    bsman->collection_paf_9a285882_zero_resume_target_addr = copied.collection_paf_9a285882_zero_resume_target_addr;
    bsman->collection_paf_9a285882_nonzero_target_addr = copied.collection_paf_9a285882_nonzero_target_addr;
    bsman->post_collection_paf_fcf265d8_leaf_addr = copied.post_collection_paf_fcf265d8_leaf_addr;
    bsman->post_collection_paf_fcf265d8_leaf_size = copied.post_collection_paf_fcf265d8_leaf_end_addr - copied.post_collection_paf_fcf265d8_leaf_addr;
    bsman->post_collection_paf_fcf265d8_natural_result_addr = copied.post_collection_paf_fcf265d8_natural_result_addr;
    bsman->post_collection_paf_fcf265d8_hits_addr = copied.post_collection_paf_fcf265d8_hits_addr;
    bsman->post_collection_paf_fcf265d8_nonzero_hits_addr = copied.post_collection_paf_fcf265d8_nonzero_hits_addr;
    bsman->post_collection_paf_fcf265d8_zero_resume_target_addr = copied.post_collection_paf_fcf265d8_zero_resume_target_addr;
    bsman->post_collection_paf_fcf265d8_nonzero_target_addr = copied.post_collection_paf_fcf265d8_nonzero_target_addr;
    bsman->masked_paf_c59fc3d0_leaf_addr = copied.masked_paf_c59fc3d0_leaf_addr;
    bsman->masked_paf_c59fc3d0_leaf_size = copied.masked_paf_c59fc3d0_leaf_end_addr - copied.masked_paf_c59fc3d0_leaf_addr;
    bsman->masked_paf_c59fc3d0_decision_value_addr = copied.masked_paf_c59fc3d0_decision_value_addr;
    bsman->masked_paf_c59fc3d0_hits_addr = copied.masked_paf_c59fc3d0_hits_addr;
    bsman->masked_paf_c59fc3d0_nonzero_hits_addr = copied.masked_paf_c59fc3d0_nonzero_hits_addr;
    bsman->masked_paf_c59fc3d0_zero_resume_target_addr = copied.masked_paf_c59fc3d0_zero_resume_target_addr;
    bsman->masked_paf_c59fc3d0_nonzero_target_addr = copied.masked_paf_c59fc3d0_nonzero_target_addr;
    bsman->masked_paf_c59fc3d0_second_leaf_addr = copied.masked_paf_c59fc3d0_second_leaf_addr;
    bsman->masked_paf_c59fc3d0_second_leaf_size = copied.masked_paf_c59fc3d0_second_leaf_end_addr - copied.masked_paf_c59fc3d0_second_leaf_addr;
    bsman->masked_paf_c59fc3d0_second_decision_value_addr = copied.masked_paf_c59fc3d0_second_decision_value_addr;
    bsman->masked_paf_c59fc3d0_second_hits_addr = copied.masked_paf_c59fc3d0_second_hits_addr;
    bsman->masked_paf_c59fc3d0_second_nonzero_hits_addr = copied.masked_paf_c59fc3d0_second_nonzero_hits_addr;
    bsman->masked_paf_c59fc3d0_second_zero_resume_target_addr = copied.masked_paf_c59fc3d0_second_zero_resume_target_addr;
    bsman->masked_paf_c59fc3d0_second_nonzero_target_addr = copied.masked_paf_c59fc3d0_second_nonzero_target_addr;
#define COPY_STATE_ZERO_LEAF(index, field) do { \
    bsman->state_zero_leaf_addr[index] = copied.field##_addr; \
    bsman->state_zero_leaf_size[index] = copied.field##_end_addr - \
            copied.field##_addr; \
} while (0)
    COPY_STATE_ZERO_LEAF(0, state_zero_cmp_leaf);
    COPY_STATE_ZERO_LEAF(1, state_zero_word_leaf);
    COPY_STATE_ZERO_LEAF(2, state_zero_byte_leaf);
    COPY_STATE_ZERO_LEAF(3, state_zero_vcall_leaf);
    COPY_STATE_ZERO_LEAF(4, state_zero_vreturn_leaf);
    COPY_STATE_ZERO_LEAF(5, state_zero_class15_leaf);
    COPY_STATE_ZERO_LEAF(6, state_zero_class17_leaf);
    COPY_STATE_ZERO_LEAF(7, state_zero_class18_leaf);
#undef COPY_STATE_ZERO_LEAF
    bsman->state_zero_path_mask_addr = copied.state_zero_path_mask_addr;
    bsman->state_zero_value_addr[0] = copied.state_zero_cmp_left_addr;
    bsman->state_zero_value_addr[1] = copied.state_zero_cmp_right_addr;
    bsman->state_zero_value_addr[2] = copied.state_zero_word_value_addr;
    bsman->state_zero_value_addr[3] = copied.state_zero_byte_value_addr;
    bsman->state_zero_value_addr[4] = copied.state_zero_vcall_target_addr;
    bsman->state_zero_value_addr[5] = copied.state_zero_vcall_ra_addr;
    bsman->state_zero_value_addr[6] = copied.state_zero_vcall_result_addr;
    bsman->state_zero_counter_addr[0] = copied.state_zero_entry_hits_addr;
    bsman->state_zero_counter_addr[1] = copied.state_zero_vcall_hits_addr;
    bsman->state_zero_counter_addr[2] = copied.state_zero_vreturn_hits_addr;
    bsman->state_zero_counter_addr[3] = copied.state_zero_rejoin_hits_addr;
    bsman->state_zero_target_addr[0] = copied.state_zero_cmp_equal_addr;
    bsman->state_zero_target_addr[1] = copied.state_zero_cmp_unequal_addr;
    bsman->state_zero_target_addr[2] = copied.state_zero_word_zero_addr;
    bsman->state_zero_target_addr[3] = copied.state_zero_word_nonzero_addr;
    bsman->state_zero_target_addr[4] = copied.state_zero_byte_zero_addr;
    bsman->state_zero_target_addr[5] = copied.state_zero_byte_nonzero_addr;
    bsman->state_zero_target_addr[6] = copied.state_zero_class15_true_addr;
    bsman->state_zero_target_addr[7] = copied.state_zero_class15_false_addr;
    bsman->state_zero_target_addr[8] = copied.state_zero_class17_true_addr;
    bsman->state_zero_target_addr[9] = copied.state_zero_class17_false_addr;
    bsman->state_zero_target_addr[10] = copied.state_zero_class18_equal_addr;
    bsman->state_zero_target_addr[11] = copied.state_zero_class18_unequal_addr;
    bsman->field12c_write_leaf_addr = copied.field12c_write_leaf_addr;
    bsman->field12c_write_leaf_size = copied.field12c_write_leaf_end_addr -
            copied.field12c_write_leaf_addr;
    bsman->field12c_write_resume_addr = copied.field12c_write_resume_addr;
    bsman->field12c_write_scalar_addr[0] = copied.field12c_write_hits_addr;
    bsman->field12c_write_scalar_addr[1] = copied.field12c_write_first_addr;
    bsman->field12c_write_scalar_addr[2] = copied.field12c_write_last_addr;
    bsman->field12c_write_scalar_addr[3] = copied.field12c_write_changes_addr;
    bsman->field12c_write_scalar_addr[4] = copied.field12c_write_context_addr;
    bsman->case14_leaf_addr = copied.case14_leaf_addr;
    bsman->case14_leaf_size = copied.case14_leaf_end_addr - copied.case14_leaf_addr;
    bsman->case14_resume_addr = copied.case14_resume_addr;
    bsman->case14_scalar_addr[0] = copied.case14_hits_addr;
    bsman->case14_scalar_addr[1] = copied.case14_first_ra_addr;
    bsman->case14_scalar_addr[2] = copied.case14_last_ra_addr;
    bsman->case14_scalar_addr[3] = copied.case14_ra_changes_addr;
    bsman->dispatch_entry_leaf_addr = copied.dispatch_entry_leaf_addr;
    bsman->dispatch_entry_leaf_size = copied.dispatch_entry_leaf_end_addr -
            copied.dispatch_entry_leaf_addr;
    bsman->dispatch_entry_resume_addr = copied.dispatch_entry_resume_addr;
    bsman->dispatch_entry_scalar_addr[0] = copied.dispatch_entry_hits_addr;
    bsman->dispatch_entry_scalar_addr[1] = copied.dispatch_case14_hits_addr;
    bsman->dispatch_entry_scalar_addr[2] = copied.dispatch_case14_first_ra_addr;
    bsman->dispatch_entry_scalar_addr[3] = copied.dispatch_case14_last_ra_addr;
    bsman->dispatch_entry_scalar_addr[4] = copied.dispatch_case14_ra_changes_addr;
    bsman->consumer_leaf_addr[0] = copied.consumer_13f6c_leaf_addr;
    bsman->consumer_leaf_size[0] = copied.consumer_13f6c_leaf_end_addr -
            copied.consumer_13f6c_leaf_addr;
    bsman->consumer_leaf_addr[1] = copied.consumer_14020_leaf_addr;
    bsman->consumer_leaf_size[1] = copied.consumer_14020_leaf_end_addr -
            copied.consumer_14020_leaf_addr;
    bsman->consumer_target_addr = copied.consumer_6f84_target_addr;
    bsman->consumer_hits_addr[0] = copied.consumer_13f6c_hits_addr;
    bsman->consumer_hits_addr[1] = copied.consumer_14020_hits_addr;
    bsman->consumer_result_addr[0] = copied.consumer_13f6c_result_addr;
    bsman->consumer_result_addr[1] = copied.consumer_14020_result_addr;
    bsman->consumer_14020_compat_mode_addr = copied.consumer_14020_compat_mode_addr;
    bsman->consumer_14020_effective_result_addr =
            copied.consumer_14020_effective_result_addr;
    bsman->consumer_14020_substitution_hits_addr =
            copied.consumer_14020_substitution_hits_addr;
    bsman->consumer_13f6c_compat_mode_addr = copied.consumer_13f6c_compat_mode_addr;
    bsman->consumer_13f6c_effective_result_addr =
            copied.consumer_13f6c_effective_result_addr;
    bsman->consumer_13f6c_substitution_hits_addr =
            copied.consumer_13f6c_substitution_hits_addr;
    bsman->state_zero_15to14_compat_mode_addr =
            copied.state_zero_15to14_compat_mode_addr;
    bsman->state_zero_15to14_effective_result_addr =
            copied.state_zero_15to14_effective_result_addr;
    bsman->state_zero_15to14_substitution_hits_addr =
            copied.state_zero_15to14_substitution_hits_addr;
    for (i = 0; i < 3; i++) {
        bsman->capability_leaf_addr[i] = copied.capability_leaf_addr[i];
        bsman->capability_leaf_size[i] = copied.capability_leaf_end_addr[i] -
                copied.capability_leaf_addr[i];
        bsman->capability_target_addr[i] = copied.capability_target_addr[i];
        bsman->capability_hits_addr[i] = copied.capability_hits_addr[i];
        bsman->capability_result_addr[i] = copied.capability_result_addr[i];
    }
    bsman->paf_mask_leaf_addr = copied.paf_mask_leaf_addr;
    bsman->paf_mask_leaf_size = copied.paf_mask_leaf_end_addr - copied.paf_mask_leaf_addr;
    bsman->paf_mask_target_addr = copied.paf_mask_target_addr;
    bsman->paf_mask_hits_addr = copied.paf_mask_hits_addr;
    bsman->paf_mask_natural_addr = copied.paf_mask_natural_addr;
    bsman->paf_mask_compat_mode_addr = copied.paf_mask_compat_mode_addr;
    bsman->paf_mask_effective_addr = copied.paf_mask_effective_addr;
    bsman->paf_mask_substitution_hits_addr = copied.paf_mask_substitution_hits_addr;
    bsman->registered = 1;
}

int zeroCtrlRegisterActivationWide(
        const ZeroCtrlActivationWideRegistration *registration) {
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    ZeroCtrlActivationWideRegistration copied;
    SceModule2 *helper;
    unsigned int wide_index;
    int k1;

    /* A NULL call is the user helper's cheap, pre-population gate query. */
    if (!registration) return bsman->activation_wide_enabled;
    if (!bsman->activation_wide_enabled || !bsman->registered) return 0;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!helper || !zeroCtrlVshModuleRangeValid(helper,
                (unsigned int)registration, sizeof(copied))) return 0;
    k1 = pspSdkSetK1(0);
    memcpy(&copied, registration, sizeof(copied));
    pspSdkSetK1(k1);
    for (wide_index = 0; wide_index < 11; wide_index++) {
        if (!zeroCtrlRegistrationLeafValid(helper, copied.leaf_addr[wide_index],
                    copied.leaf_end_addr[wide_index])) return 0;
    }
    for (wide_index = 0; wide_index < 54; wide_index++) {
        if (!zeroCtrlVshModuleRangeValid(helper,
                    copied.scalar_addr[wide_index], 4)) return 0;
    }
    for (wide_index = 0; wide_index < 11; wide_index++) {
        bsman->activation_wide_leaf_addr[wide_index] =
                copied.leaf_addr[wide_index];
        bsman->activation_wide_leaf_size[wide_index] =
                copied.leaf_end_addr[wide_index] - copied.leaf_addr[wide_index];
    }
    for (wide_index = 0; wide_index < 54; wide_index++)
        bsman->activation_wide_scalar_addr[wide_index] =
                copied.scalar_addr[wide_index];
    return 1;
}

void zeroCtrlRegisterActivationCallerRA(unsigned int first_addr,
        unsigned int last_addr, unsigned int changes_addr) {
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *helper;
    unsigned int address[3];
    unsigned int index;

    if (!bsman->activation_enabled || !bsman->registered ||
            bsman->activation_caller_ra_registered) return;
    helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    if (!helper || ((unsigned int)helper & 3) != 0 ||
            (unsigned int)helper < 0x88000000 ||
            (unsigned int)helper >= 0x8C000000 ||
            helper->text_addr == 0 || helper->text_size == 0 ||
            helper->nsegment == 0 || helper->nsegment > 4) return;
    address[0] = first_addr;
    address[1] = last_addr;
    address[2] = changes_addr;
    for (index = 0; index < 3; index++) {
        if ((address[index] & 3) != 0 ||
                !zeroCtrlVshModuleRangeValid(helper, address[index], 4)) return;
    }
    bsman->activation_caller_ra_validation = 1;
    for (index = 0; index < 3; index++) {
        bsman->activation_caller_ra_addr[index] = address[index];
        _sw(0, address[index]);
        sceKernelDcacheWritebackInvalidateRange((const void *)address[index], 4);
    }
    bsman->activation_caller_ra_registered = 1;
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
    slide_diag.bsman.dispatch_entry_early_attempted = 1;
    slide_diag.bsman.consumer_early_attempted = 1;
    zeroCtrlInstall6F84ConsumerTraces();
    zeroCtrlInstallCapabilityMaskTraces();
    zeroCtrlInstallDispatchEntryTrace();
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

static unsigned int zeroCtrlReadHelperCounter(unsigned int address) {
    if (!slide_diag.bsman.registered || !address) return 0;
    return *(volatile unsigned int *)address;
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
    unsigned int observed_activation_hits = 0, observed_bsman_call_hits = 0;
    unsigned int observed_trace_stage = 0, observed_prefix_mask = 0;
    unsigned int observed_prefix_counts[6] = { 0, 0, 0, 0, 0, 0 };
    unsigned int observed_paf_returns = 0;
    unsigned int observed_post_mask = 0;
    unsigned int observed_state_zero_mask = 0;
    unsigned int observed_topmenu_returns = 0;
    int observed_state_zero_vcall_owner = 0;
    unsigned int observed_post_counts[25] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    unsigned int observed_wide_early[18] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int observed_wide_early_status[4] = { -1, -1, -1, -1 };
    unsigned int observed_wide_02374143 = 0;
    unsigned int observed_prewide_early[9] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int observed_prewide_early_ready = 0;
    unsigned int observed_collection_early[14] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int observed_collection_early_ready = 0;
    int observed_collection_enabled = -1;
    unsigned int observed_post_early[22] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int observed_post_early_ready = 0;
    unsigned int observed_activation_caller_ra[4] = { 0, 0, 0, 0 };
    int observed_activation_caller_ra_ready = 0;
    unsigned int fast_poll_until = 0;
    int observed_bsman_attempted = 0;
    int observed_field12c_write_install_status = 0;
    int observed_case14_install_status = 0;
    int observed_dispatch_entry_install_status = 0;
    int observed_dispatch_entry_early_status = 0;
    int observed_dispatch_entry_pre_slide = 0;
    int observed_consumer_install = 0, observed_consumer_pre_slide = 0;
    char line[384];
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
        if (slide_diag.saw_rco_request != observed_rco_request) {
            observed_rco_request = slide_diag.saw_rco_request;
            zeroCtrlWriteLateTransition(elapsed, "rco_request",
                    (unsigned int)observed_rco_request);
            if (observed_rco_request)
                fast_poll_until = elapsed + 2000000;
        }
        WRITE_LATE_FLAG(slide_diag.saw_probe, observed_probe, "probe");
        WRITE_LATE_FLAG(slide_diag.saw_start, observed_start, "start");
        if (slide_diag.bsman.activation_enabled) {
            ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
            unsigned int caller_ra[4] = { 0, 0, 0, 0 };
            int caller_ra_changed = !observed_activation_caller_ra_ready;
            caller_ra[0] = bsman->activation_caller_ra_registered;
            if (caller_ra[0]) {
                caller_ra[1] = zeroCtrlReadHelperCounter(
                        bsman->activation_caller_ra_addr[0]);
                caller_ra[2] = zeroCtrlReadHelperCounter(
                        bsman->activation_caller_ra_addr[1]);
                caller_ra[3] = zeroCtrlReadHelperCounter(
                        bsman->activation_caller_ra_addr[2]);
            }
            for (i = 0; i < 4; i++)
                if (caller_ra[i] != observed_activation_caller_ra[i])
                    caller_ra_changed = 1;
            if (caller_ra_changed) {
                unsigned int which;
                snprintf(line, sizeof(line),
                        "[activation-caller-ra] registered=%u validation=%d "
                        "hits=%u first=0x%08X last=0x%08X changes=%u\n",
                        caller_ra[0], bsman->activation_caller_ra_validation,
                        zeroCtrlReadHelperCounter(bsman->activation_hits_addr),
                        caller_ra[1], caller_ra[2], caller_ra[3]);
                zeroCtrlDiagnosticsText(line);
                for (which = 0; which < 2; which++) {
                    unsigned int ra = caller_ra[which + 1];
                    SceModule2 *owner;
                    if (ra == 0) continue;
                    owner = sceKernelFindModuleByAddress(ra);
                    if (owner && (ra & 3) == 0 &&
                            ((unsigned int)owner & 3) == 0 &&
                            (unsigned int)owner >= 0x88000000 &&
                            (unsigned int)owner < 0x8C000000 &&
                            owner->text_addr != 0 && owner->text_size >= 8 &&
                            owner->nsegment != 0 && owner->nsegment <= 4 &&
                            ra >= owner->text_addr + 8 &&
                            ra <= owner->text_addr + owner->text_size) {
                        unsigned int callsite = ra - 8;
                        unsigned int word = _lw(callsite);
                        unsigned int delay = _lw(ra - 4);
                        unsigned int opcode = word >> 26;
                        unsigned int function = word & 0x3F;
                        unsigned int direct_target = opcode == 3 ?
                                zeroCtrlMipsJumpTarget(callsite, word) : 0;
                        snprintf(line, sizeof(line),
                                "[activation-caller-ra-resolve] which=%s "
                                "ra=0x%08X module=%.27s text=0x%08X size=0x%X "
                                "offset=0x%08X callsite=0x%08X word=0x%08X "
                                "delay=0x%08X opcode=0x%02X rs=%u rt=%u rd=%u "
                                "function=0x%02X class=%s target=0x%08X match=%d\n",
                                which == 0 ? "first" : "last", ra,
                                owner->modname, owner->text_addr, owner->text_size,
                                ra - owner->text_addr, callsite, word, delay,
                                opcode, (word >> 21) & 0x1F,
                                (word >> 16) & 0x1F, (word >> 11) & 0x1F,
                                function, opcode == 3 ? "JAL" :
                                    (opcode == 0 && function == 9 ? "JALR" : "OTHER"),
                                direct_target,
                                opcode == 3 && direct_target == bsman->activation_addr);
                        zeroCtrlDiagnosticsText(line);
                        if ((which == 0 || caller_ra[1] != caller_ra[2]) &&
                                strcmp(owner->modname, "scePaf_Module") == 0 &&
                                owner->text_size >= 0x124 &&
                                callsite >= owner->text_addr + 0xC0 &&
                                callsite - owner->text_addr <=
                                    owner->text_size - 0x64) {
                            unsigned int window_start = callsite - 0xC0;
                            unsigned int window_end = callsite + 0x60;
                            unsigned int group;
                            for (group = 0; group < 13; group++) {
                                unsigned int item;
                                unsigned int used = (unsigned int)snprintf(line,
                                        sizeof(line), "[paf-dispatch-window-%u]", group);
                                for (item = group * 6;
                                        item < group * 6 + 6 &&
                                        window_start + item * 4 <= window_end;
                                        item++) {
                                    unsigned int pc = window_start + item * 4;
                                    used += (unsigned int)snprintf(line + used,
                                            sizeof(line) - used, " %05X=0x%08X",
                                            pc - owner->text_addr, _lw(pc));
                                }
                                snprintf(line + used, sizeof(line) - used, "\n");
                                zeroCtrlDiagnosticsText(line);
                            }
                            for (i = 0; window_start + i * 4 <= window_end; i++) {
                                unsigned int pc = window_start + i * 4;
                                unsigned int instruction = _lw(pc);
                                unsigned int instruction_opcode = instruction >> 26;
                                unsigned int instruction_rs =
                                        (instruction >> 21) & 0x1F;
                                unsigned int instruction_rt =
                                        (instruction >> 16) & 0x1F;
                                unsigned int instruction_rd =
                                        (instruction >> 11) & 0x1F;
                                unsigned int instruction_function =
                                        instruction & 0x3F;
                                int direct_jump = instruction_opcode == 2 ||
                                        instruction_opcode == 3;
                                int regimm_branch = instruction_opcode == 1 &&
                                        (instruction_rt <= 3 ||
                                            (instruction_rt >= 16 &&
                                                instruction_rt <= 19));
                                int likely_branch =
                                        (instruction_opcode >= 20 &&
                                            instruction_opcode <= 23) ||
                                        (instruction_opcode == 1 &&
                                            (instruction_rt == 2 ||
                                                instruction_rt == 3 ||
                                                instruction_rt == 18 ||
                                                instruction_rt == 19));
                                int conditional_branch =
                                        regimm_branch ||
                                        (instruction_opcode >= 4 &&
                                            instruction_opcode <= 7) ||
                                        (instruction_opcode >= 20 &&
                                            instruction_opcode <= 23);
                                int register_jump = instruction_opcode == 0 &&
                                        (instruction_function == 8 ||
                                            instruction_function == 9);
                                int t0_immediate = instruction_rt == 8 &&
                                        (instruction_opcode == 9 ||
                                            instruction_opcode == 12 ||
                                            instruction_opcode == 13 ||
                                            instruction_opcode == 15 ||
                                            instruction_opcode == 35 ||
                                            instruction_opcode == 36 ||
                                            instruction_opcode == 37);
                                int t0_register = instruction_opcode == 0 &&
                                        instruction_rd == 8 &&
                                        (instruction_function == 0 ||
                                            instruction_function == 4 ||
                                            instruction_function == 33 ||
                                            instruction_function == 37);
                                if (direct_jump || conditional_branch ||
                                        register_jump) {
                                    unsigned int target = direct_jump ?
                                            zeroCtrlMipsJumpTarget(pc, instruction) :
                                            (conditional_branch ?
                                                zeroCtrlMipsBranchTarget(
                                                    pc, instruction) : 0);
                                    snprintf(line, sizeof(line),
                                            "[paf-dispatch-control] offset=0x%05X "
                                            "word=0x%08X opcode=0x%02X rs=%u "
                                            "rt=%u rd=%u function=0x%02X "
                                            "target=0x%08X likely=%d\n",
                                            pc - owner->text_addr, instruction,
                                            instruction_opcode, instruction_rs,
                                            instruction_rt, instruction_rd,
                                            instruction_function, target,
                                            likely_branch);
                                    zeroCtrlDiagnosticsText(line);
                                }
                                {
                                    unsigned int destination;
                                    int tracked_immediate =
                                            (instruction_rt == 9 ||
                                                instruction_rt == 16 ||
                                                instruction_rt == 17 ||
                                                instruction_rt == 18) &&
                                            (instruction_opcode == 9 ||
                                                instruction_opcode == 12 ||
                                                instruction_opcode == 13 ||
                                                instruction_opcode == 15 ||
                                                instruction_opcode == 35 ||
                                                instruction_opcode == 36 ||
                                                instruction_opcode == 37);
                                    int tracked_register = instruction_opcode == 0 &&
                                            (instruction_rd == 9 ||
                                                instruction_rd == 16 ||
                                                instruction_rd == 17 ||
                                                instruction_rd == 18) &&
                                            (instruction_function == 0 ||
                                                instruction_function == 4 ||
                                                instruction_function == 33 ||
                                                instruction_function == 37);
                                    if (tracked_immediate || tracked_register) {
                                        int load = instruction_opcode == 35 ||
                                                instruction_opcode == 36 ||
                                                instruction_opcode == 37;
                                        destination = tracked_immediate ?
                                                instruction_rt : instruction_rd;
                                        snprintf(line, sizeof(line),
                                                "[paf-dispatch-reg-def] "
                                                "offset=0x%05X word=0x%08X reg=%u "
                                                "opcode=0x%02X rs=%u rt=%u rd=%u "
                                                "function=0x%02X load=%d base=%u "
                                                "displacement=%d\n",
                                                pc - owner->text_addr, instruction,
                                                destination, instruction_opcode,
                                                instruction_rs, instruction_rt,
                                                instruction_rd,
                                                instruction_function, load,
                                                load ? instruction_rs : 0,
                                                load ? (short)(instruction & 0xFFFF) : 0);
                                        zeroCtrlDiagnosticsText(line);
                                    }
                                }
                                {
                                    int stack_adjust = instruction_opcode == 9 &&
                                            instruction_rs == 29 &&
                                            instruction_rt == 29;
                                    int ra_stack = (instruction_opcode == 35 ||
                                            instruction_opcode == 43) &&
                                            instruction_rs == 29 &&
                                            instruction_rt == 31;
                                    int return_jump = instruction_opcode == 0 &&
                                            instruction_function == 8 &&
                                            instruction_rs == 31;
                                    if (stack_adjust || ra_stack || return_jump) {
                                        snprintf(line, sizeof(line),
                                                "[paf-dispatch-frame-candidate] "
                                                "offset=0x%05X word=0x%08X "
                                                "opcode=0x%02X rs=%u rt=%u rd=%u "
                                                "function=0x%02X displacement=%d\n",
                                                pc - owner->text_addr, instruction,
                                                instruction_opcode, instruction_rs,
                                                instruction_rt, instruction_rd,
                                                instruction_function,
                                                (short)(instruction & 0xFFFF));
                                        zeroCtrlDiagnosticsText(line);
                                    }
                                }
                                if (t0_immediate || t0_register) {
                                    int load = instruction_opcode == 35 ||
                                            instruction_opcode == 36 ||
                                            instruction_opcode == 37;
                                    snprintf(line, sizeof(line),
                                            "[paf-jalr-t0-def] offset=0x%05X "
                                            "word=0x%08X opcode=0x%02X rs=%u "
                                            "rt=%u rd=%u function=0x%02X "
                                            "load=%d base=%u displacement=%d\n",
                                            pc - owner->text_addr, instruction,
                                            instruction_opcode, instruction_rs,
                                            instruction_rt, instruction_rd,
                                            instruction_function, load,
                                            load ? instruction_rs : 0,
                                            load ? (short)(instruction & 0xFFFF) : 0);
                                    zeroCtrlDiagnosticsText(line);
                                }
                            }
                            {
                                static const unsigned int fingerprint_offset[] = {
                                    0x00, 0x04, 0x08, 0x0C, 0x10, 0x14,
                                    0xA0, 0xA4,
                                    0xBC, 0xC0, 0xC4, 0xC8, 0xCC, 0xD0, 0xD4
                                };
                                static const unsigned int fingerprint_word[] = {
                                    0x27BDFFD0, 0xAFB00020, 0x2403FFFF,
                                    0xAFBF002C, 0xAFB20028, 0xAFB10024,
                                    0x0100F809, 0x8CE7002C,
                                    0x8FBF002C, 0x8FB20028, 0x8FB10024,
                                    0x8FB00020, 0x00601021, 0x03E00008,
                                    0x27BD0030
                                };
                                unsigned int dispatcher_start = callsite - 0xA0;
                                unsigned int dispatcher_offset =
                                        dispatcher_start - owner->text_addr;
                                unsigned int fingerprint_index;
                                unsigned int jal_matches = 0;
                                unsigned int jump_matches = 0;
                                unsigned int reported = 0;
                                int dispatcher_validation =
                                        dispatcher_start >= owner->text_addr &&
                                        dispatcher_offset <= owner->text_size - 0xD8;
                                for (fingerprint_index = 0;
                                        dispatcher_validation && fingerprint_index <
                                            sizeof(fingerprint_offset) /
                                                sizeof(fingerprint_offset[0]);
                                        fingerprint_index++) {
                                    unsigned int fingerprint_pc = dispatcher_start +
                                            fingerprint_offset[fingerprint_index];
                                    if (_lw(fingerprint_pc) !=
                                            fingerprint_word[fingerprint_index])
                                        dispatcher_validation = 0;
                                }
                                if (dispatcher_validation) {
                                    unsigned int scan_offset;
                                    for (scan_offset = 0;
                                            scan_offset <= owner->text_size - 4;
                                            scan_offset += 4) {
                                        unsigned int scan_pc =
                                                owner->text_addr + scan_offset;
                                        unsigned int scan_word = _lw(scan_pc);
                                        unsigned int scan_opcode = scan_word >> 26;
                                        if ((scan_opcode == 2 || scan_opcode == 3) &&
                                                zeroCtrlMipsJumpTarget(
                                                    scan_pc, scan_word) ==
                                                    dispatcher_start) {
                                            if (scan_opcode == 3) jal_matches++;
                                            else jump_matches++;
                                        }
                                    }
                                }
                                snprintf(line, sizeof(line),
                                        "[paf-dispatch-callers] validation=%d "
                                        "dispatcher=0x%08X offset=0x%08X "
                                        "jal_matches=%u jump_matches=%u "
                                        "loaded_words=%u truncated=%u\n",
                                        dispatcher_validation, dispatcher_start,
                                        dispatcher_offset, jal_matches, jump_matches,
                                        owner->text_size / 4,
                                        jal_matches + jump_matches > 8 ?
                                            jal_matches + jump_matches - 8 : 0);
                                zeroCtrlDiagnosticsText(line);
                                if (dispatcher_validation) {
                                    unsigned int scan_offset;
                                    for (scan_offset = 0;
                                            scan_offset <= owner->text_size - 4 &&
                                                reported < 8;
                                            scan_offset += 4) {
                                        unsigned int scan_pc =
                                                owner->text_addr + scan_offset;
                                        unsigned int scan_word = _lw(scan_pc);
                                        unsigned int scan_opcode = scan_word >> 26;
                                        if ((scan_opcode == 2 || scan_opcode == 3) &&
                                                zeroCtrlMipsJumpTarget(
                                                    scan_pc, scan_word) ==
                                                    dispatcher_start) {
                                            int delay_valid = scan_offset <=
                                                    owner->text_size - 8;
                                            unsigned int delay = delay_valid ?
                                                    _lw(scan_pc + 4) : 0;
                                            snprintf(line, sizeof(line),
                                                    "[paf-dispatch-caller] index=%u "
                                                    "type=%s offset=0x%08X "
                                                    "pc=0x%08X word=0x%08X "
                                                    "delay=0x%08X delay_valid=%d\n",
                                                    reported,
                                                    scan_opcode == 3 ? "JAL" : "J",
                                                    scan_offset, scan_pc, scan_word,
                                                    delay, delay_valid);
                                            zeroCtrlDiagnosticsText(line);
                                            reported++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                memcpy(observed_activation_caller_ra, caller_ra,
                        sizeof(caller_ra));
                observed_activation_caller_ra_ready = 1;
            }
        }
        if (slide_diag.bsman.activation_wide_enabled) {
            ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
            unsigned int current[18] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            int registered = bsman->activation_wide_scalar_addr[0] != 0;
            int changed = observed_wide_early_status[0] != registered ||
                    observed_wide_early_status[1] !=
                        bsman->activation_wide_validation ||
                    observed_wide_early_status[2] !=
                        bsman->activation_wide_install ||
                    observed_wide_early_status[3] !=
                        bsman->activation_wide_cache_sync;
            unsigned int pre02374143 = registered ? zeroCtrlReadHelperCounter(
                    bsman->activation_wide_scalar_addr[53]) : 0;
            static const unsigned int scalar_index[18] = {
                /* triplets: hits/zero/nonzero; loop is hits/back/exit. */
                0, 1, 2, 11, 15, 16, 20, 24, 25,
                29, 33, 34, 35, 36, 37, 46, 50, 51
            };
            if (registered) {
                for (i = 0; i < 18; i++) {
                    current[i] = zeroCtrlReadHelperCounter(
                            bsman->activation_wide_scalar_addr[scalar_index[i]]);
                    if (current[i] != observed_wide_early[i]) changed = 1;
                }
            }
            if (pre02374143 != observed_wide_02374143) changed = 1;
            if (changed) {
                snprintf(line, sizeof(line),
                        "[activation-wide-early] registered=%d validation=%d "
                        "install=%d cache_sync=%d compare=%u/%u/%u "
                        "662=%u/%u/%u 440=%u/%u/%u fcf=%u/%u/%u "
                        "loop=%u/%u/%u 090=%u/%u/%u pre02374143=%u\n",
                        registered, bsman->activation_wide_validation,
                        bsman->activation_wide_install,
                        bsman->activation_wide_cache_sync,
                        current[0], current[1], current[2],
                        current[3], current[4], current[5],
                        current[6], current[7], current[8],
                        current[9], current[10], current[11],
                        current[12], current[13], current[14],
                        current[15], current[16], current[17], pre02374143);
                zeroCtrlDiagnosticsText(line);
                memcpy(observed_wide_early, current, sizeof(current));
                observed_wide_early_status[0] = registered;
                observed_wide_early_status[1] =
                        bsman->activation_wide_validation;
                observed_wide_early_status[2] = bsman->activation_wide_install;
                observed_wide_early_status[3] =
                        bsman->activation_wide_cache_sync;
                observed_wide_02374143 = pre02374143;
            }
            if (bsman->registered) {
                unsigned int prewide[9];
                int prewide_changed = !observed_prewide_early_ready;
                prewide[0] = zeroCtrlReadHelperCounter(
                        bsman->post_collection_paf_fcf265d8_hits_addr);
                prewide[1] = zeroCtrlReadHelperCounter(
                        bsman->post_collection_paf_fcf265d8_nonzero_hits_addr);
                prewide[2] = zeroCtrlReadHelperCounter(
                        bsman->post_collection_paf_fcf265d8_natural_result_addr);
                prewide[3] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_hits_addr);
                prewide[4] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_nonzero_hits_addr);
                prewide[5] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_decision_value_addr);
                prewide[6] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_second_hits_addr);
                prewide[7] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_second_nonzero_hits_addr);
                prewide[8] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_second_decision_value_addr);
                for (i = 0; i < 9; i++)
                    if (prewide[i] != observed_prewide_early[i])
                        prewide_changed = 1;
                if (prewide_changed) {
                    snprintf(line, sizeof(line),
                            "[activation-prewide-early] "
                            "t37=%u/%u/0x%08X t38=%u/%u/0x%08X "
                            "t39=%u/%u/0x%08X\n",
                            prewide[0], prewide[1], prewide[2],
                            prewide[3], prewide[4], prewide[5],
                            prewide[6], prewide[7], prewide[8]);
                    zeroCtrlDiagnosticsText(line);
                    memcpy(observed_prewide_early, prewide, sizeof(prewide));
                    observed_prewide_early_ready = 1;
                }
                {
                    unsigned int collection[14];
                    int collection_changed = !observed_collection_early_ready ||
                            observed_collection_enabled !=
                                bsman->post_vcall64_collection_enabled;
                    collection[0] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_hits_addr);
                    collection[1] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_return_hits_addr);
                    collection[2] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_natural_result_addr);
                    collection[3] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_count_snapshot_addr);
                    collection[4] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_array_read_hits_addr);
                    collection[5] = zeroCtrlReadHelperCounter(
                            bsman->post_minus_one_vcall64_array_snapshot_addr);
                    collection[6] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_fcf265d8_hits_addr);
                    collection[7] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_fcf265d8_nonzero_hits_addr);
                    collection[8] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_fcf265d8_natural_result_addr);
                    collection[9] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_fcf265d8_last_item_addr);
                    collection[10] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_9a285882_hits_addr);
                    collection[11] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_9a285882_nonzero_hits_addr);
                    collection[12] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_9a285882_natural_result_addr);
                    collection[13] = zeroCtrlReadHelperCounter(
                            bsman->collection_paf_9a285882_last_item_addr);
                    for (i = 0; i < 14; i++)
                        if (collection[i] != observed_collection_early[i])
                            collection_changed = 1;
                    if (collection_changed) {
                        snprintf(line, sizeof(line),
                                "[activation-collection-early] enabled=%d "
                                "t33=%u/%u/0x%08X t34=%u/%u/0x%08X "
                                "t35=%u/%u/0x%08X/0x%08X "
                                "t36=%u/%u/0x%08X/0x%08X\n",
                                bsman->post_vcall64_collection_enabled,
                                collection[0], collection[1], collection[2],
                                collection[3], collection[4], collection[5],
                                collection[6], collection[7], collection[8],
                                collection[9], collection[10], collection[11],
                                collection[12], collection[13]);
                        zeroCtrlDiagnosticsText(line);
                        memcpy(observed_collection_early, collection,
                                sizeof(collection));
                        observed_collection_early_ready = 1;
                        observed_collection_enabled =
                                bsman->post_vcall64_collection_enabled;
                    }
                }
                {
                    unsigned int post[22];
                    int post_changed = !observed_post_early_ready;
                    post[0] = zeroCtrlReadHelperCounter(bsman->post_path_mask_addr);
                    post[1] = zeroCtrlReadHelperCounter(bsman->post_bs_counter_addr[0]);
                    post[2] = zeroCtrlReadHelperCounter(bsman->post_bs_counter_addr[1]);
                    post[3] = zeroCtrlReadHelperCounter(bsman->post_state_counter_addr[0]);
                    post[4] = zeroCtrlReadHelperCounter(bsman->post_state_counter_addr[1]);
                    post[5] = zeroCtrlReadHelperCounter(bsman->post_state_natural_value_addr);
                    post[6] = zeroCtrlReadHelperCounter(bsman->post_paf_entry_counter_addr[0]);
                    post[7] = zeroCtrlReadHelperCounter(bsman->post_paf_return_counter_addr[0]);
                    post[8] = zeroCtrlReadHelperCounter(bsman->post_paf_result_addr[0]);
                    post[9] = zeroCtrlReadHelperCounter(bsman->post_paf_entry_counter_addr[1]);
                    post[10] = zeroCtrlReadHelperCounter(bsman->post_paf_return_counter_addr[1]);
                    post[11] = zeroCtrlReadHelperCounter(bsman->post_paf_result_addr[1]);
                    post[12] = zeroCtrlReadHelperCounter(bsman->post_vsh_entry_hits_addr);
                    post[13] = zeroCtrlReadHelperCounter(bsman->post_vsh_return_hits_addr);
                    post[14] = zeroCtrlReadHelperCounter(bsman->post_vsh_argument_addr);
                    post[15] = zeroCtrlReadHelperCounter(bsman->post_vsh_natural_result_addr);
                    post[16] = zeroCtrlReadHelperCounter(bsman->post_vsh_effective_result_addr);
                    post[17] = zeroCtrlReadHelperCounter(bsman->post_vsh_substitution_hits_addr);
                    post[18] = zeroCtrlReadHelperCounter(bsman->post_impose_vcall_hits_addr);
                    post[19] = zeroCtrlReadHelperCounter(bsman->post_impose_vcall_return_hits_addr);
                    post[20] = zeroCtrlReadHelperCounter(bsman->post_impose_vcall_target_addr);
                    post[21] = zeroCtrlReadHelperCounter(bsman->post_impose_vcall_natural_result_addr);
                    for (i = 0; i < 22; i++)
                        if (post[i] != observed_post_early[i]) post_changed = 1;
                    if (post_changed) {
                        snprintf(line, sizeof(line),
                                "[activation-post-early] mask=0x%03X "
                                "bs=%u/%u state=%u/%u/0x%08X "
                                "paf0=%u/%u/0x%08X paf1=%u/%u/0x%08X\n",
                                post[0], post[1], post[2], post[3], post[4],
                                post[5], post[6], post[7], post[8], post[9],
                                post[10], post[11]);
                        zeroCtrlDiagnosticsText(line);
                        snprintf(line, sizeof(line),
                                "[activation-post-early-call] "
                                "vsh=%u/%u/arg:0x%08X/nat:0x%08X/"
                                "eff:0x%08X/sub:%u "
                                "t32=%u/%u/target:0x%08X/nat:0x%08X\n",
                                post[12], post[13], post[14], post[15],
                                post[16], post[17], post[18], post[19],
                                post[20], post[21]);
                        zeroCtrlDiagnosticsText(line);
                        memcpy(observed_post_early, post, sizeof(post));
                        observed_post_early_ready = 1;
                    }
                }
            }
        }
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
        if (slide_diag.bsman.enabled || slide_diag.bsman.activation_enabled) {
            ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
            unsigned int hits = zeroCtrlReadBSManHits();
            if (bsman->consumer_early_attempted && !observed_consumer_install) {
                snprintf(line, sizeof(line),
                        "[vsh-6f84-consumers-install] "
                        "consumer_13f6c_validation=%d consumer_13f6c_install=%d "
                        "consumer_13f6c_cache_sync=%d "
                        "consumer_14020_validation=%d consumer_14020_install=%d "
                        "consumer_14020_cache_sync=%d "
                        "shared_global_early_valid=%d shared_global_early=0x%08X\n",
                        bsman->consumer_validation[0], bsman->consumer_install[0],
                        bsman->consumer_cache_sync[0], bsman->consumer_validation[1],
                        bsman->consumer_install[1], bsman->consumer_cache_sync[1],
                        bsman->shared_global_early_valid,
                        bsman->shared_global_early_value);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[vsh-6f84-consumers-guard] reason=%s(%d) "
                        "decode_valid=%d segment_valid=%d shared_global_addr=0x%08X "
                        "vsh_text=0x%08X text_size=0x%X nsegment=%u\n",
                        zeroCtrlConsumerGuardReasonName(bsman->consumer_guard_reason),
                        bsman->consumer_guard_reason,
                        slide_diag.vsh_shared_global_decode_valid,
                        slide_diag.vsh_shared_global_segment_valid,
                        bsman->consumer_shared_global_addr, bsman->consumer_vsh_text,
                        bsman->consumer_vsh_text_size, bsman->consumer_vsh_nsegment);
                zeroCtrlDiagnosticsText(line);
                for (i = 0; i < bsman->consumer_segment_count && i < 4; i++) {
                    snprintf(line, sizeof(line),
                            "[vsh-6f84-segment] index=%u addr=0x%08X size=0x%X\n",
                            i, bsman->consumer_segment_addr[i],
                            bsman->consumer_segment_size[i]);
                    zeroCtrlDiagnosticsText(line);
                }
                for (i = 0; i < 2; i++) {
                    static const unsigned int offsets[2] = { 0x13F6C, 0x14020 };
                    snprintf(line, sizeof(line),
                            "[vsh-6f84-callsite] offset=0x%05X word=0x%08X "
                            "delay=0x%08X decoded_target=0x%08X\n", offsets[i],
                            bsman->consumer_callsite_words[i][0],
                            bsman->consumer_callsite_words[i][1],
                            bsman->consumer_callsite_target[i]);
                    zeroCtrlDiagnosticsText(line);
                }
                snprintf(line, sizeof(line),
                        "[vsh-6f84-predicate] validation=%d first_bad_index=%d "
                        "actual=0x%08X expected=0x%08X decoded=0x%08X\n",
                        bsman->consumer_predicate_validation,
                        bsman->consumer_predicate_first_bad,
                        bsman->consumer_predicate_actual,
                        bsman->consumer_predicate_expected,
                        bsman->consumer_predicate_decoded_addr);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[vsh-6f84-helper] target_scalar=%d leaf_13f6c=%d "
                        "counter_13f6c=%d leaf_14020=%d counter_14020=%d\n",
                        bsman->consumer_target_scalar_range_valid,
                        bsman->consumer_leaf_range_valid[0],
                        bsman->consumer_counter_range_valid[0],
                        bsman->consumer_leaf_range_valid[1],
                        bsman->consumer_counter_range_valid[1]);
                zeroCtrlDiagnosticsText(line);
                observed_consumer_install = 1;
            }
            if (bsman->consumer_pre_slide_captured &&
                    !observed_consumer_pre_slide) {
                snprintf(line, sizeof(line),
                        "[vsh-6f84-consumers-pre-slide] caller_13f6c_hits=%u "
                        "caller_14020_hits=%u shared_global_valid=%d "
                        "shared_global=0x%08X\n",
                        bsman->consumer_pre_slide_hits[0],
                        bsman->consumer_pre_slide_hits[1],
                        bsman->shared_global_pre_slide_valid,
                        bsman->shared_global_pre_slide_value);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[vsh-6f84-consumers-natural] caller_13f6c_hits=%u "
                        "caller_13f6c_result=0x%08X caller_14020_hits=%u "
                        "caller_14020_result=0x%08X\n",
                        bsman->consumer_pre_slide_hits[0],
                        bsman->consumer_pre_slide_result[0],
                        bsman->consumer_pre_slide_hits[1],
                        bsman->consumer_pre_slide_result[1]);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[vsh-6f84-13f6c-compat] enabled=%d hits=%u "
                        "natural=0x%08X effective=0x%08X substitutions=%u\n",
                        bsman->consumer_13f6c_compat_enabled,
                        bsman->consumer_pre_slide_hits[0],
                        bsman->consumer_pre_slide_result[0],
                        bsman->consumer_13f6c_pre_slide_effective,
                        bsman->consumer_13f6c_pre_slide_substitutions);
                zeroCtrlDiagnosticsText(line);
                snprintf(line, sizeof(line),
                        "[vsh-6f84-14020-compat] enabled=%d hits=%u "
                        "natural=0x%08X effective=0x%08X substitutions=%u\n",
                        bsman->consumer_14020_compat_enabled,
                        bsman->consumer_pre_slide_hits[1],
                        bsman->consumer_pre_slide_result[1],
                        bsman->consumer_14020_pre_slide_effective,
                        bsman->consumer_14020_pre_slide_substitutions);
                zeroCtrlDiagnosticsText(line);
                if (bsman->capability_captured) {
                    static const unsigned int offsets[3] = {
                        0x14014, 0x1402C, 0x14038 };
                    static const unsigned int targets[3] = {
                        0x6F44, 0x6FC4, 0x7004 };
                    unsigned int capability_index;
                    for (capability_index = 0; capability_index < 3;
                            capability_index++) {
                        snprintf(line, sizeof(line),
                                "[vsh-capability-predicate] offset=0x%05X "
                                "target=0x%04X validation=%d install=%d "
                                "cache_sync=%d hits=%u natural=0x%08X\n",
                                offsets[capability_index], targets[capability_index],
                                bsman->capability_validation[capability_index],
                                bsman->capability_install[capability_index],
                                bsman->capability_cache_sync[capability_index],
                                bsman->capability_hits[capability_index],
                                bsman->capability_result[capability_index]);
                        zeroCtrlDiagnosticsText(line);
                    }
                    snprintf(line, sizeof(line),
                            "[vsh-paf-capability-mask] validation=%d install=%d "
                            "cache_sync=%d enabled=%d hits=%u natural=0x%08X "
                            "effective=0x%08X substitutions=%u\n",
                            bsman->capability_validation[3],
                            bsman->capability_install[3],
                            bsman->capability_cache_sync[3],
                            bsman->paf_mask_compat_enabled, bsman->paf_mask_hits,
                            bsman->paf_mask_natural, bsman->paf_mask_effective,
                            bsman->paf_mask_substitutions);
                    zeroCtrlDiagnosticsText(line);
                }
                observed_consumer_pre_slide = 1;
            }
            if (bsman->dispatch_entry_early_attempted &&
                    !observed_dispatch_entry_early_status) {
                snprintf(line, sizeof(line),
                        "[topmenu-dispatch-entry-early-install] attempted=1 "
                        "validation=%d install=%d cache_sync=%d\n",
                        bsman->dispatch_entry_validation,
                        bsman->dispatch_entry_install,
                        bsman->dispatch_entry_cache_sync);
                zeroCtrlDiagnosticsText(line);
                observed_dispatch_entry_early_status = 1;
            }
            if (bsman->dispatch_entry_pre_slide_captured &&
                    !observed_dispatch_entry_pre_slide) {
                snprintf(line, sizeof(line),
                        "[topmenu-dispatch-entry-pre-slide] hits=%u "
                        "case14_requests=%u first_ra=0x%08X "
                        "last_ra=0x%08X ra_changes=%u\n",
                        bsman->dispatch_entry_pre_slide[0],
                        bsman->dispatch_entry_pre_slide[1],
                        bsman->dispatch_entry_pre_slide[2],
                        bsman->dispatch_entry_pre_slide[3],
                        bsman->dispatch_entry_pre_slide[4]);
                zeroCtrlDiagnosticsText(line);
                observed_dispatch_entry_pre_slide = 1;
            }
            if (bsman->attempted && !observed_field12c_write_install_status) {
                snprintf(line, sizeof(line),
                        "[topmenu-field12c-write-install] validation=%d "
                        "install=%d cache_sync=%d\n",
                        bsman->field12c_write_validation,
                        bsman->field12c_write_install,
                        bsman->field12c_write_cache_sync);
                zeroCtrlDiagnosticsText(line);
                observed_field12c_write_install_status = 1;
            }
            if (bsman->attempted && !observed_case14_install_status) {
                snprintf(line, sizeof(line),
                        "[topmenu-case14-install] validation=%d install=%d "
                        "cache_sync=%d\n", bsman->case14_validation,
                        bsman->case14_install, bsman->case14_cache_sync);
                zeroCtrlDiagnosticsText(line);
                observed_case14_install_status = 1;
            }
            if (bsman->attempted && !observed_dispatch_entry_install_status) {
                snprintf(line, sizeof(line),
                        "[topmenu-dispatch-entry-install] validation=%d "
                        "install=%d cache_sync=%d\n",
                        bsman->dispatch_entry_validation,
                        bsman->dispatch_entry_install,
                        bsman->dispatch_entry_cache_sync);
                zeroCtrlDiagnosticsText(line);
                observed_dispatch_entry_install_status = 1;
            }
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
                if (bsman->activation_enabled) {
                    snprintf(line, sizeof(line),
                            "[activation-trace] validation=%d install=%d "
                            "cache_sync=%d entry=0x%08X bsman_call=0x%08X\n",
                            bsman->activation_validation,
                            bsman->activation_install,
                            bsman->activation_cache_sync,
                            bsman->activation_addr, bsman->caller_addr);
                    zeroCtrlDiagnosticsText(line);
                    {
                        unsigned int word_f0 = _lw(
                                bsman->activation_addr + 0xF0);
                        unsigned int word_f4 = _lw(
                                bsman->activation_addr + 0xF4);
                        unsigned int opcode = word_f0 >> 26;
                        int conditional_branch = opcode == 1 || opcode == 4 ||
                                opcode == 5 || opcode == 6 || opcode == 7;
                        unsigned int branch_target = conditional_branch ?
                                zeroCtrlMipsBranchTarget(
                                    bsman->activation_addr + 0xF0, word_f0) : 0;
                        unsigned int target_offset = conditional_branch ?
                                branch_target - bsman->activation_addr : 0;
                        snprintf(line, sizeof(line),
                                "[post-paf0-gap] word_f0=0x%08X "
                                "word_f4=0x%08X opcode=0x%02X rs=%u rt=%u "
                                "conditional=%d branch_target=0x%08X "
                                "target_offset=0x%08X\n",
                                word_f0, word_f4, opcode,
                                (word_f0 >> 21) & 0x1F,
                                (word_f0 >> 16) & 0x1F,
                                conditional_branch, branch_target,
                                target_offset);
                        zeroCtrlDiagnosticsText(line);
                    }
                    {
                        static const unsigned int exit_offsets[18] = {
                            0x234, 0x238, 0x23C, 0x240, 0x244, 0x248,
                            0x24C, 0x250, 0x254, 0x258, 0x25C, 0x260,
                            0x264, 0x268, 0x26C, 0x270, 0x274, 0x278
                        };
                        unsigned int exit_words[18];
                        unsigned int exit_index;
                        for (exit_index = 0; exit_index < 18; exit_index++)
                            exit_words[exit_index] = _lw(bsman->activation_addr +
                                    exit_offsets[exit_index]);
                        for (exit_index = 0; exit_index < 3; exit_index++) {
                            unsigned int first = exit_index * 6;
                            snprintf(line, sizeof(line),
                                    "[t40-exit-window-%u] "
                                    "%03x=0x%08X %03x=0x%08X %03x=0x%08X "
                                    "%03x=0x%08X %03x=0x%08X %03x=0x%08X\n",
                                    exit_index,
                                    exit_offsets[first], exit_words[first],
                                    exit_offsets[first + 1], exit_words[first + 1],
                                    exit_offsets[first + 2], exit_words[first + 2],
                                    exit_offsets[first + 3], exit_words[first + 3],
                                    exit_offsets[first + 4], exit_words[first + 4],
                                    exit_offsets[first + 5], exit_words[first + 5]);
                            zeroCtrlDiagnosticsText(line);
                        }
                        for (exit_index = 0; exit_index < 18; exit_index++) {
                            unsigned int word = exit_words[exit_index];
                            unsigned int opcode = word >> 26;
                            unsigned int function = word & 0x3F;
                            unsigned int pc = bsman->activation_addr +
                                    exit_offsets[exit_index];
                            int direct_jump = opcode == 2 || opcode == 3;
                            int branch = opcode == 1 || opcode == 4 ||
                                    opcode == 5 || opcode == 6 || opcode == 7;
                            int register_jump = opcode == 0 &&
                                    (function == 8 || function == 9);
                            unsigned int target = direct_jump ?
                                    zeroCtrlMipsJumpTarget(pc, word) :
                                    (branch ? zeroCtrlMipsBranchTarget(pc, word) : 0);
                            if (direct_jump || branch || register_jump) {
                                snprintf(line, sizeof(line),
                                        "[t40-exit-control] offset=0x%03X "
                                        "word=0x%08X opcode=0x%02X rs=%u rt=%u "
                                        "function=0x%02X target=0x%08X "
                                        "target_offset=0x%08X\n",
                                        exit_offsets[exit_index], word, opcode,
                                        (word >> 21) & 0x1F,
                                        (word >> 16) & 0x1F, function, target,
                                        target ? target - bsman->activation_addr : 0);
                                zeroCtrlDiagnosticsText(line);
                            }
                        }
                    }
                    {
                        static const unsigned int natural_offsets[26] = {
                            0x04C, 0x050, 0x054, 0x058, 0x05C, 0x060,
                            0x064, 0x068, 0x06C, 0x070, 0x074, 0x078,
                            0x07C, 0x080, 0x084, 0x088, 0x08C, 0x090,
                            0x094, 0x098, 0x09C, 0x0A0, 0x0A4, 0x0A8,
                            0x0AC, 0x0B0
                        };
                        unsigned int natural_words[26];
                        unsigned int natural_index;
                        for (natural_index = 0; natural_index < 26;
                                natural_index++)
                            natural_words[natural_index] = _lw(
                                    bsman->activation_addr +
                                    natural_offsets[natural_index]);
                        for (natural_index = 0; natural_index < 4;
                                natural_index++) {
                            unsigned int first = natural_index * 6;
                            snprintf(line, sizeof(line),
                                    "[natural-50-window-%u] "
                                    "%03x=0x%08X %03x=0x%08X %03x=0x%08X "
                                    "%03x=0x%08X %03x=0x%08X %03x=0x%08X\n",
                                    natural_index,
                                    natural_offsets[first], natural_words[first],
                                    natural_offsets[first + 1], natural_words[first + 1],
                                    natural_offsets[first + 2], natural_words[first + 2],
                                    natural_offsets[first + 3], natural_words[first + 3],
                                    natural_offsets[first + 4], natural_words[first + 4],
                                    natural_offsets[first + 5], natural_words[first + 5]);
                            zeroCtrlDiagnosticsText(line);
                        }
                        snprintf(line, sizeof(line),
                                "[natural-50-window-4] 0ac=0x%08X 0b0=0x%08X\n",
                                natural_words[24], natural_words[25]);
                        zeroCtrlDiagnosticsText(line);
                        for (natural_index = 0; natural_index < 26;
                                natural_index++) {
                            unsigned int word = natural_words[natural_index];
                            unsigned int opcode = word >> 26;
                            unsigned int function = word & 0x3F;
                            unsigned int pc = bsman->activation_addr +
                                    natural_offsets[natural_index];
                            int direct_jump = opcode == 2 || opcode == 3;
                            int branch = opcode == 1 || opcode == 4 ||
                                    opcode == 5 || opcode == 6 || opcode == 7;
                            int register_jump = opcode == 0 &&
                                    (function == 8 || function == 9);
                            unsigned int target = direct_jump ?
                                    zeroCtrlMipsJumpTarget(pc, word) :
                                    (branch ? zeroCtrlMipsBranchTarget(pc, word) : 0);
                            if (direct_jump || branch || register_jump) {
                                snprintf(line, sizeof(line),
                                        "[natural-50-control] offset=0x%03X "
                                        "word=0x%08X opcode=0x%02X rs=%u rt=%u "
                                        "function=0x%02X target=0x%08X "
                                        "target_offset=0x%08X\n",
                                        natural_offsets[natural_index], word,
                                        opcode, (word >> 21) & 0x1F,
                                        (word >> 16) & 0x1F, function, target,
                                        target ? target - bsman->activation_addr : 0);
                                zeroCtrlDiagnosticsText(line);
                            }
                        }
                    }
                    {
                        SceModule2 *slide = sceKernelFindModuleByName(
                                "slide_plugin_module");
                        unsigned int jal_matches = 0;
                        unsigned int jump_matches = 0;
                        unsigned int scan_offset;
                        if (slide && bsman->activation_addr >= slide->text_addr &&
                                bsman->activation_addr - slide->text_addr <
                                    slide->text_size) {
                            for (scan_offset = 0; scan_offset + 8 <=
                                    slide->text_size; scan_offset += 4) {
                                unsigned int pc = slide->text_addr + scan_offset;
                                unsigned int word = _lw(pc);
                                if ((word >> 26) == 3 &&
                                        zeroCtrlMipsJumpTarget(pc, word) ==
                                            bsman->activation_addr)
                                    jal_matches++;
                                else if ((word >> 26) == 2 &&
                                        zeroCtrlMipsJumpTarget(pc, word) ==
                                            bsman->activation_addr)
                                    jump_matches++;
                            }
                            snprintf(line, sizeof(line),
                                    "[activation-callers] matches=%u jumps=%u "
                                    "activation=0x%08X text=0x%08X size=0x%X "
                                    "loaded_words=1\n",
                                    jal_matches, jump_matches,
                                    bsman->activation_addr, slide->text_addr,
                                    slide->text_size);
                            zeroCtrlDiagnosticsText(line);
                            jal_matches = 0;
                            jump_matches = 0;
                            for (scan_offset = 0; scan_offset + 8 <=
                                    slide->text_size; scan_offset += 4) {
                                unsigned int pc = slide->text_addr + scan_offset;
                                unsigned int word = _lw(pc);
                                unsigned int opcode = word >> 26;
                                if ((opcode == 2 || opcode == 3) &&
                                        zeroCtrlMipsJumpTarget(pc, word) ==
                                            bsman->activation_addr) {
                                    unsigned int index = opcode == 3 ?
                                            jal_matches++ : jump_matches++;
                                    snprintf(line, sizeof(line),
                                            opcode == 3 ?
                                            "[activation-caller] index=%u " :
                                            "[activation-jump] index=%u ", index);
                                    snprintf(line + strlen(line),
                                            sizeof(line) - strlen(line),
                                            "offset=0x%08X address=0x%08X "
                                            "word=0x%08X delay=0x%08X "
                                            "return=0x%08X\n",
                                            scan_offset, pc, word, _lw(pc + 4),
                                            pc + 8);
                                    zeroCtrlDiagnosticsText(line);
                                }
                            }
                        }
                    }
                    if (bsman->post_collection_paf_fcf265d8_enabled) {
                        snprintf(line, sizeof(line),
                                "[t37-validation] enabled=1 checked=%u "
                                "fail_mask=0x%08X word_198=0x%08X "
                                "word_19c=0x%08X word_1a0=0x%08X "
                                "word_1a4=0x%08X word_1a8=0x%08X\n",
                                bsman->post_collection_paf_fcf265d8_guard_checked,
                                bsman->post_collection_paf_fcf265d8_fail_mask,
                                bsman->post_collection_paf_fcf265d8_original[0],
                                bsman->post_collection_paf_fcf265d8_original[1],
                                bsman->post_collection_paf_fcf265d8_original[2],
                                bsman->post_collection_paf_fcf265d8_original[3],
                                bsman->post_collection_paf_fcf265d8_original[4]);
                        zeroCtrlDiagnosticsText(line);
                        snprintf(line, sizeof(line),
                                "[t37-validation-targets] call_target=0x%08X "
                                "expected_call_target=0x%08X arg_target=0x%08X "
                                "expected_arg_target=0x%08X replacement=0x%08X "
                                "replacement_target=0x%08X leaf=0x%08X\n",
                                bsman->post_collection_paf_fcf265d8_decoded_call_target,
                                bsman->post_collection_paf_fcf265d8_expected_call_target,
                                bsman->post_collection_paf_fcf265d8_observed_arg_target,
                                bsman->post_collection_paf_fcf265d8_expected_arg_target,
                                bsman->post_collection_paf_fcf265d8_replacement,
                                bsman->post_collection_paf_fcf265d8_decoded_replacement_target,
                                bsman->post_collection_paf_fcf265d8_leaf_addr);
                        zeroCtrlDiagnosticsText(line);
                    }
                    snprintf(line, sizeof(line),
                            "[activation-trace] original=0x%08X,0x%08X "
                            "replacement=0x%08X,0x%08X "
                            "call_original=0x%08X call_replacement=0x%08X\n",
                            bsman->activation_original[0],
                            bsman->activation_original[1],
                            bsman->activation_replacement[0],
                            bsman->activation_replacement[1],
                            bsman->call_original, bsman->call_replacement);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[activation-prefix] branch_words="
                            "0x%08X,0x%08X,0x%08X,0x%08X,0x%08X,0x%08X\n",
                            bsman->prefix_original[0], bsman->prefix_original[1],
                            bsman->prefix_original[2], bsman->prefix_original[3],
                            bsman->prefix_original[4], bsman->prefix_original[5]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[activation-prefix] paf_call_words=0x%08X,0x%08X "
                            "nid=0xED83BBCF\n",
                            bsman->prefix_original[6], bsman->prefix_original[7]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[post-bsman] words="
                            "0x%08X,0x%08X,0x%08X,0x%08X,"
                            "0x%08X,0x%08X,0x%08X,0x%08X\n",
                            bsman->post_original[0], bsman->post_original[1],
                            bsman->post_original[2], bsman->post_original[3],
                            bsman->post_original[4], bsman->post_original[5],
                            bsman->post_original[6], bsman->post_original[7]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[post-bsman] vsh_words=0x%08X,0x%08X,"
                            "0x%08X,0x%08X paf_nid=0xFF03BCD5 "
                            "vshbridge_nid=0x639C3CB3 argument=0x8000000D\n",
                            bsman->post_original[8], bsman->post_original[9],
                            bsman->post_original[10], bsman->post_original[11]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[state-zero] words0="
                            "0x%08X,0x%08X,0x%08X,0x%08X,"
                            "0x%08X,0x%08X,0x%08X,0x%08X\n",
                            bsman->state_zero_original[0],
                            bsman->state_zero_original[1],
                            bsman->state_zero_original[2],
                            bsman->state_zero_original[3],
                            bsman->state_zero_original[4],
                            bsman->state_zero_original[5],
                            bsman->state_zero_original[6],
                            bsman->state_zero_original[7]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[state-zero] words1="
                            "0x%08X,0x%08X,0x%08X,0x%08X,"
                            "0x%08X,0x%08X\n",
                            bsman->state_zero_original[8],
                            bsman->state_zero_original[9],
                            bsman->state_zero_original[10],
                            bsman->state_zero_original[11],
                            bsman->state_zero_original[12],
                            bsman->state_zero_original[13]);
                    zeroCtrlDiagnosticsText(line);
                }
                observed_bsman_attempted = 1;
            }
            if (hits != observed_bsman_hits) {
                observed_bsman_hits = hits;
                zeroCtrlWriteLateTransition(elapsed, "bsman_hit_count", hits);
            }
        }
        if (slide_diag.bsman.activation_enabled) {
            ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
            unsigned int hits = zeroCtrlReadHelperCounter(
                    bsman->activation_hits_addr);
            unsigned int call_hits = zeroCtrlReadHelperCounter(
                    bsman->call_hits_addr);
            unsigned int stage = zeroCtrlReadHelperCounter(
                    bsman->trace_stage_addr);
            unsigned int prefix_mask = zeroCtrlReadHelperCounter(
                    bsman->prefix_path_mask_addr);
            unsigned int paf_substitutions = zeroCtrlReadHelperCounter(
                    bsman->prefix_paf_substitution_hits_addr);
            unsigned int paf_returns = zeroCtrlReadHelperCounter(
                    bsman->prefix_paf_return_hits_addr);
            unsigned int post_mask = zeroCtrlReadHelperCounter(
                    bsman->post_path_mask_addr);
            if (stage != observed_trace_stage) {
                observed_trace_stage = stage;
                zeroCtrlWriteLateTransition(elapsed,
                        "slide_last_stage", stage);
            }
            if (hits != observed_activation_hits) {
                observed_activation_hits = hits;
                zeroCtrlWriteLateTransition(elapsed,
                        "slide_activation_entry_count", hits);
            }
            if (call_hits != observed_bsman_call_hits) {
                observed_bsman_call_hits = call_hits;
                zeroCtrlWriteLateTransition(elapsed,
                        "slide_bsman_call_boundary_count", call_hits);
            }
            if (prefix_mask != observed_prefix_mask) {
                observed_prefix_mask = prefix_mask;
                snprintf(line, sizeof(line),
                        "[late] elapsed_us=%u slide_prefix_path_mask=0x%03X\n",
                        elapsed, prefix_mask);
                zeroCtrlDiagnosticsText(line);
            }
            if (paf_returns != observed_paf_returns) {
                unsigned int natural_result = zeroCtrlReadHelperCounter(
                        bsman->prefix_paf_natural_result_addr);
                observed_paf_returns = paf_returns;
                snprintf(line, sizeof(line),
                        "[late] elapsed_us=%u paf_ed83bbcf_natural=0x%08X "
                        "return_count=%u zero_to_one_count=%u\n",
                        elapsed, natural_result, paf_returns, paf_substitutions);
                zeroCtrlDiagnosticsText(line);
            }
            if (post_mask != observed_post_mask) {
                observed_post_mask = post_mask;
                snprintf(line, sizeof(line),
                        "[late] elapsed_us=%u post_bsman_path_mask=0x%03X\n",
                        elapsed, post_mask);
                zeroCtrlDiagnosticsText(line);
            }
            {
                unsigned int state_mask = zeroCtrlReadHelperCounter(
                        bsman->state_zero_path_mask_addr);
                if (state_mask != observed_state_zero_mask) {
                    unsigned int value[7], count[4];
                    observed_state_zero_mask = state_mask;
                    for (i = 0; i < 7; i++) value[i] = zeroCtrlReadHelperCounter(
                            bsman->state_zero_value_addr[i]);
                    for (i = 0; i < 4; i++) count[i] = zeroCtrlReadHelperCounter(
                            bsman->state_zero_counter_addr[i]);
                    snprintf(line, sizeof(line),
                            "[late] elapsed_us=%u state_zero_mask=0x%04X "
                            "cmp=0x%08X/0x%08X word=0x%08X byte=0x%02X "
                            "vcall=0x%08X result=0x%08X "
                            "counts=entry:%u,call:%u,return:%u,rejoin:%u\n",
                            elapsed, state_mask, value[0], value[1], value[2],
                            value[3] & 0xFF, value[4], value[6], count[0],
                            count[1], count[2], count[3]);
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[state-zero-15to14-compat] enabled=%d "
                            "natural=0x%08X effective=0x%08X substitutions=%u\n",
                            bsman->state_zero_15to14_compat_enabled, value[6],
                            zeroCtrlReadHelperCounter(
                                bsman->state_zero_15to14_effective_result_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->state_zero_15to14_substitution_hits_addr));
                    zeroCtrlDiagnosticsText(line);
                }
                if (!observed_state_zero_vcall_owner) {
                    unsigned int target = zeroCtrlReadHelperCounter(
                            bsman->state_zero_value_addr[4]);
                    unsigned int returns = zeroCtrlReadHelperCounter(
                            bsman->state_zero_counter_addr[2]);
                    if (target != 0 && returns != 0)
                        zeroCtrlCaptureStateZeroVCallOwner(target);
                    if (slide_diag.state_zero_vcall_resolve_attempted) {
                        snprintf(line, sizeof(line),
                                "[state-zero-vcall-resolve] attempted=1 "
                                "target=0x%08X candidates_found=%u "
                                "containing_candidates=%u owner_found=%d "
                                "text_valid=%d "
                                "segment_valid=%d fingerprint_valid=%d "
                                "reason=%s(%d)\n",
                                slide_diag.state_zero_vcall_target,
                                slide_diag.state_zero_vcall_candidates_found,
                                slide_diag.state_zero_vcall_containing_candidates,
                                slide_diag.state_zero_vcall_owner_found,
                                slide_diag.state_zero_vcall_text_valid,
                                slide_diag.state_zero_vcall_segment_valid,
                                slide_diag.state_zero_vcall_fingerprint_valid,
                                zeroCtrlStateZeroVCallReasonName(
                                    slide_diag.state_zero_vcall_resolve_reason),
                                slide_diag.state_zero_vcall_resolve_reason);
                        zeroCtrlDiagnosticsText(line);
                        if (slide_diag.state_zero_vcall_fingerprint_valid) {
                            snprintf(line, sizeof(line),
                                    "[state-zero-vcall-owner] target=0x%08X "
                                    "module=%s text=0x%08X text_size=0x%08X "
                                    "offset=0x%08X segment=%u "
                                    "segment_start=0x%08X segment_size=0x%08X\n",
                                    slide_diag.state_zero_vcall_target,
                                    slide_diag.state_zero_vcall_module,
                                    slide_diag.state_zero_vcall_text_addr,
                                    slide_diag.state_zero_vcall_text_size,
                                    slide_diag.state_zero_vcall_offset,
                                    slide_diag.state_zero_vcall_segment_index,
                                    slide_diag.state_zero_vcall_segment_addr,
                                    slide_diag.state_zero_vcall_segment_size);
                            zeroCtrlDiagnosticsText(line);
                            snprintf(line, sizeof(line),
                                    "[state-zero-vcall-code] offset=0x%08X "
                                    "words=0x%08X,0x%08X,0x%08X,0x%08X,"
                                    "0x%08X,0x%08X,0x%08X,0x%08X,"
                                    "0x%08X,0x%08X\n",
                                    slide_diag.state_zero_vcall_offset,
                                    slide_diag.state_zero_vcall_code[0],
                                    slide_diag.state_zero_vcall_code[1],
                                    slide_diag.state_zero_vcall_code[2],
                                    slide_diag.state_zero_vcall_code[3],
                                    slide_diag.state_zero_vcall_code[4],
                                    slide_diag.state_zero_vcall_code[5],
                                    slide_diag.state_zero_vcall_code[6],
                                    slide_diag.state_zero_vcall_code[7],
                                    slide_diag.state_zero_vcall_code[8],
                                    slide_diag.state_zero_vcall_code[9]);
                            zeroCtrlDiagnosticsText(line);
                        }
                        if (slide_diag.topmenu_validation) {
                            zeroCtrlCaptureTopMenuState();
                            observed_topmenu_returns = returns;
                        }
                        snprintf(line, sizeof(line),
                                "[topmenu-state] validation=%d reason=%s(%d) "
                                "target_offset=0x%08X global_slot=0x%08X "
                                "context=0x%08X field_128=0x%08X "
                                "field_12C=0x%08X field_150=0x%02X "
                                "return_source=%s\n",
                                slide_diag.topmenu_validation,
                                zeroCtrlTopMenuReasonName(
                                    slide_diag.topmenu_failure_reason),
                                slide_diag.topmenu_failure_reason,
                                slide_diag.state_zero_vcall_offset,
                                slide_diag.topmenu_global_slot,
                                slide_diag.topmenu_context,
                                slide_diag.topmenu_first[0],
                                slide_diag.topmenu_first[1],
                                slide_diag.topmenu_first[2] & 0xFF,
                                slide_diag.topmenu_first[2] != 0 ?
                                    "FORCED_15" : "FIELD_12C");
                        zeroCtrlDiagnosticsText(line);
                        snprintf(line, sizeof(line),
                                "[topmenu-field12c-write-live] validation=%d "
                                "install=%d cache_sync=%d hits=%u "
                                "first=0x%08X last=0x%08X changes=%u "
                                "context=0x%08X\n",
                                bsman->field12c_write_validation,
                                bsman->field12c_write_install,
                                bsman->field12c_write_cache_sync,
                                zeroCtrlReadHelperCounter(
                                    bsman->field12c_write_scalar_addr[0]),
                                zeroCtrlReadHelperCounter(
                                    bsman->field12c_write_scalar_addr[1]),
                                zeroCtrlReadHelperCounter(
                                    bsman->field12c_write_scalar_addr[2]),
                                zeroCtrlReadHelperCounter(
                                    bsman->field12c_write_scalar_addr[3]),
                                zeroCtrlReadHelperCounter(
                                    bsman->field12c_write_scalar_addr[4]));
                        zeroCtrlDiagnosticsText(line);
                        snprintf(line, sizeof(line),
                                "[topmenu-case14-live] validation=%d install=%d "
                                "cache_sync=%d hits=%u first_ra=0x%08X "
                                "last_ra=0x%08X ra_changes=%u\n",
                                bsman->case14_validation, bsman->case14_install,
                                bsman->case14_cache_sync,
                                zeroCtrlReadHelperCounter(bsman->case14_scalar_addr[0]),
                                zeroCtrlReadHelperCounter(bsman->case14_scalar_addr[1]),
                                zeroCtrlReadHelperCounter(bsman->case14_scalar_addr[2]),
                                zeroCtrlReadHelperCounter(bsman->case14_scalar_addr[3]));
                        zeroCtrlDiagnosticsText(line);
                        snprintf(line, sizeof(line),
                                "[topmenu-dispatch-entry-live] validation=%d "
                                "install=%d cache_sync=%d hits=%u "
                                "case14_requests=%u first_ra=0x%08X "
                                "last_ra=0x%08X ra_changes=%u\n",
                                bsman->dispatch_entry_validation,
                                bsman->dispatch_entry_install,
                                bsman->dispatch_entry_cache_sync,
                                zeroCtrlReadHelperCounter(
                                    bsman->dispatch_entry_scalar_addr[0]),
                                zeroCtrlReadHelperCounter(
                                    bsman->dispatch_entry_scalar_addr[1]),
                                zeroCtrlReadHelperCounter(
                                    bsman->dispatch_entry_scalar_addr[2]),
                                zeroCtrlReadHelperCounter(
                                    bsman->dispatch_entry_scalar_addr[3]),
                                zeroCtrlReadHelperCounter(
                                    bsman->dispatch_entry_scalar_addr[4]));
                        zeroCtrlDiagnosticsText(line);
                        observed_state_zero_vcall_owner = 1;
                    }
                }
                if (slide_diag.topmenu_validation) {
                    unsigned int returns = zeroCtrlReadHelperCounter(
                            bsman->state_zero_counter_addr[2]);
                    if (returns != observed_topmenu_returns) {
                        zeroCtrlCaptureTopMenuState();
                        observed_topmenu_returns = returns;
                    }
                }
            }
            {
                unsigned int counts[25], j;
                int changed = 0;
                counts[0] = zeroCtrlReadHelperCounter(bsman->bsman_return_hits_addr);
                counts[1] = zeroCtrlReadHelperCounter(bsman->post_bs_counter_addr[0]);
                counts[2] = zeroCtrlReadHelperCounter(bsman->post_bs_counter_addr[1]);
                counts[3] = zeroCtrlReadHelperCounter(bsman->post_state_counter_addr[0]);
                counts[4] = zeroCtrlReadHelperCounter(bsman->post_state_counter_addr[1]);
                counts[5] = zeroCtrlReadHelperCounter(
                        bsman->post_paf_entry_counter_addr[0]);
                counts[6] = zeroCtrlReadHelperCounter(
                        bsman->post_paf_return_counter_addr[0]);
                counts[7] = zeroCtrlReadHelperCounter(
                        bsman->post_paf_entry_counter_addr[1]);
                counts[8] = zeroCtrlReadHelperCounter(
                        bsman->post_paf_return_counter_addr[1]);
                counts[9] = zeroCtrlReadHelperCounter(
                        bsman->post_vsh_entry_hits_addr);
                counts[10] = zeroCtrlReadHelperCounter(
                        bsman->post_vsh_return_hits_addr);
                counts[11] = zeroCtrlReadHelperCounter(
                        bsman->post_impose_vcall_hits_addr);
                counts[12] = zeroCtrlReadHelperCounter(
                        bsman->post_impose_vcall_return_hits_addr);
                counts[13] = zeroCtrlReadHelperCounter(
                        bsman->post_minus_one_vcall64_hits_addr);
                counts[14] = zeroCtrlReadHelperCounter(
                        bsman->post_minus_one_vcall64_return_hits_addr);
                counts[15] = zeroCtrlReadHelperCounter(
                        bsman->collection_paf_fcf265d8_hits_addr);
                counts[16] = zeroCtrlReadHelperCounter(
                        bsman->collection_paf_fcf265d8_nonzero_hits_addr);
                counts[17] = zeroCtrlReadHelperCounter(
                        bsman->collection_paf_9a285882_hits_addr);
                counts[18] = zeroCtrlReadHelperCounter(
                        bsman->collection_paf_9a285882_nonzero_hits_addr);
                counts[19] = zeroCtrlReadHelperCounter(
                        bsman->post_collection_paf_fcf265d8_hits_addr);
                counts[20] = zeroCtrlReadHelperCounter(
                        bsman->post_collection_paf_fcf265d8_nonzero_hits_addr);
                counts[21] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_hits_addr);
                counts[22] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_nonzero_hits_addr);
                counts[23] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_second_hits_addr);
                counts[24] = zeroCtrlReadHelperCounter(
                        bsman->masked_paf_c59fc3d0_second_nonzero_hits_addr);
                for (j = 0; j < 25; j++)
                    if (counts[j] != observed_post_counts[j]) changed = 1;
                if (changed) {
                    unsigned int bs_result = zeroCtrlReadHelperCounter(
                            bsman->bsman_natural_result_addr);
                    unsigned int bs_substitutions = zeroCtrlReadHelperCounter(
                            bsman->bsman_substitution_hits_addr);
                    unsigned int bs_effective = zeroCtrlReadHelperCounter(
                            bsman->bsman_effective_result_addr);
                    unsigned int paf0 = zeroCtrlReadHelperCounter(
                            bsman->post_paf_result_addr[0]);
                    unsigned int paf1 = zeroCtrlReadHelperCounter(
                            bsman->post_paf_result_addr[1]);
                    unsigned int vsh_result = zeroCtrlReadHelperCounter(
                            bsman->post_vsh_natural_result_addr);
                    memcpy(observed_post_counts, counts, sizeof(counts));
                    snprintf(line, sizeof(line),
                            "[late] elapsed_us=%u post_bsman_counts="
                            "return:%u,zero:%u,nonzero:%u,state_zero:%u,"
                            "state_nonzero:%u,paf0:%u/%u,paf1:%u/%u,"
                            "vsh:%u/%u "
                            "results=bs_natural:0x%08X,bs_exact_sub:%u,"
                            "bs_effective:0x%08X,paf0:0x%08X,paf1:0x%08X,"
                            "vsh:0x%08X\n",
                            elapsed, counts[0], counts[1], counts[2], counts[3],
                            counts[4], counts[5], counts[6], counts[7], counts[8],
                            counts[9], counts[10], bs_result, bs_substitutions,
                            bs_effective, paf0, paf1, vsh_result);
                    zeroCtrlDiagnosticsText(line);
                    if (bsman->activation_wide_enabled) {
                        unsigned int *w = bsman->activation_wide_scalar_addr;
#define WREAD(i) zeroCtrlReadHelperCounter(w[(i)])
                        snprintf(line, sizeof(line),
                                "[activation-wide-compare] validation=%d install=%d cache_sync=%d "
                                "hits=%u zero=%u nonzero=%u first_compare=%u last_compare=%u changes=%u\n",
                                bsman->activation_wide_validation,
                                bsman->activation_wide_install,
                                bsman->activation_wide_cache_sync,
                                WREAD(0), WREAD(1), WREAD(2), WREAD(3), WREAD(4), WREAD(5));
                        zeroCtrlDiagnosticsText(line);
#define WIDE_RAW_LINE(label, base) do { \
    snprintf(line, sizeof(line), "[activation-wide-" label "] validation=%d install=%d cache_sync=%d hits=%u zero=%u nonzero=%u first_raw=0x%08X last_raw=0x%08X changes=%u\n", \
        bsman->activation_wide_validation, bsman->activation_wide_install, \
        bsman->activation_wide_cache_sync, WREAD((base)+3), WREAD((base)+7), \
        WREAD((base)+8), WREAD((base)+4), WREAD((base)+5), WREAD((base)+6)); \
    zeroCtrlDiagnosticsText(line); \
} while (0)
                        WIDE_RAW_LINE("662922b9", 8);
                        WIDE_RAW_LINE("440665db", 17);
                        WIDE_RAW_LINE("fcf265d8", 26);
                        snprintf(line, sizeof(line),
                                "[activation-wide-loop] validation=%d install=%d cache_sync=%d "
                                "hits=%u loop_back=%u exit=%u first_decision=%u last_decision=%u changes=%u\n",
                                bsman->activation_wide_validation,
                                bsman->activation_wide_install,
                                bsman->activation_wide_cache_sync,
                                WREAD(35), WREAD(36), WREAD(37), WREAD(38), WREAD(39), WREAD(40));
                        zeroCtrlDiagnosticsText(line);
                        WIDE_RAW_LINE("090ccb3f", 43);
#undef WIDE_RAW_LINE
#undef WREAD
                    }
                    snprintf(line, sizeof(line),
                            "[masked-paf-c59fc3d0-second] validation=%d "
                            "install=%d cache_sync=%d hits=%u nonzero=%u "
                            "decision=0x%08X\n",
                            bsman->masked_paf_c59fc3d0_second_validation,
                            bsman->masked_paf_c59fc3d0_second_install,
                            bsman->masked_paf_c59fc3d0_second_cache_sync,
                            counts[23], counts[24],
                            zeroCtrlReadHelperCounter(bsman->
                                masked_paf_c59fc3d0_second_decision_value_addr));
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[masked-paf-c59fc3d0] validation=%d install=%d "
                            "cache_sync=%d hits=%u nonzero=%u decision=0x%08X\n",
                            bsman->masked_paf_c59fc3d0_validation,
                            bsman->masked_paf_c59fc3d0_install,
                            bsman->masked_paf_c59fc3d0_cache_sync,
                            counts[21], counts[22],
                            zeroCtrlReadHelperCounter(
                                bsman->masked_paf_c59fc3d0_decision_value_addr));
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[post-collection-paf-fcf265d8] validation=%d "
                            "install=%d cache_sync=%d hits=%u nonzero=%u "
                            "natural=0x%08X\n",
                            bsman->post_collection_paf_fcf265d8_validation,
                            bsman->post_collection_paf_fcf265d8_install,
                            bsman->post_collection_paf_fcf265d8_cache_sync,
                            counts[19], counts[20],
                            zeroCtrlReadHelperCounter(
                                bsman->post_collection_paf_fcf265d8_natural_result_addr));
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[collection-paf-9a285882] validation=%d install=%d "
                            "cache_sync=%d hits=%u nonzero=%u last_item=0x%08X "
                            "natural=0x%08X\n",
                            bsman->collection_paf_9a285882_validation,
                            bsman->collection_paf_9a285882_install,
                            bsman->collection_paf_9a285882_cache_sync,
                            counts[17], counts[18],
                            zeroCtrlReadHelperCounter(bsman->collection_paf_9a285882_last_item_addr),
                            zeroCtrlReadHelperCounter(bsman->collection_paf_9a285882_natural_result_addr));
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[vsh-impose-param-8000000d-compat] enabled=%d "
                            "argument=0x%08X natural=0x%08X effective=0x%08X "
                            "substitutions=%u\n",
                            bsman->post_vsh_compat_enabled,
                            zeroCtrlReadHelperCounter(bsman->post_vsh_argument_addr),
                            vsh_result,
                            zeroCtrlReadHelperCounter(
                                bsman->post_vsh_effective_result_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->post_vsh_substitution_hits_addr));
                    zeroCtrlDiagnosticsText(line);
                    {
                        unsigned int natural = zeroCtrlReadHelperCounter(
                                bsman->post_impose_vcall_natural_result_addr);
                        snprintf(line, sizeof(line),
                                "[post-impose-vcall-50] validation=%d install=%d "
                                "cache_sync=%d hits=%u returns=%u target=0x%08X "
                                "natural=0x%08X equals_minus_one=%d\n",
                                bsman->post_impose_vcall_validation,
                                bsman->post_impose_vcall_install,
                                bsman->post_impose_vcall_cache_sync,
                                counts[11], counts[12],
                                zeroCtrlReadHelperCounter(
                                    bsman->post_impose_vcall_target_addr),
                                natural, natural == 0xFFFFFFFF);
                        zeroCtrlDiagnosticsText(line);
                    }
                    {
                        unsigned int target = zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_target_addr);
                        unsigned int natural = zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_natural_result_addr);
                        unsigned int target_offset = target - slide_diag.vsh_text_addr;
                        snprintf(line, sizeof(line),
                                "[post-minus-one-vcall-64] validation=%d install=%d "
                                "cache_sync=%d hits=%u returns=%u target=0x%08X "
                                "target_offset=0x%08X target_matches_1f8e0=%d "
                                "natural=0x%08X\n",
                                bsman->post_minus_one_vcall64_validation,
                                bsman->post_minus_one_vcall64_install,
                                bsman->post_minus_one_vcall64_cache_sync,
                                counts[13], counts[14], target, target_offset,
                                target_offset == 0x1F8E0, natural);
                        zeroCtrlDiagnosticsText(line);
                    }
                    snprintf(line, sizeof(line),
                            "[post-vcall64-collection] enabled=%d pointer=0x%08X "
                            "count=0x%08X array=0x%08X array_read=%u\n",
                            bsman->post_vcall64_collection_enabled,
                            zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_natural_result_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_count_snapshot_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_array_snapshot_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->post_minus_one_vcall64_array_read_hits_addr));
                    zeroCtrlDiagnosticsText(line);
                    snprintf(line, sizeof(line),
                            "[collection-paf-fcf265d8] validation=%d install=%d "
                            "cache_sync=%d hits=%u nonzero=%u last_item=0x%08X "
                            "natural=0x%08X\n",
                            bsman->collection_paf_fcf265d8_validation,
                            bsman->collection_paf_fcf265d8_install,
                            bsman->collection_paf_fcf265d8_cache_sync,
                            counts[15], counts[16],
                            zeroCtrlReadHelperCounter(
                                bsman->collection_paf_fcf265d8_last_item_addr),
                            zeroCtrlReadHelperCounter(
                                bsman->collection_paf_fcf265d8_natural_result_addr));
                    zeroCtrlDiagnosticsText(line);
                }
            }
            {
                unsigned int counts[6];
                int changed = 0;
                for (i = 0; i < 6; i++) {
                    counts[i] = zeroCtrlReadHelperCounter(
                            bsman->prefix_counter_addr[i]);
                    if (counts[i] != observed_prefix_counts[i]) changed = 1;
                }
                if (changed) {
                    memcpy(observed_prefix_counts, counts, sizeof(counts));
                    snprintf(line, sizeof(line),
                            "[late] elapsed_us=%u slide_prefix_counts="
                            "result_zero:%u,result_nonzero:%u,flag_zero:%u,"
                            "flag_nonzero:%u,mask_equal:%u,mask_unequal:%u\n",
                            elapsed, counts[0], counts[1], counts[2], counts[3],
                            counts[4], counts[5]);
                    zeroCtrlDiagnosticsText(line);
                }
            }
        }
#undef WRITE_LATE_FLAG
        {
            unsigned int delay = elapsed < fast_poll_until ?
                    10000 : SLIDE_OBSERVATION_POLL_US;
            sceKernelDelayThread(delay);
            elapsed += delay;
        }
    }
    zeroCtrlDiagnosticsText("[checkpoint] slide_observation_window_complete\n");
    zeroCtrlWriteSlideCheckpoints(&written);
    zeroCtrlDiagnosticsText("[checkpoint] final_partition_capture_begin\n");
    zeroCtrlDiagnosticsCapturePartitions(&slide_diag.delayed_or_timeout);
    zeroCtrlDiagnosticsText("[checkpoint] final_partition_capture_end\n");

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
    if (slide_diag.bsman.enabled || slide_diag.bsman.activation_enabled) {
        snprintf(line, sizeof(line),
                "[bsman] final install=%d validation=%d hit_count=%u\n",
                slide_diag.bsman.install, slide_diag.bsman.validation,
                zeroCtrlReadBSManHits());
        zeroCtrlDiagnosticsText(line);
        snprintf(line, sizeof(line),
                "[topmenu-field12c-write] validation=%d install=%d "
                "cache_sync=%d hits=%u first=0x%08X last=0x%08X "
                "changes=%u context=0x%08X\n",
                slide_diag.bsman.field12c_write_validation,
                slide_diag.bsman.field12c_write_install,
                slide_diag.bsman.field12c_write_cache_sync,
                zeroCtrlReadHelperCounter(
                    slide_diag.bsman.field12c_write_scalar_addr[0]),
                zeroCtrlReadHelperCounter(
                    slide_diag.bsman.field12c_write_scalar_addr[1]),
                zeroCtrlReadHelperCounter(
                    slide_diag.bsman.field12c_write_scalar_addr[2]),
                zeroCtrlReadHelperCounter(
                    slide_diag.bsman.field12c_write_scalar_addr[3]),
                zeroCtrlReadHelperCounter(
                    slide_diag.bsman.field12c_write_scalar_addr[4]));
        zeroCtrlDiagnosticsText(line);
    }
    if (slide_diag.state_zero_vcall_resolve_attempted) {
        snprintf(line, sizeof(line),
                "[topmenu-state-final] validation=%d reason=%s(%d) "
                "context=0x%08X first=0x%08X,0x%08X,0x%02X "
                "last=0x%08X,0x%08X,0x%02X transitions=%u "
                "return_source=%s\n",
                slide_diag.topmenu_validation,
                zeroCtrlTopMenuReasonName(slide_diag.topmenu_failure_reason),
                slide_diag.topmenu_failure_reason,
                slide_diag.topmenu_context,
                slide_diag.topmenu_first[0], slide_diag.topmenu_first[1],
                slide_diag.topmenu_first[2] & 0xFF,
                slide_diag.topmenu_last[0], slide_diag.topmenu_last[1],
                slide_diag.topmenu_last[2] & 0xFF,
                slide_diag.topmenu_transition_count,
                slide_diag.topmenu_last[2] != 0 ?
                    "FORCED_15" : "FIELD_12C");
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

static int zeroCtrlLibraryNameEquals(SceModule2 *mod, const char *name,
        const char *expected, unsigned int expected_size) {
    unsigned int i;
    if (!zeroCtrlVshModuleRangeValid(mod, (unsigned int)name,
                expected_size)) return 0;
    for (i = 0; i < expected_size; i++)
        if (name[i] != expected[i]) return 0;
    return 1;
}

static int zeroCtrlBSManLibraryNameValid(SceModule2 *mod, const char *name) {
    static const char expected[] = "sceBSMan";
    return zeroCtrlLibraryNameEquals(mod, name, expected, sizeof(expected));
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

static void zeroCtrlInstallField12CWriteTrace(void) {
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    unsigned int site, continuation, jump_word, store_word, replacement;
    unsigned int i;

    if (!vsh || !helper || vsh->text_size < 0x1DEB0 ||
            !zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x1DEA8, 8) ||
            !zeroCtrlVshModuleRangeValid(helper, bsman->field12c_write_leaf_addr,
                bsman->field12c_write_leaf_size) ||
            !zeroCtrlVshModuleRangeValid(helper,
                bsman->field12c_write_resume_addr, 4)) return;
    for (i = 0; i < 5; i++)
        if (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->field12c_write_scalar_addr[i], 4)) return;
    site = vsh->text_addr + 0x1DEA8;
    continuation = vsh->text_addr + 0x1D8C4;
    jump_word = _lw(site);
    store_word = _lw(site + 4);
    if ((jump_word >> 26) != 2 ||
            zeroCtrlMipsJumpTarget(site, jump_word) != continuation ||
            store_word != 0xAC53012C ||
            ((site + 4) & 0xF0000000) !=
                (bsman->field12c_write_leaf_addr & 0xF0000000)) return;
    replacement = 0x08000000 |
            ((bsman->field12c_write_leaf_addr >> 2) & 0x03FFFFFF);
    if (zeroCtrlMipsJumpTarget(site, replacement) !=
            bsman->field12c_write_leaf_addr) return;
    bsman->field12c_write_validation = 1;
    _sw(continuation, bsman->field12c_write_resume_addr);
    for (i = 0; i < 5; i++) _sw(0, bsman->field12c_write_scalar_addr[i]);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->field12c_write_resume_addr, 4);
    for (i = 0; i < 5; i++)
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->field12c_write_scalar_addr[i], 4);
    _sw(replacement, site);
    _sw(store_word, site + 4);
    sceKernelDcacheWritebackInvalidateRange((const void *)site, 8);
    sceKernelIcacheInvalidateRange((const void *)site, 8);
    bsman->field12c_write_install = 1;
    bsman->field12c_write_cache_sync = 1;
}

static void zeroCtrlInstallCase14Trace(void) {
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    unsigned int dispatcher, table, entry, natural, word, i;

    if (model != 0 || sceKernelDevkitVersion() != 0x06060110 || !vsh || !helper ||
            vsh->text_size < 0x4FDD8 ||
            !zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x1D7A4, 0x58) ||
            !zeroCtrlVshModuleRangeValid(helper, bsman->case14_leaf_addr,
                bsman->case14_leaf_size) ||
            !zeroCtrlVshModuleRangeValid(helper, bsman->case14_resume_addr, 4)) return;
    for (i = 0; i < 4; i++)
        if (!zeroCtrlVshModuleRangeValid(helper, bsman->case14_scalar_addr[i], 4)) return;
    dispatcher = vsh->text_addr + 0x1D7A4;
    if (_lw(dispatcher) != 0x27BDFFC0 ||
            _lw(dispatcher + 0x2C) != 0x00809821 ||
            _lw(dispatcher + 0x30) != 0x2C820016 ||
            (_lw(dispatcher + 0x3C) & 0xFFFF0000) != 0x3C030000 ||
            _lw(dispatcher + 0x40) != 0x00041080 ||
            (_lw(dispatcher + 0x44) & 0xFFFF0000) != 0x24630000 ||
            _lw(dispatcher + 0x48) != 0x00431021 ||
            _lw(dispatcher + 0x4C) != 0x8C440000 ||
            _lw(dispatcher + 0x50) != 0x00800008) return;
    table = ((_lw(dispatcher + 0x3C) & 0xFFFF) << 16) +
            (short)(_lw(dispatcher + 0x44) & 0xFFFF);
    if (table != vsh->text_addr + 0x4FDA0 || (table & 3) != 0 ||
            !zeroCtrlVshModuleRangeValid(vsh, table, 22 * 4)) return;
    entry = table + 14 * 4;
    natural = vsh->text_addr + 0x1DE18;
    if (_lw(entry) != natural || (natural & 3) != 0 ||
            !zeroCtrlVshModuleRangeValid(vsh, natural, 4) ||
            (bsman->case14_leaf_addr & 3) != 0) return;
    bsman->case14_validation = 1;
    _sw(natural, bsman->case14_resume_addr);
    for (i = 0; i < 4; i++) _sw(0, bsman->case14_scalar_addr[i]);
    sceKernelDcacheWritebackInvalidateRange((const void *)bsman->case14_resume_addr, 4);
    for (i = 0; i < 4; i++)
        sceKernelDcacheWritebackInvalidateRange((const void *)bsman->case14_scalar_addr[i], 4);
    word = bsman->case14_leaf_addr;
    _sw(word, entry);
    sceKernelDcacheWritebackInvalidateRange((const void *)entry, 4);
    bsman->case14_install = 1;
    bsman->case14_cache_sync = 1;
}

static void zeroCtrlInstallDispatchEntryTrace(void) {
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    unsigned int site, resume, replacement, i;

    if (bsman->dispatch_entry_install) return;
    if (model != 0 || sceKernelDevkitVersion() != 0x06060110 || !vsh || !helper ||
            vsh->text_size != 0x556C0 ||
            !zeroCtrlVshModuleRangeValid(vsh, vsh->text_addr + 0x1D7A4, 0x58) ||
            !zeroCtrlVshModuleRangeValid(helper, bsman->dispatch_entry_leaf_addr,
                bsman->dispatch_entry_leaf_size) ||
            !zeroCtrlVshModuleRangeValid(helper,
                bsman->dispatch_entry_resume_addr, 4)) return;
    for (i = 0; i < 5; i++)
        if (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->dispatch_entry_scalar_addr[i], 4)) return;
    site = vsh->text_addr + 0x1D7A4;
    resume = site + 8;
    if (_lw(site) != 0x27BDFFC0 || _lw(site + 4) != 0xAFB20018 ||
            (_lw(site + 8) & 0xFFFF0000) != 0x3C120000 ||
            (_lw(site + 0x20) & 0xFFFF0000) != 0x8E430000 ||
            _lw(site + 0x24) != 0x9062019D ||
            _lw(site + 0x28) != 0x1440003D ||
            _lw(site + 0x2C) != 0x00809821 ||
            _lw(site + 0x30) != 0x2C820016 ||
            !zeroCtrlVshModuleRangeValid(vsh, resume, 4) ||
            ((site + 4) & 0xF0000000) !=
                (bsman->dispatch_entry_leaf_addr & 0xF0000000)) return;
    replacement = 0x08000000 |
            ((bsman->dispatch_entry_leaf_addr >> 2) & 0x03FFFFFF);
    if (zeroCtrlMipsJumpTarget(site, replacement) !=
            bsman->dispatch_entry_leaf_addr) return;
    bsman->dispatch_entry_validation = 1;
    _sw(resume, bsman->dispatch_entry_resume_addr);
    for (i = 0; i < 5; i++) _sw(0, bsman->dispatch_entry_scalar_addr[i]);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->dispatch_entry_resume_addr, 4);
    for (i = 0; i < 5; i++)
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->dispatch_entry_scalar_addr[i], 4);
    _sw(replacement, site);
    _sw(0, site + 4);
    sceKernelDcacheWritebackInvalidateRange((const void *)site, 8);
    sceKernelIcacheInvalidateRange((const void *)site, 8);
    bsman->dispatch_entry_install = 1;
    bsman->dispatch_entry_cache_sync = 1;
}

static void zeroCtrlInstallCapabilityMaskTraces(void) {
    static const unsigned int offsets[4] = { 0x14014, 0x1402C, 0x14038, 0x1404C };
    static const unsigned int target_offsets[4] = { 0x6F44, 0x6FC4, 0x7004, 0x3F778 };
    static const unsigned int delays[4] = {
        0x0062800B, 0x0062800B, 0x0062800B, 0x27B10030 };
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    unsigned int callsite[4], target[4], leaf[4], leaf_size[4];
    unsigned int target_scalar[4], hits_scalar[4], value_scalar[4];
    unsigned int replacement[4], i;

    if (model != 0 || sceKernelDevkitVersion() != 0x06060110 || !vsh || !helper ||
            vsh->text_size != 0x556C0) return;
    for (i = 0; i < 3; i++) {
        leaf[i] = bsman->capability_leaf_addr[i];
        leaf_size[i] = bsman->capability_leaf_size[i];
        target_scalar[i] = bsman->capability_target_addr[i];
        hits_scalar[i] = bsman->capability_hits_addr[i];
        value_scalar[i] = bsman->capability_result_addr[i];
    }
    leaf[3] = bsman->paf_mask_leaf_addr;
    leaf_size[3] = bsman->paf_mask_leaf_size;
    target_scalar[3] = bsman->paf_mask_target_addr;
    hits_scalar[3] = bsman->paf_mask_hits_addr;
    value_scalar[3] = bsman->paf_mask_natural_addr;
    for (i = 0; i < 4; i++) {
        callsite[i] = vsh->text_addr + offsets[i];
        target[i] = vsh->text_addr + target_offsets[i];
        if (!zeroCtrlVshModuleRangeValid(vsh, callsite[i], 8) ||
                !zeroCtrlVshModuleRangeValid(vsh, target[i], 8) ||
                !zeroCtrlVshModuleRangeValid(helper, leaf[i], leaf_size[i]) ||
                !zeroCtrlVshModuleRangeValid(helper, target_scalar[i], 4) ||
                !zeroCtrlVshModuleRangeValid(helper, hits_scalar[i], 4) ||
                !zeroCtrlVshModuleRangeValid(helper, value_scalar[i], 4)) return;
        bsman->capability_original[i][0] = _lw(callsite[i]);
        bsman->capability_original[i][1] = _lw(callsite[i] + 4);
        if ((bsman->capability_original[i][0] >> 26) != 3 ||
                bsman->capability_original[i][1] != delays[i]) return;
        bsman->capability_decoded_target[i] = zeroCtrlMipsJumpTarget(
                callsite[i], bsman->capability_original[i][0]);
        if (bsman->capability_decoded_target[i] != target[i] ||
                ((callsite[i] + 4) & 0xF0000000) != (leaf[i] & 0xF0000000)) return;
        replacement[i] = 0x0C000000 | ((leaf[i] >> 2) & 0x03FFFFFF);
        if (zeroCtrlMipsJumpTarget(callsite[i], replacement[i]) != leaf[i]) return;
    }
    if (!zeroCtrlVshModuleRangeValid(helper, bsman->paf_mask_compat_mode_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper, bsman->paf_mask_effective_addr, 4) ||
            !zeroCtrlVshModuleRangeValid(helper,
                bsman->paf_mask_substitution_hits_addr, 4)) return;
    for (i = 0; i < 4; i++) bsman->capability_validation[i] = 1;
    for (i = 0; i < 4; i++) {
        _sw(target[i], target_scalar[i]);
        _sw(0, hits_scalar[i]);
        _sw(0xFFFFFFFF, value_scalar[i]);
        sceKernelDcacheWritebackInvalidateRange((const void *)target_scalar[i], 4);
        sceKernelDcacheWritebackInvalidateRange((const void *)hits_scalar[i], 4);
        sceKernelDcacheWritebackInvalidateRange((const void *)value_scalar[i], 4);
    }
    _sw(bsman->paf_mask_compat_enabled ? 1 : 0, bsman->paf_mask_compat_mode_addr);
    _sw(0xFFFFFFFF, bsman->paf_mask_effective_addr);
    _sw(0, bsman->paf_mask_substitution_hits_addr);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->paf_mask_compat_mode_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->paf_mask_effective_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->paf_mask_substitution_hits_addr, 4);
    for (i = 0; i < 4; i++) {
        _sw(replacement[i], callsite[i]);
        sceKernelDcacheWritebackInvalidateRange((const void *)callsite[i], 4);
        sceKernelIcacheInvalidateRange((const void *)callsite[i], 4);
        bsman->capability_install[i] = 1;
        bsman->capability_cache_sync[i] = 1;
    }
}

static void zeroCtrlInstall6F84ConsumerTraces(void) {
    static const unsigned int offsets[2] = { 0x13F6C, 0x14020 };
    static const unsigned int delays[2] = { 0x00000000, 0x0062800B };
    static const int range_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_RANGE_INVALID,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_RANGE_INVALID };
    static const int helper_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_HELPER_RANGE_INVALID,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_HELPER_RANGE_INVALID };
    static const int counter_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_COUNTER_RANGE_INVALID,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_COUNTER_RANGE_INVALID };
    static const int jal_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_NOT_JAL,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_NOT_JAL };
    static const int target_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_TARGET_MISMATCH,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_TARGET_MISMATCH };
    static const int delay_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_DELAY_MISMATCH,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_DELAY_MISMATCH };
    static const int region_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_PSEUDODIRECT_RANGE_INVALID,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_PSEUDODIRECT_RANGE_INVALID };
    static const int result_reasons[2] = {
        ZERO_CONSUMER_GUARD_CALLSITE_13F6C_RESULT_RANGE_INVALID,
        ZERO_CONSUMER_GUARD_CALLSITE_14020_RESULT_RANGE_INVALID };
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
    SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
    unsigned int target, callsite[2], replacement[2], predicate_global, i;
#define CONSUMER_GUARD_FAIL(value) do { \
    bsman->consumer_guard_reason = (value); \
    return; \
} while (0)

    bsman->consumer_guard_reason = ZERO_CONSUMER_GUARD_NOT_ATTEMPTED;
    bsman->consumer_predicate_first_bad = -1;
    bsman->consumer_shared_global_addr = slide_diag.vsh_shared_global_addr;
    if (model != 0) CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_MODEL_MISMATCH);
    if (sceKernelDevkitVersion() != 0x06060110)
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_DEVKIT_MISMATCH);
    if (!vsh) CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_VSH_NOT_FOUND);
    bsman->consumer_vsh_text = vsh->text_addr;
    bsman->consumer_vsh_text_size = vsh->text_size;
    bsman->consumer_vsh_nsegment = vsh->nsegment;
    bsman->consumer_segment_count = vsh->nsegment < 4 ? vsh->nsegment : 4;
    for (i = 0; i < bsman->consumer_segment_count; i++) {
        bsman->consumer_segment_addr[i] = vsh->segmentaddr[i];
        bsman->consumer_segment_size[i] = vsh->segmentsize[i];
    }
    if (!helper) CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_HELPER_NOT_FOUND);
    if (vsh->text_size != 0x556C0)
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_VSH_TEXT_SIZE_MISMATCH);
    target = vsh->text_addr + 0x6F84;
    if (!zeroCtrlVshModuleRangeValid(vsh, target, 0x40))
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_PREDICATE_RANGE_INVALID);
    for (i = 0; i < 16; i++)
        bsman->consumer_predicate_words[i] = _lw(target + i * 4);
    for (i = 0; i < 2; i++) {
        callsite[i] = vsh->text_addr + offsets[i];
        if (zeroCtrlVshModuleRangeValid(vsh, callsite[i], 8)) {
            bsman->consumer_callsite_words[i][0] = _lw(callsite[i]);
            bsman->consumer_callsite_words[i][1] = _lw(callsite[i] + 4);
            if ((bsman->consumer_callsite_words[i][0] >> 26) == 3)
                bsman->consumer_callsite_target[i] = zeroCtrlMipsJumpTarget(
                        callsite[i], bsman->consumer_callsite_words[i][0]);
        }
    }
    if (!slide_diag.vsh_shared_global_decode_valid)
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_SHARED_GLOBAL_DECODE_INVALID);
    if (!slide_diag.vsh_shared_global_segment_valid)
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_SHARED_GLOBAL_SEGMENT_INVALID);
    if (!zeroCtrlVshModuleRangeValid(vsh, slide_diag.vsh_shared_global_addr, 4))
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_SHARED_GLOBAL_RANGE_INVALID);
    bsman->consumer_target_scalar_range_valid = zeroCtrlVshModuleRangeValid(
            helper, bsman->consumer_target_addr, 4);
    if (!bsman->consumer_target_scalar_range_valid)
        CONSUMER_GUARD_FAIL(ZERO_CONSUMER_GUARD_TARGET_SCALAR_RANGE_INVALID);
    predicate_global = zeroCtrlDecodeLuiSignedLowAddress(
            bsman->consumer_predicate_words[0],
            bsman->consumer_predicate_words[1]);
    bsman->consumer_predicate_decoded_addr = predicate_global;
    if (
            (_lw(target) & 0xFFFF0000) != 0x3C020000 ||
            (_lw(target + 4) & 0xFFFF0000) != 0x8C440000 ||
            predicate_global != slide_diag.vsh_shared_global_addr ||
            _lw(target + 8) != 0x2483FFFC ||
            _lw(target + 12) != 0x38820007 ||
            _lw(target + 16) != 0x2C630002 ||
            _lw(target + 20) != 0x2C420001 ||
            _lw(target + 24) != 0x00621825 ||
            _lw(target + 28) != 0x14600006 ||
            _lw(target + 32) != 0x00002821 ||
            _lw(target + 36) != 0x24020009 ||
            _lw(target + 40) != 0x50820001 ||
            _lw(target + 44) != 0x24050001 ||
            _lw(target + 48) != 0x03E00008 ||
            _lw(target + 52) != 0x30A200FF ||
            (_lw(target + 56) >> 26) != 2 ||
            zeroCtrlMipsJumpTarget(target + 56, _lw(target + 56)) !=
                target + 48 ||
            _lw(target + 60) != 0x24050001) {
        static const unsigned int expected[16] = {
            0x3C020000, 0x8C440000, 0x2483FFFC, 0x38820007,
            0x2C630002, 0x2C420001, 0x00621825, 0x14600006,
            0x00002821, 0x24020009, 0x50820001, 0x24050001,
            0x03E00008, 0x30A200FF, 0, 0x24050001 };
        for (i = 0; i < 16; i++) {
            unsigned int actual = bsman->consumer_predicate_words[i];
            unsigned int wanted = expected[i];
            int match = i == 0 ? (actual & 0xFFFF0000) == wanted :
                    (i == 1 ? ((actual & 0xFFFF0000) == wanted &&
                    predicate_global == slide_diag.vsh_shared_global_addr) :
                    (i == 14 ? ((actual >> 26) == 2 &&
                    zeroCtrlMipsJumpTarget(target + 56, actual) == target + 48) :
                    actual == wanted));
            if (!match) {
                if (i == 14) wanted = 0x08000000 |
                        (((target + 48) >> 2) & 0x03FFFFFF);
                bsman->consumer_predicate_first_bad = i;
                bsman->consumer_predicate_actual = actual;
                bsman->consumer_predicate_expected = wanted;
                break;
            }
        }
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_PREDICATE_FINGERPRINT_MISMATCH);
    }
    bsman->consumer_predicate_validation = 1;
    for (i = 0; i < 2; i++) {
        callsite[i] = vsh->text_addr + offsets[i];
        if (!zeroCtrlVshModuleRangeValid(vsh, callsite[i], 8))
            CONSUMER_GUARD_FAIL(range_reasons[i]);
        bsman->consumer_callsite_words[i][0] = _lw(callsite[i]);
        bsman->consumer_callsite_words[i][1] = _lw(callsite[i] + 4);
        bsman->consumer_leaf_range_valid[i] = zeroCtrlVshModuleRangeValid(
                helper, bsman->consumer_leaf_addr[i], bsman->consumer_leaf_size[i]);
        if (!bsman->consumer_leaf_range_valid[i])
            CONSUMER_GUARD_FAIL(helper_reasons[i]);
        bsman->consumer_counter_range_valid[i] = zeroCtrlVshModuleRangeValid(
                helper, bsman->consumer_hits_addr[i], 4);
        if (!bsman->consumer_counter_range_valid[i])
            CONSUMER_GUARD_FAIL(counter_reasons[i]);
        if (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->consumer_result_addr[i], 4))
            CONSUMER_GUARD_FAIL(result_reasons[i]);
        if ((bsman->consumer_callsite_words[i][0] >> 26) != 3)
            CONSUMER_GUARD_FAIL(jal_reasons[i]);
        bsman->consumer_callsite_target[i] = zeroCtrlMipsJumpTarget(
                callsite[i], bsman->consumer_callsite_words[i][0]);
        if (bsman->consumer_callsite_target[i] != target)
            CONSUMER_GUARD_FAIL(target_reasons[i]);
        if (bsman->consumer_callsite_words[i][1] != delays[i])
            CONSUMER_GUARD_FAIL(delay_reasons[i]);
        if (((callsite[i] + 4) & 0xF0000000) !=
                (bsman->consumer_leaf_addr[i] & 0xF0000000))
            CONSUMER_GUARD_FAIL(region_reasons[i]);
        replacement[i] = 0x0C000000 |
                ((bsman->consumer_leaf_addr[i] >> 2) & 0x03FFFFFF);
        if (zeroCtrlMipsJumpTarget(callsite[i], replacement[i]) !=
                bsman->consumer_leaf_addr[i])
            CONSUMER_GUARD_FAIL(
                    ZERO_CONSUMER_GUARD_REPLACEMENT_TARGET_MISMATCH);
    }
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_14020_compat_mode_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_14020_COMPAT_MODE_RANGE_INVALID);
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_14020_effective_result_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_14020_EFFECTIVE_RESULT_RANGE_INVALID);
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_14020_substitution_hits_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_14020_SUBSTITUTION_HITS_RANGE_INVALID);
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_13f6c_compat_mode_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_13F6C_COMPAT_MODE_RANGE_INVALID);
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_13f6c_effective_result_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_13F6C_EFFECTIVE_RESULT_RANGE_INVALID);
    if (!zeroCtrlVshModuleRangeValid(helper,
                bsman->consumer_13f6c_substitution_hits_addr, 4))
        CONSUMER_GUARD_FAIL(
                ZERO_CONSUMER_GUARD_CALLSITE_13F6C_SUBSTITUTION_HITS_RANGE_INVALID);
    bsman->consumer_guard_reason = ZERO_CONSUMER_GUARD_NONE;
    for (i = 0; i < 2; i++) bsman->consumer_validation[i] = 1;
    _sw(target, bsman->consumer_target_addr);
    for (i = 0; i < 2; i++) _sw(0, bsman->consumer_hits_addr[i]);
    for (i = 0; i < 2; i++) _sw(0xFFFFFFFF, bsman->consumer_result_addr[i]);
    _sw(bsman->consumer_14020_compat_enabled ? 1 : 0,
            bsman->consumer_14020_compat_mode_addr);
    _sw(0xFFFFFFFF, bsman->consumer_14020_effective_result_addr);
    _sw(0, bsman->consumer_14020_substitution_hits_addr);
    _sw(bsman->consumer_13f6c_compat_enabled ? 1 : 0,
            bsman->consumer_13f6c_compat_mode_addr);
    _sw(0xFFFFFFFF, bsman->consumer_13f6c_effective_result_addr);
    _sw(0, bsman->consumer_13f6c_substitution_hits_addr);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_target_addr, 4);
    for (i = 0; i < 2; i++)
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->consumer_hits_addr[i], 4);
    for (i = 0; i < 2; i++)
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->consumer_result_addr[i], 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_14020_compat_mode_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_14020_effective_result_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_14020_substitution_hits_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_13f6c_compat_mode_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_13f6c_effective_result_addr, 4);
    sceKernelDcacheWritebackInvalidateRange(
            (const void *)bsman->consumer_13f6c_substitution_hits_addr, 4);
    bsman->shared_global_early_valid = 1;
    bsman->shared_global_early_value = _lw(slide_diag.vsh_shared_global_addr);
    for (i = 0; i < 2; i++) {
        _sw(replacement[i], callsite[i]);
        sceKernelDcacheWritebackInvalidateRange((const void *)callsite[i], 4);
        sceKernelIcacheInvalidateRange((const void *)callsite[i], 4);
        bsman->consumer_install[i] = 1;
        bsman->consumer_cache_sync[i] = 1;
    }
#undef CONSUMER_GUARD_FAIL
}

static void zeroCtrlInstallBSManClosedShim(SceModule2 *mod) {
    const unsigned int target_nid = 0x23E3A9B6;
    static const char paf_library[] = "scePaf";
    static const char vshbridge_library[] = "sceVshBridge";
    ZeroCtrlBSManEvidence *bsman = &slide_diag.bsman;
    unsigned int cursor, end, offset, snapshot_index;
    unsigned int caller_matches = 0, paf_matches = 0;
    unsigned int post_paf_matches = 0, vshbridge_matches = 0;
    unsigned int prefix_paf_stub = 0, post_paf_stub = 0, vshbridge_stub = 0;

    if ((!bsman->enabled && !bsman->activation_enabled) ||
            !bsman->registered || model != 0 || !mod ||
            strcmp(mod->modname, "slide_plugin_module") != 0 ||
            sceKernelDevkitVersion() != 0x06060110) return;
    for (snapshot_index = 0; snapshot_index < 5; snapshot_index++)
        bsman->dispatch_entry_pre_slide[snapshot_index] =
                zeroCtrlReadHelperCounter(
                    bsman->dispatch_entry_scalar_addr[snapshot_index]);
    bsman->dispatch_entry_pre_slide_captured = 1;
    bsman->consumer_pre_slide_hits[0] =
            zeroCtrlReadHelperCounter(bsman->consumer_hits_addr[0]);
    bsman->consumer_pre_slide_hits[1] =
            zeroCtrlReadHelperCounter(bsman->consumer_hits_addr[1]);
    bsman->consumer_pre_slide_result[0] =
            zeroCtrlReadHelperCounter(bsman->consumer_result_addr[0]);
    bsman->consumer_pre_slide_result[1] =
            zeroCtrlReadHelperCounter(bsman->consumer_result_addr[1]);
    bsman->consumer_14020_pre_slide_effective = zeroCtrlReadHelperCounter(
            bsman->consumer_14020_effective_result_addr);
    bsman->consumer_14020_pre_slide_substitutions = zeroCtrlReadHelperCounter(
            bsman->consumer_14020_substitution_hits_addr);
    bsman->consumer_13f6c_pre_slide_effective = zeroCtrlReadHelperCounter(
            bsman->consumer_13f6c_effective_result_addr);
    bsman->consumer_13f6c_pre_slide_substitutions = zeroCtrlReadHelperCounter(
            bsman->consumer_13f6c_substitution_hits_addr);
    for (snapshot_index = 0; snapshot_index < 3; snapshot_index++) {
        bsman->capability_hits[snapshot_index] = zeroCtrlReadHelperCounter(
                bsman->capability_hits_addr[snapshot_index]);
        bsman->capability_result[snapshot_index] = zeroCtrlReadHelperCounter(
                bsman->capability_result_addr[snapshot_index]);
    }
    bsman->paf_mask_hits = zeroCtrlReadHelperCounter(bsman->paf_mask_hits_addr);
    bsman->paf_mask_natural = zeroCtrlReadHelperCounter(bsman->paf_mask_natural_addr);
    bsman->paf_mask_effective = zeroCtrlReadHelperCounter(bsman->paf_mask_effective_addr);
    bsman->paf_mask_substitutions = zeroCtrlReadHelperCounter(
            bsman->paf_mask_substitution_hits_addr);
    bsman->capability_captured = 1;
    {
        SceModule2 *vsh = sceKernelFindModuleByName("vsh_module");
        if (bsman->shared_global_early_valid && vsh &&
                zeroCtrlVshModuleRangeValid(vsh,
                    slide_diag.vsh_shared_global_addr, 4)) {
            bsman->shared_global_pre_slide_valid = 1;
            bsman->shared_global_pre_slide_value =
                    _lw(slide_diag.vsh_shared_global_addr);
        }
    }
    bsman->consumer_pre_slide_captured = 1;
    zeroCtrlInstallField12CWriteTrace();
    zeroCtrlInstallCase14Trace();
    zeroCtrlInstallDispatchEntryTrace();
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
        if (zeroCtrlLibraryNameEquals(mod, table->libname, paf_library,
                    sizeof(paf_library))) {
            if (!zeroCtrlVshModuleRangeValid(mod, (unsigned int)table->nidtable,
                        (unsigned int)table->stubcount * 4) ||
                    !zeroCtrlVshModuleRangeValid(mod,
                        (unsigned int)table->stubtable,
                        (unsigned int)table->stubcount * 8)) return;
            for (i = 0; i < table->stubcount; i++) {
                if (table->nidtable[i] != 0xED83BBCF) continue;
                prefix_paf_stub = (unsigned int)table->stubtable + i * 8;
                paf_matches++;
            }
        }
        if (zeroCtrlLibraryNameEquals(mod, table->libname, paf_library,
                    sizeof(paf_library))) {
            for (i = 0; i < table->stubcount; i++) {
                if (table->nidtable[i] != 0xFF03BCD5) continue;
                post_paf_stub = (unsigned int)table->stubtable + i * 8;
                post_paf_matches++;
            }
        }
        if (zeroCtrlLibraryNameEquals(mod, table->libname, vshbridge_library,
                    sizeof(vshbridge_library))) {
            if (!zeroCtrlVshModuleRangeValid(mod, (unsigned int)table->nidtable,
                        (unsigned int)table->stubcount * 4) ||
                    !zeroCtrlVshModuleRangeValid(mod,
                        (unsigned int)table->stubtable,
                        (unsigned int)table->stubcount * 8)) return;
            for (i = 0; i < table->stubcount; i++) {
                if (table->nidtable[i] != 0x639C3CB3) continue;
                vshbridge_stub = (unsigned int)table->stubtable + i * 8;
                vshbridge_matches++;
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

    if (bsman->activation_enabled) {
        unsigned int scan_start = bsman->caller_addr > mod->text_addr + 0x200 ?
                bsman->caller_addr - 0x200 : mod->text_addr;
        unsigned int pc;
        unsigned int candidates = 0;
        SceModule2 *helper = sceKernelFindModuleByName("ZeroVSH_Patcher_User");
        for (pc = scan_start; pc + 20 <= bsman->caller_addr; pc += 4) {
            if (_lw(pc) == 0x27BDFFE0 && _lw(pc + 4) == 0xAFB10004 &&
                    _lw(pc + 8) == 0x00808821 &&
                    _lw(pc + 12) == 0xAFB00000 &&
                    _lw(pc + 16) == 0xAFBF001C) {
                bsman->activation_addr = pc;
                candidates++;
            }
        }
        if (candidates != 1 || !helper ||
                !zeroCtrlVshModuleRangeValid(mod, bsman->activation_addr, 0x2DC) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->activation_leaf_addr,
                    bsman->activation_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->call_leaf_addr,
                    bsman->call_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->return_leaf_addr,
                    bsman->return_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->prefix_result_leaf_addr,
                    bsman->prefix_result_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->prefix_flag_leaf_addr,
                    bsman->prefix_flag_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->prefix_mask_leaf_addr,
                    bsman->prefix_mask_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->prefix_paf_call_leaf_addr,
                    bsman->prefix_paf_call_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->prefix_paf_return_leaf_addr,
                    bsman->prefix_paf_return_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->post_bs_leaf_addr,
                    bsman->post_bs_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper, bsman->post_state_leaf_addr,
                    bsman->post_state_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_paf_call_leaf_addr,
                    bsman->post_paf_call_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_paf_return_leaf_addr,
                    bsman->post_paf_return_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_vsh_call_leaf_addr,
                    bsman->post_vsh_call_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_vsh_return_leaf_addr,
                    bsman->post_vsh_return_leaf_size) ||
                (bsman->return_leaf_addr & 3) != 0 ||
                ((bsman->activation_addr + 4) & 0xF0000000) !=
                    (bsman->activation_leaf_addr & 0xF0000000) ||
                ((bsman->caller_addr + 4) & 0xF0000000) !=
                    (bsman->call_leaf_addr & 0xF0000000)) return;
        for (pc = 0; pc < 8; pc++)
            if (!zeroCtrlVshModuleRangeValid(helper,
                        bsman->state_zero_leaf_addr[pc],
                        bsman->state_zero_leaf_size[pc])) return;
        if (bsman->post_impose_vcall_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_impose_vcall_leaf_addr,
                    bsman->post_impose_vcall_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_impose_vcall_return_leaf_addr,
                    bsman->post_impose_vcall_return_leaf_size) ||
                ((bsman->activation_addr + 0x124) & 0xF0000000) !=
                    (bsman->post_impose_vcall_leaf_addr & 0xF0000000))) return;
        if (bsman->post_minus_one_vcall64_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_minus_one_vcall64_leaf_addr,
                    bsman->post_minus_one_vcall64_leaf_size) ||
                !zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_minus_one_vcall64_return_leaf_addr,
                    bsman->post_minus_one_vcall64_return_leaf_size) ||
                ((bsman->activation_addr + 0x13C) & 0xF0000000) !=
                    (bsman->post_minus_one_vcall64_leaf_addr & 0xF0000000))) return;
        if (bsman->collection_paf_fcf265d8_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->collection_paf_fcf265d8_leaf_addr,
                    bsman->collection_paf_fcf265d8_leaf_size) ||
                ((bsman->activation_addr + 0x174) & 0xF0000000) !=
                    (bsman->collection_paf_fcf265d8_leaf_addr & 0xF0000000))) return;
        if (bsman->collection_paf_9a285882_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->collection_paf_9a285882_leaf_addr,
                    bsman->collection_paf_9a285882_leaf_size) ||
                ((bsman->activation_addr + 0x184) & 0xF0000000) !=
                    (bsman->collection_paf_9a285882_leaf_addr & 0xF0000000))) return;
        bsman->activation_original[0] = _lw(bsman->activation_addr);
        bsman->activation_original[1] = _lw(bsman->activation_addr + 4);
        bsman->call_original = _lw(bsman->caller_addr);
        bsman->prefix_original[0] = _lw(bsman->activation_addr + 0x34);
        bsman->prefix_original[1] = _lw(bsman->activation_addr + 0x38);
        bsman->prefix_original[2] = _lw(bsman->activation_addr + 0x44);
        bsman->prefix_original[3] = _lw(bsman->activation_addr + 0x48);
        bsman->prefix_original[4] = _lw(bsman->activation_addr + 0x94);
        bsman->prefix_original[5] = _lw(bsman->activation_addr + 0x98);
        bsman->prefix_original[6] = _lw(bsman->activation_addr + 0x2C);
        bsman->prefix_original[7] = _lw(bsman->activation_addr + 0x30);
        bsman->post_original[0] = _lw(bsman->activation_addr + 0xB0);
        bsman->post_original[1] = _lw(bsman->activation_addr + 0xB4);
        bsman->post_original[2] = _lw(bsman->activation_addr + 0xDC);
        bsman->post_original[3] = _lw(bsman->activation_addr + 0xE0);
        bsman->post_original[4] = _lw(bsman->activation_addr + 0xE8);
        bsman->post_original[5] = _lw(bsman->activation_addr + 0xEC);
        bsman->post_original[6] = _lw(bsman->activation_addr + 0xF8);
        bsman->post_original[7] = _lw(bsman->activation_addr + 0xFC);
        bsman->post_original[8] = _lw(bsman->activation_addr + 0x10C);
        bsman->post_original[9] = _lw(bsman->activation_addr + 0x110);
        bsman->post_original[10] = _lw(bsman->activation_addr + 0x114);
        bsman->post_original[11] = _lw(bsman->activation_addr + 0x118);
        bsman->post_impose_vcall_original[0] =
                _lw(bsman->activation_addr + 0x120);
        bsman->post_impose_vcall_original[1] =
                _lw(bsman->activation_addr + 0x124);
        bsman->post_impose_vcall_replacement = 0x0C000000 |
                ((bsman->post_impose_vcall_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_minus_one_vcall64_original[0] =
                _lw(bsman->activation_addr + 0x138);
        bsman->post_minus_one_vcall64_original[1] =
                _lw(bsman->activation_addr + 0x13C);
        bsman->post_minus_one_vcall64_replacement = 0x0C000000 |
                ((bsman->post_minus_one_vcall64_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->collection_paf_fcf265d8_original[0] =
                _lw(bsman->activation_addr + 0x170);
        bsman->collection_paf_fcf265d8_original[1] =
                _lw(bsman->activation_addr + 0x174);
        bsman->collection_paf_fcf265d8_replacement = 0x0C000000 |
                ((bsman->collection_paf_fcf265d8_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->collection_paf_9a285882_original[0] = _lw(bsman->activation_addr + 0x180);
        bsman->collection_paf_9a285882_original[1] = _lw(bsman->activation_addr + 0x184);
        bsman->collection_paf_9a285882_replacement = 0x08000000 |
                ((bsman->collection_paf_9a285882_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_collection_paf_fcf265d8_original[0] = _lw(bsman->activation_addr + 0x198);
        bsman->post_collection_paf_fcf265d8_original[1] = _lw(bsman->activation_addr + 0x19C);
        bsman->post_collection_paf_fcf265d8_original[2] = _lw(bsman->activation_addr + 0x1A0);
        bsman->post_collection_paf_fcf265d8_original[3] = _lw(bsman->activation_addr + 0x1A4);
        bsman->post_collection_paf_fcf265d8_original[4] = _lw(bsman->activation_addr + 0x1A8);
        bsman->post_collection_paf_fcf265d8_replacement = 0x08000000 |
                ((bsman->post_collection_paf_fcf265d8_leaf_addr >> 2) & 0x03FFFFFF);
        if (bsman->post_collection_paf_fcf265d8_enabled) {
            unsigned int fail_mask = 0;
            int arg_lo = (short)(
                    bsman->post_collection_paf_fcf265d8_original[2] & 0xFFFF);
            bsman->post_collection_paf_fcf265d8_guard_checked = 1;
            bsman->post_collection_paf_fcf265d8_decoded_call_target =
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x19C,
                        bsman->post_collection_paf_fcf265d8_original[1]);
            bsman->post_collection_paf_fcf265d8_expected_call_target =
                    mod->text_addr + 0x2A698;
            bsman->post_collection_paf_fcf265d8_decoded_replacement_target =
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1A4,
                        bsman->post_collection_paf_fcf265d8_replacement);
            bsman->post_collection_paf_fcf265d8_observed_arg_target =
                    ((bsman->post_collection_paf_fcf265d8_original[0] & 0xFFFF)
                        << 16) + arg_lo;
            bsman->post_collection_paf_fcf265d8_expected_arg_target =
                    mod->nsegment >= 2 ? mod->segmentaddr[1] + 0x0DC4 : 0;
            if ((bsman->post_collection_paf_fcf265d8_original[0] & 0xFFFF0000) !=
                    0x3C020000) fail_mask |= T37_FAIL_LUI_SHAPE;
            if ((bsman->post_collection_paf_fcf265d8_original[1] >> 26) != 3)
                fail_mask |= T37_FAIL_CALL_OPCODE;
            if (bsman->post_collection_paf_fcf265d8_decoded_call_target !=
                    bsman->post_collection_paf_fcf265d8_expected_call_target)
                fail_mask |= T37_FAIL_CALL_TARGET;
            if ((bsman->post_collection_paf_fcf265d8_original[2] & 0xFFFF0000) !=
                    0x8C440000)
                fail_mask |= T37_FAIL_ARG_LOAD_WORD;
            if (mod->nsegment < 2)
                fail_mask |= T37_FAIL_SEGMENT1_MISSING;
            else if (bsman->post_collection_paf_fcf265d8_observed_arg_target !=
                    bsman->post_collection_paf_fcf265d8_expected_arg_target)
                fail_mask |= T37_FAIL_ARG_LOAD_TARGET;
            if (bsman->post_collection_paf_fcf265d8_original[3] != 0x1440FFAA)
                fail_mask |= T37_FAIL_DECISION_WORD;
            if (bsman->post_collection_paf_fcf265d8_original[4] != 0x8FBF001C)
                fail_mask |= T37_FAIL_RA_DELAY_WORD;
            if ((bsman->post_collection_paf_fcf265d8_replacement >> 26) != 2)
                fail_mask |= T37_FAIL_REPLACEMENT_OPCODE;
            if (bsman->post_collection_paf_fcf265d8_decoded_replacement_target !=
                    bsman->post_collection_paf_fcf265d8_leaf_addr)
                fail_mask |= T37_FAIL_REPLACEMENT_TARGET;
            if (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->post_collection_paf_fcf265d8_leaf_addr,
                    bsman->post_collection_paf_fcf265d8_leaf_size))
                fail_mask |= T37_FAIL_HELPER_RANGE;
            if (((bsman->activation_addr + 0x1A8) & 0xF0000000) !=
                    (bsman->post_collection_paf_fcf265d8_leaf_addr & 0xF0000000))
                fail_mask |= T37_FAIL_PSEUDODIRECT_REGION;
            bsman->post_collection_paf_fcf265d8_fail_mask = fail_mask;
            if (fail_mask != 0) return;
        }
        if (bsman->masked_paf_c59fc3d0_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->masked_paf_c59fc3d0_leaf_addr,
                    bsman->masked_paf_c59fc3d0_leaf_size) ||
                ((bsman->activation_addr + 0x1C4) & 0xF0000000) !=
                    (bsman->masked_paf_c59fc3d0_leaf_addr & 0xF0000000))) return;
        if (bsman->masked_paf_c59fc3d0_enabled) {
            static const unsigned int masked_paf_offsets[7] = {
                0x1AC, 0x1B0, 0x1B4, 0x1B8, 0x1BC, 0x1C0, 0x1C4
            };
            for (pc = 0; pc < 7; pc++)
                bsman->masked_paf_c59fc3d0_original[pc] =
                        _lw(bsman->activation_addr + masked_paf_offsets[pc]);
            bsman->masked_paf_c59fc3d0_replacement = 0x08000000 |
                    ((bsman->masked_paf_c59fc3d0_leaf_addr >> 2) & 0x03FFFFFF);
            if (bsman->masked_paf_c59fc3d0_original[0] != 0x3C050300 ||
                    bsman->masked_paf_c59fc3d0_original[1] != 0x02202021 ||
                    (bsman->masked_paf_c59fc3d0_original[2] >> 26) != 3 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1B4,
                        bsman->masked_paf_c59fc3d0_original[2]) !=
                            mod->text_addr + 0x2A558 ||
                    bsman->masked_paf_c59fc3d0_original[3] != 0x34A50002 ||
                    bsman->masked_paf_c59fc3d0_original[4] != 0x304200FF ||
                    bsman->masked_paf_c59fc3d0_original[5] != 0x1440FFA3 ||
                    bsman->masked_paf_c59fc3d0_original[6] != 0x8FBF001C ||
                    (bsman->masked_paf_c59fc3d0_replacement >> 26) != 2 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1C0,
                        bsman->masked_paf_c59fc3d0_replacement) !=
                            bsman->masked_paf_c59fc3d0_leaf_addr) return;
            bsman->masked_paf_c59fc3d0_validation = 1;
        }
        if (bsman->masked_paf_c59fc3d0_second_enabled &&
                (!zeroCtrlVshModuleRangeValid(helper,
                    bsman->masked_paf_c59fc3d0_second_leaf_addr,
                    bsman->masked_paf_c59fc3d0_second_leaf_size) ||
                ((bsman->activation_addr + 0x1E4) & 0xF0000000) !=
                    (bsman->masked_paf_c59fc3d0_second_leaf_addr & 0xF0000000))) return;
        if (bsman->masked_paf_c59fc3d0_second_enabled) {
            static const unsigned int masked_paf_second_offsets[8] = {
                0x1C8, 0x1CC, 0x1D0, 0x1D4, 0x1D8, 0x1DC, 0x1E0, 0x1E4
            };
            unsigned int observed_arg_target;
            unsigned int expected_arg_target;
            int arg_lo;
            for (pc = 0; pc < 8; pc++)
                bsman->masked_paf_c59fc3d0_second_original[pc] =
                        _lw(bsman->activation_addr +
                            masked_paf_second_offsets[pc]);
            arg_lo = (short)(bsman->masked_paf_c59fc3d0_second_original[1] &
                    0xFFFF);
            observed_arg_target =
                    ((bsman->masked_paf_c59fc3d0_second_original[0] & 0xFFFF)
                        << 16) + arg_lo;
            expected_arg_target = mod->nsegment >= 2 ?
                    mod->segmentaddr[1] + 0x0DC0 : 0;
            bsman->masked_paf_c59fc3d0_second_replacement = 0x08000000 |
                    ((bsman->masked_paf_c59fc3d0_second_leaf_addr >> 2) &
                        0x03FFFFFF);
            if ((bsman->masked_paf_c59fc3d0_second_original[0] & 0xFFFF0000) !=
                        0x3C020000 ||
                    (bsman->masked_paf_c59fc3d0_second_original[1] &
                        0xFFFF0000) != 0x8C440000 ||
                    mod->nsegment < 2 || observed_arg_target != expected_arg_target ||
                    bsman->masked_paf_c59fc3d0_second_original[2] != 0x3C050100 ||
                    (bsman->masked_paf_c59fc3d0_second_original[3] >> 26) != 3 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1D4,
                        bsman->masked_paf_c59fc3d0_second_original[3]) !=
                            mod->text_addr + 0x2A558 ||
                    bsman->masked_paf_c59fc3d0_second_original[4] != 0x34A50011 ||
                    bsman->masked_paf_c59fc3d0_second_original[5] != 0x304200FF ||
                    bsman->masked_paf_c59fc3d0_second_original[6] != 0x1440FF9A ||
                    bsman->masked_paf_c59fc3d0_second_original[7] != 0x00008021 ||
                    (bsman->masked_paf_c59fc3d0_second_replacement >> 26) != 2 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1E0,
                        bsman->masked_paf_c59fc3d0_second_replacement) !=
                            bsman->masked_paf_c59fc3d0_second_leaf_addr) return;
            bsman->masked_paf_c59fc3d0_second_validation = 1;
        }
        if (bsman->activation_wide_enabled) {
            static const unsigned int wide_offset[6] = {
                0x1F8, 0x200, 0x20C, 0x214, 0x21C, 0x22C
            };
            static const unsigned int wide_word[6] = {
                0x1040000C, 0, 0, 0, 0x1040FFF2, 0
            };
            static const unsigned int wide_helper[6] = { 0, 1, 3, 5, 7, 8 };
            unsigned int wide_index;
            for (wide_index = 0; wide_index < 11; wide_index++)
                if (!zeroCtrlVshModuleRangeValid(helper,
                        bsman->activation_wide_leaf_addr[wide_index],
                        bsman->activation_wide_leaf_size[wide_index])) return;
            for (wide_index = 0; wide_index < 6; wide_index++) {
                unsigned int site = bsman->activation_addr + wide_offset[wide_index];
                bsman->activation_wide_original[wide_index] = _lw(site);
                bsman->activation_wide_replacement[wide_index] = 0x08000000 |
                        ((bsman->activation_wide_leaf_addr[
                            wide_helper[wide_index]] >> 2) & 0x03FFFFFF);
                if (((wide_index == 0 || wide_index == 4) &&
                            bsman->activation_wide_original[wide_index] !=
                                wide_word[wide_index]) ||
                        ((wide_index != 0 && wide_index != 4) &&
                            (bsman->activation_wide_original[wide_index] >> 26) != 3) ||
                        ((site + 4) & 0xF0000000) !=
                            (bsman->activation_wide_leaf_addr[
                                wide_helper[wide_index]] & 0xF0000000) ||
                        zeroCtrlMipsJumpTarget(site,
                            bsman->activation_wide_replacement[wide_index]) !=
                        bsman->activation_wide_leaf_addr[
                                wide_helper[wide_index]]) return;
            }
            bsman->activation_wide_pre_original =
                    _lw(bsman->activation_addr + 0x1E8);
            bsman->activation_wide_pre_replacement = 0x0C000000 |
                    ((bsman->activation_wide_leaf_addr[10] >> 2) & 0x03FFFFFF);
            if ((bsman->activation_wide_pre_original >> 26) != 3 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1E8,
                        bsman->activation_wide_pre_original) !=
                            bsman->activation_addr - 0x9304 + 0x2A168 ||
                    _lw(bsman->activation_addr + 0x1EC) != 0 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1E8,
                        bsman->activation_wide_pre_replacement) !=
                            bsman->activation_wide_leaf_addr[10] ||
                    ((bsman->activation_addr + 0x1F0) & 0xF0000000) !=
                        (bsman->activation_wide_leaf_addr[10] & 0xF0000000) ||
                    zeroCtrlMipsBranchTarget(bsman->activation_addr + 0x1F8,
                        bsman->activation_wide_original[0]) !=
                            bsman->activation_addr + 0x22C ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x200,
                        bsman->activation_wide_original[1]) !=
                            bsman->activation_addr - 0x9304 + 0x2A380 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x20C,
                        bsman->activation_wide_original[2]) !=
                            bsman->activation_addr - 0x9304 + 0x2A290 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x214,
                        bsman->activation_wide_original[3]) !=
                            bsman->activation_addr - 0x9304 + 0x2A698 ||
                    zeroCtrlMipsBranchTarget(bsman->activation_addr + 0x21C,
                        bsman->activation_wide_original[4]) !=
                            bsman->activation_addr + 0x1E8 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x22C,
                        bsman->activation_wide_original[5]) !=
                            bsman->activation_addr - 0x9304 + 0x2A6F8 ||
                    _lw(bsman->activation_addr + 0x1FC) != 0x26100001 ||
                    _lw(bsman->activation_addr + 0x204) != 0 ||
                    _lw(bsman->activation_addr + 0x210) != 0x00002821 ||
                    _lw(bsman->activation_addr + 0x218) != 0x00402021 ||
                    _lw(bsman->activation_addr + 0x220) != 0x8FBF001C ||
                    _lw(bsman->activation_addr + 0x230) != 0x00002021) return;
            bsman->activation_wide_validation = 1;
        }
        for (pc = 0; pc < 7; pc++) {
            static const unsigned int site_offset[7] = {
                0x27C, 0x288, 0x298, 0x2A4, 0x2B4, 0x2BC, 0x2C8
            };
            bsman->state_zero_original[pc * 2] =
                    _lw(bsman->activation_addr + site_offset[pc]);
            bsman->state_zero_original[pc * 2 + 1] =
                    _lw(bsman->activation_addr + site_offset[pc] + 4);
            bsman->state_zero_replacement[pc] =
                    (pc == 3 ? 0x0C000000 : 0x08000000) |
                    ((bsman->state_zero_leaf_addr[pc < 4 ? pc : pc + 1] >> 2) &
                        0x03FFFFFF);
        }
        bsman->activation_replacement[0] = 0x08000000 |
                ((bsman->activation_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->activation_replacement[1] = 0;
        bsman->call_replacement = 0x0C000000 |
                ((bsman->call_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->prefix_replacement[0] = 0x08000000 |
                ((bsman->prefix_result_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->prefix_replacement[1] = 0x08000000 |
                ((bsman->prefix_flag_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->prefix_replacement[2] = 0x08000000 |
                ((bsman->prefix_mask_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->prefix_replacement[3] = 0x0C000000 |
                ((bsman->prefix_paf_call_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_replacement[0] = 0x08000000 |
                ((bsman->post_bs_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_replacement[1] = 0x08000000 |
                ((bsman->post_state_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_replacement[2] = 0x0C000000 |
                ((bsman->post_paf_call_leaf_addr >> 2) & 0x03FFFFFF);
        bsman->post_replacement[3] = bsman->post_replacement[2];
        bsman->post_replacement[4] = 0x0C000000 |
                ((bsman->post_vsh_call_leaf_addr >> 2) & 0x03FFFFFF);
        if (zeroCtrlMipsJumpTarget(bsman->activation_addr,
                    bsman->activation_replacement[0]) !=
                        bsman->activation_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->caller_addr,
                    bsman->call_replacement) != bsman->call_leaf_addr ||
                bsman->caller_addr != bsman->activation_addr + 0xA8 ||
                bsman->prefix_original[0] != 0x10400006 ||
                bsman->prefix_original[1] != 0x8FBF001C ||
                bsman->prefix_original[2] != 0x1460000B ||
                bsman->prefix_original[3] != 0 ||
                bsman->prefix_original[4] != 0x10620090 ||
                (bsman->prefix_original[5] & 0xFFFF0000) != 0x3C020000 ||
                (bsman->prefix_original[6] >> 26) != 3 ||
                bsman->prefix_original[7] != 0x00408021 ||
                paf_matches != 1 ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x2C,
                    bsman->prefix_original[6]) != prefix_paf_stub ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x34,
                    bsman->prefix_replacement[0]) !=
                        bsman->prefix_result_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x44,
                    bsman->prefix_replacement[1]) !=
                        bsman->prefix_flag_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x94,
                    bsman->prefix_replacement[2]) !=
                        bsman->prefix_mask_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x2C,
                    bsman->prefix_replacement[3]) !=
                        bsman->prefix_paf_call_leaf_addr ||
                bsman->post_original[0] != 0x1040000A ||
                (bsman->post_original[1] & 0xFFFF0000) != 0x92620000 ||
                bsman->post_original[2] != 0x10400066 ||
                (bsman->post_original[3] & 0xFFFF0000) != 0x3C020000 ||
                (bsman->post_original[4] >> 26) != 3 ||
                bsman->post_original[5] != 0x00002021 ||
                (bsman->post_original[6] >> 26) != 3 ||
                bsman->post_original[7] != 0x24040001 ||
                _lw(bsman->activation_addr + 0x108) != 0x3C048000 ||
                (bsman->post_original[8] >> 26) != 3 ||
                bsman->post_original[9] != 0x3484000D ||
                bsman->post_original[10] != 0x1440FFCE ||
                bsman->post_original[11] != 0x8FBF001C ||
                (bsman->post_impose_vcall_enabled &&
                    (bsman->post_impose_vcall_original[0] != 0x0040F809 ||
                    bsman->post_impose_vcall_original[1] != 0 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x120,
                        bsman->post_impose_vcall_replacement) !=
                            bsman->post_impose_vcall_leaf_addr)) ||
                (bsman->post_minus_one_vcall64_enabled &&
                    (bsman->post_minus_one_vcall64_original[0] != 0x0040F809 ||
                    bsman->post_minus_one_vcall64_original[1] != 0x0000A021 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x138,
                        bsman->post_minus_one_vcall64_replacement) !=
                            bsman->post_minus_one_vcall64_leaf_addr)) ||
                (bsman->collection_paf_fcf265d8_enabled &&
                    (bsman->collection_paf_fcf265d8_original[0] != 0x1440FFB6 ||
                    bsman->collection_paf_fcf265d8_original[1] != 0x02002021 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x170,
                        bsman->collection_paf_fcf265d8_replacement) !=
                            bsman->collection_paf_fcf265d8_leaf_addr)) ||
                (bsman->collection_paf_9a285882_enabled &&
                    (bsman->collection_paf_9a285882_original[0] != 0x1440FFB3 ||
                    bsman->collection_paf_9a285882_original[1] != 0x8FBF001C ||
                    (bsman->collection_paf_9a285882_replacement >> 26) != 2 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x180,
                        bsman->collection_paf_9a285882_replacement) !=
                            bsman->collection_paf_9a285882_leaf_addr)) ||
                (bsman->post_collection_paf_fcf265d8_enabled &&
                    ((bsman->post_collection_paf_fcf265d8_original[0] & 0xFFFF0000) != 0x3C020000 ||
                    (bsman->post_collection_paf_fcf265d8_original[1] >> 26) != 3 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x19C,
                        bsman->post_collection_paf_fcf265d8_original[1]) !=
                            mod->text_addr + 0x2A698 ||
                    (bsman->post_collection_paf_fcf265d8_original[2] & 0xFFFF0000) != 0x8C440000 ||
                    mod->nsegment < 2 ||
                    bsman->post_collection_paf_fcf265d8_observed_arg_target !=
                        bsman->post_collection_paf_fcf265d8_expected_arg_target ||
                    bsman->post_collection_paf_fcf265d8_original[3] != 0x1440FFAA ||
                    bsman->post_collection_paf_fcf265d8_original[4] != 0x8FBF001C ||
                    (bsman->post_collection_paf_fcf265d8_replacement >> 26) != 2 ||
                    zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x1A4,
                        bsman->post_collection_paf_fcf265d8_replacement) !=
                            bsman->post_collection_paf_fcf265d8_leaf_addr)) ||
                bsman->state_zero_original[0] != 0x1243FF73 ||
                (bsman->state_zero_original[1] & 0xFFFF0000) != 0x3C020000 ||
                bsman->state_zero_original[2] != 0x1460FF71 ||
                bsman->state_zero_original[3] != 0x8FBF001C ||
                bsman->state_zero_original[4] != 0x1460FF6E ||
                bsman->state_zero_original[5] != 0x8FB60018 ||
                bsman->state_zero_original[6] != 0x0040F809 ||
                bsman->state_zero_original[7] != 0 ||
                bsman->state_zero_original[8] != 0x1440FF8C ||
                bsman->state_zero_original[9] != 0x28620011 ||
                bsman->state_zero_original[10] != 0x1440FF64 ||
                bsman->state_zero_original[11] != 0x8FBF001C ||
                bsman->state_zero_original[12] != 0x1462FF87 ||
                bsman->state_zero_original[13] != 0x8FB60018 ||
                post_paf_matches != 1 || vshbridge_matches != 1 ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xE8,
                    bsman->post_original[4]) != post_paf_stub ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xF8,
                    bsman->post_original[6]) != post_paf_stub ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x10C,
                    bsman->post_original[8]) != vshbridge_stub ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xB0,
                    bsman->post_replacement[0]) != bsman->post_bs_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xDC,
                    bsman->post_replacement[1]) != bsman->post_state_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xE8,
                    bsman->post_replacement[2]) !=
                        bsman->post_paf_call_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0xF8,
                    bsman->post_replacement[3]) !=
                        bsman->post_paf_call_leaf_addr ||
                zeroCtrlMipsJumpTarget(bsman->activation_addr + 0x10C,
                    bsman->post_replacement[4]) !=
                        bsman->post_vsh_call_leaf_addr) return;
        if (bsman->post_impose_vcall_enabled)
            bsman->post_impose_vcall_validation = 1;
        if (bsman->post_minus_one_vcall64_enabled)
            bsman->post_minus_one_vcall64_validation = 1;
        if (bsman->collection_paf_fcf265d8_enabled)
            bsman->collection_paf_fcf265d8_validation = 1;
        if (bsman->collection_paf_9a285882_enabled)
            bsman->collection_paf_9a285882_validation = 1;
        if (bsman->post_collection_paf_fcf265d8_enabled)
            bsman->post_collection_paf_fcf265d8_validation = 1;
        for (pc = 0; pc < 7; pc++) {
            static const unsigned int site_offset[7] = {
                0x27C, 0x288, 0x298, 0x2A4, 0x2B4, 0x2BC, 0x2C8
            };
            unsigned int leaf_index = pc < 4 ? pc : pc + 1;
            if (zeroCtrlMipsJumpTarget(bsman->activation_addr + site_offset[pc],
                        bsman->state_zero_replacement[pc]) !=
                    bsman->state_zero_leaf_addr[leaf_index]) return;
        }
        bsman->activation_validation = 1;
        _sw(bsman->activation_addr + 8, bsman->activation_resume_addr);
        _sw(bsman->import_stub_addr, bsman->call_target_addr);
        _sw(0, bsman->activation_hits_addr);
        _sw(0, bsman->call_hits_addr);
        _sw(0, bsman->trace_stage_addr);
        _sw(0, bsman->call_ra_addr);
        _sw(bsman->activation_addr + 0x50, bsman->prefix_result_zero_addr);
        _sw(bsman->activation_addr + 0x3C, bsman->prefix_result_nonzero_addr);
        _sw(bsman->activation_addr + 0x4C, bsman->prefix_flag_zero_addr);
        _sw(bsman->activation_addr + 0x74, bsman->prefix_flag_nonzero_addr);
        _sw(bsman->activation_addr + 0x2D8, bsman->prefix_mask_equal_addr);
        _sw(bsman->activation_addr + 0x98, bsman->prefix_mask_unequal_addr);
        _sw((bsman->prefix_original[5] & 0xFFFF) << 16,
                bsman->prefix_mask_delay_value_addr);
        _sw(0, bsman->prefix_path_mask_addr);
        _sw(prefix_paf_stub, bsman->prefix_paf_target_addr);
        _sw(0, bsman->prefix_paf_ra_addr);
        _sw(bsman->paf_compat_enabled ? 1 : 0,
                bsman->prefix_paf_compat_mode_addr);
        _sw(0, bsman->prefix_paf_natural_result_addr);
        _sw(0, bsman->prefix_paf_substitution_hits_addr);
        _sw(0, bsman->prefix_paf_return_hits_addr);
        _sw(0, bsman->post_path_mask_addr);
        _sw(0, bsman->bsman_natural_result_addr);
        _sw(bsman->bsman_not_linked_compat_enabled ? 1 : 0,
                bsman->bsman_compat_mode_addr);
        _sw(0, bsman->bsman_substitution_hits_addr);
        _sw(0, bsman->bsman_effective_result_addr);
        _sw(0, bsman->bsman_return_hits_addr);
        _sw(bsman->activation_addr + 0xDC, bsman->post_bs_target_addr[0]);
        _sw(bsman->activation_addr + 0xB8, bsman->post_bs_target_addr[1]);
        _sw(0, bsman->post_bs_counter_addr[0]);
        _sw(0, bsman->post_bs_counter_addr[1]);
        _sw(bsman->activation_addr + 0x278, bsman->post_state_target_addr[0]);
        _sw(bsman->activation_addr + 0xE4, bsman->post_state_target_addr[1]);
        _sw(0, bsman->post_state_natural_value_addr);
        _sw(0, bsman->post_state_counter_addr[0]);
        _sw(0, bsman->post_state_counter_addr[1]);
        _sw(post_paf_stub, bsman->post_paf_target_addr);
        _sw(bsman->activation_addr + 0xF0, bsman->post_paf_call_ra_addr[0]);
        _sw(bsman->activation_addr + 0x100, bsman->post_paf_call_ra_addr[1]);
        _sw(0, bsman->post_paf_saved_ra_addr);
        _sw(0, bsman->post_paf_result_addr[0]);
        _sw(0, bsman->post_paf_result_addr[1]);
        _sw(0, bsman->post_paf_return_counter_addr[0]);
        _sw(0, bsman->post_paf_return_counter_addr[1]);
        _sw(vshbridge_stub, bsman->post_vsh_target_addr);
        _sw(0, bsman->post_vsh_saved_ra_addr);
        _sw(0, bsman->post_vsh_natural_result_addr);
        _sw(0, bsman->post_vsh_return_hits_addr);
        _sw(0xFFFFFFFF, bsman->post_vsh_argument_addr);
        _sw(bsman->post_vsh_compat_enabled ? 1 : 0,
                bsman->post_vsh_compat_mode_addr);
        _sw(0xFFFFFFFF, bsman->post_vsh_effective_result_addr);
        _sw(0, bsman->post_vsh_substitution_hits_addr);
        _sw(0, bsman->post_impose_vcall_target_addr);
        _sw(0, bsman->post_impose_vcall_saved_ra_addr);
        _sw(0xFFFFFFFF, bsman->post_impose_vcall_natural_result_addr);
        _sw(0, bsman->post_impose_vcall_hits_addr);
        _sw(0, bsman->post_impose_vcall_return_hits_addr);
        _sw(0, bsman->post_minus_one_vcall64_target_addr);
        _sw(0, bsman->post_minus_one_vcall64_saved_ra_addr);
        _sw(0xFFFFFFFF, bsman->post_minus_one_vcall64_natural_result_addr);
        _sw(0, bsman->post_minus_one_vcall64_hits_addr);
        _sw(0, bsman->post_minus_one_vcall64_return_hits_addr);
        _sw(bsman->post_vcall64_collection_enabled ? 1 : 0,
                bsman->post_minus_one_vcall64_collection_enabled_addr);
        _sw(0xFFFFFFFF, bsman->post_minus_one_vcall64_count_snapshot_addr);
        _sw(0, bsman->post_minus_one_vcall64_array_snapshot_addr);
        _sw(0, bsman->post_minus_one_vcall64_array_read_hits_addr);
        _sw(0, bsman->collection_paf_fcf265d8_last_item_addr);
        _sw(0xFFFFFFFF, bsman->collection_paf_fcf265d8_natural_result_addr);
        _sw(0, bsman->collection_paf_fcf265d8_hits_addr);
        _sw(0, bsman->collection_paf_fcf265d8_nonzero_hits_addr);
        _sw(0, bsman->collection_paf_9a285882_last_item_addr);
        _sw(0xFFFFFFFF, bsman->collection_paf_9a285882_natural_result_addr);
        _sw(0, bsman->collection_paf_9a285882_hits_addr);
        _sw(0, bsman->collection_paf_9a285882_nonzero_hits_addr);
        _sw(bsman->activation_addr + 0x188,
                bsman->collection_paf_9a285882_zero_resume_target_addr);
        _sw(bsman->activation_addr + 0x50,
                bsman->collection_paf_9a285882_nonzero_target_addr);
        _sw(0xFFFFFFFF, bsman->post_collection_paf_fcf265d8_natural_result_addr);
        _sw(0, bsman->post_collection_paf_fcf265d8_hits_addr);
        _sw(0, bsman->post_collection_paf_fcf265d8_nonzero_hits_addr);
        _sw(bsman->activation_addr + 0x1AC,
                bsman->post_collection_paf_fcf265d8_zero_resume_target_addr);
        _sw(bsman->activation_addr + 0x50,
                bsman->post_collection_paf_fcf265d8_nonzero_target_addr);
        _sw(0xFFFFFFFF, bsman->masked_paf_c59fc3d0_decision_value_addr);
        _sw(0, bsman->masked_paf_c59fc3d0_hits_addr);
        _sw(0, bsman->masked_paf_c59fc3d0_nonzero_hits_addr);
        _sw(bsman->activation_addr + 0x1C8,
                bsman->masked_paf_c59fc3d0_zero_resume_target_addr);
        _sw(bsman->activation_addr + 0x50,
                bsman->masked_paf_c59fc3d0_nonzero_target_addr);
        _sw(0xFFFFFFFF, bsman->masked_paf_c59fc3d0_second_decision_value_addr);
        _sw(0, bsman->masked_paf_c59fc3d0_second_hits_addr);
        _sw(0, bsman->masked_paf_c59fc3d0_second_nonzero_hits_addr);
        _sw(bsman->activation_addr + 0x1E8,
                bsman->masked_paf_c59fc3d0_second_zero_resume_target_addr);
        _sw(bsman->activation_addr + 0x4C,
                bsman->masked_paf_c59fc3d0_second_nonzero_target_addr);
        if (bsman->activation_wide_enabled) {
            unsigned int wide_index;
            for (wide_index = 0; wide_index < 54; wide_index++)
                _sw(0, bsman->activation_wide_scalar_addr[wide_index]);
            /* Compare: zero exits the body; nonzero enters it. */
            _sw(bsman->activation_addr + 0x22C,
                    bsman->activation_wide_scalar_addr[6]);
            _sw(bsman->activation_addr + 0x200,
                    bsman->activation_wide_scalar_addr[7]);
            /* Four natural PAF call targets, saved RAs, and continuations. */
            _sw(bsman->activation_addr - 0x9304 + 0x2A380,
                    bsman->activation_wide_scalar_addr[8]);
            _sw(bsman->activation_addr + 0x208,
                    bsman->activation_wide_scalar_addr[10]);
            _sw(bsman->activation_addr - 0x9304 + 0x2A290,
                    bsman->activation_wide_scalar_addr[17]);
            _sw(bsman->activation_addr + 0x214,
                    bsman->activation_wide_scalar_addr[19]);
            _sw(bsman->activation_addr - 0x9304 + 0x2A698,
                    bsman->activation_wide_scalar_addr[26]);
            _sw(bsman->activation_addr + 0x21C,
                    bsman->activation_wide_scalar_addr[28]);
            /* At +0x21C zero loops; nonzero takes Sony's +0x224 exit. */
            _sw(bsman->activation_addr + 0x1E8,
                    bsman->activation_wide_scalar_addr[41]);
            _sw(bsman->activation_addr + 0x224,
                    bsman->activation_wide_scalar_addr[42]);
            _sw(bsman->activation_addr - 0x9304 + 0x2A6F8,
                    bsman->activation_wide_scalar_addr[43]);
            _sw(bsman->activation_addr + 0x234,
                    bsman->activation_wide_scalar_addr[45]);
            _sw(bsman->activation_addr - 0x9304 + 0x2A168,
                    bsman->activation_wide_scalar_addr[52]);
            /* Routing and counters must be coherent before any owner is live. */
            for (wide_index = 0; wide_index < 54; wide_index++)
                sceKernelDcacheWritebackInvalidateRange(
                        (const void *)bsman->activation_wide_scalar_addr[
                            wide_index], 4);
        }
        _sw(0, bsman->post_paf_entry_counter_addr[0]);
        _sw(0, bsman->post_paf_entry_counter_addr[1]);
        _sw(0, bsman->post_vsh_entry_hits_addr);
        _sw(0, bsman->state_zero_path_mask_addr);
        for (pc = 0; pc < 7; pc++) _sw(0, bsman->state_zero_value_addr[pc]);
        for (pc = 0; pc < 4; pc++) _sw(0, bsman->state_zero_counter_addr[pc]);
        _sw(bsman->state_zero_15to14_compat_enabled ? 1 : 0,
                bsman->state_zero_15to14_compat_mode_addr);
        _sw(0xFFFFFFFF, bsman->state_zero_15to14_effective_result_addr);
        _sw(0, bsman->state_zero_15to14_substitution_hits_addr);
        _sw(bsman->activation_addr + 0x4C, bsman->state_zero_target_addr[0]);
        _sw(bsman->activation_addr + 0x284, bsman->state_zero_target_addr[1]);
        _sw(bsman->activation_addr + 0x290, bsman->state_zero_target_addr[2]);
        _sw(bsman->activation_addr + 0x50, bsman->state_zero_target_addr[3]);
        _sw(bsman->activation_addr + 0x2A0, bsman->state_zero_target_addr[4]);
        _sw(bsman->activation_addr + 0x54, bsman->state_zero_target_addr[5]);
        _sw(bsman->activation_addr + 0xE8, bsman->state_zero_target_addr[6]);
        _sw(bsman->activation_addr + 0x2BC, bsman->state_zero_target_addr[7]);
        _sw(bsman->activation_addr + 0x50, bsman->state_zero_target_addr[8]);
        _sw(bsman->activation_addr + 0x2C4, bsman->state_zero_target_addr[9]);
        _sw(bsman->activation_addr + 0x2D0, bsman->state_zero_target_addr[10]);
        _sw(bsman->activation_addr + 0xE8, bsman->state_zero_target_addr[11]);
        for (pc = 0; pc < 6; pc++)
            _sw(0, bsman->prefix_counter_addr[pc]);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->activation_resume_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->call_target_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->activation_hits_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->call_hits_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->trace_stage_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->call_ra_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_result_zero_addr, 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_flag_zero_addr, 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_mask_equal_addr, 12);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_path_mask_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_target_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_ra_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_compat_mode_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_natural_result_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_substitution_hits_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->prefix_paf_return_hits_addr, 4);
        for (pc = 0; pc < 6; pc++)
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)bsman->prefix_counter_addr[pc], 4);
#define SYNC_POST_SCALAR(address) \
        sceKernelDcacheWritebackInvalidateRange((const void *)(address), 4)
        SYNC_POST_SCALAR(bsman->post_path_mask_addr);
        SYNC_POST_SCALAR(bsman->bsman_natural_result_addr);
        SYNC_POST_SCALAR(bsman->bsman_compat_mode_addr);
        SYNC_POST_SCALAR(bsman->bsman_substitution_hits_addr);
        SYNC_POST_SCALAR(bsman->bsman_effective_result_addr);
        SYNC_POST_SCALAR(bsman->bsman_return_hits_addr);
        for (pc = 0; pc < 2; pc++) {
            SYNC_POST_SCALAR(bsman->post_bs_target_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_bs_counter_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_state_target_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_state_counter_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_paf_call_ra_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_paf_result_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_paf_return_counter_addr[pc]);
            SYNC_POST_SCALAR(bsman->post_paf_entry_counter_addr[pc]);
        }
        SYNC_POST_SCALAR(bsman->post_state_delay_value_addr);
        SYNC_POST_SCALAR(bsman->post_state_natural_value_addr);
        SYNC_POST_SCALAR(bsman->post_paf_target_addr);
        SYNC_POST_SCALAR(bsman->post_paf_saved_ra_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_target_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_saved_ra_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_natural_result_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_return_hits_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_entry_hits_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_argument_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_compat_mode_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_effective_result_addr);
        SYNC_POST_SCALAR(bsman->post_vsh_substitution_hits_addr);
        SYNC_POST_SCALAR(bsman->post_impose_vcall_target_addr);
        SYNC_POST_SCALAR(bsman->post_impose_vcall_saved_ra_addr);
        SYNC_POST_SCALAR(bsman->post_impose_vcall_natural_result_addr);
        SYNC_POST_SCALAR(bsman->post_impose_vcall_hits_addr);
        SYNC_POST_SCALAR(bsman->post_impose_vcall_return_hits_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_target_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_saved_ra_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_natural_result_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_hits_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_return_hits_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_collection_enabled_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_count_snapshot_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_array_snapshot_addr);
        SYNC_POST_SCALAR(bsman->post_minus_one_vcall64_array_read_hits_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_fcf265d8_last_item_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_fcf265d8_natural_result_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_fcf265d8_hits_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_fcf265d8_nonzero_hits_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_last_item_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_natural_result_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_hits_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_nonzero_hits_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_zero_resume_target_addr);
        SYNC_POST_SCALAR(bsman->collection_paf_9a285882_nonzero_target_addr);
        SYNC_POST_SCALAR(bsman->post_collection_paf_fcf265d8_natural_result_addr);
        SYNC_POST_SCALAR(bsman->post_collection_paf_fcf265d8_hits_addr);
        SYNC_POST_SCALAR(bsman->post_collection_paf_fcf265d8_nonzero_hits_addr);
        SYNC_POST_SCALAR(bsman->post_collection_paf_fcf265d8_zero_resume_target_addr);
        SYNC_POST_SCALAR(bsman->post_collection_paf_fcf265d8_nonzero_target_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_decision_value_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_hits_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_nonzero_hits_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_zero_resume_target_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_nonzero_target_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_second_decision_value_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_second_hits_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_second_nonzero_hits_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_second_zero_resume_target_addr);
        SYNC_POST_SCALAR(bsman->masked_paf_c59fc3d0_second_nonzero_target_addr);
        SYNC_POST_SCALAR(bsman->state_zero_path_mask_addr);
        SYNC_POST_SCALAR(bsman->state_zero_15to14_compat_mode_addr);
        SYNC_POST_SCALAR(bsman->state_zero_15to14_effective_result_addr);
        SYNC_POST_SCALAR(bsman->state_zero_15to14_substitution_hits_addr);
        for (pc = 0; pc < 7; pc++) SYNC_POST_SCALAR(bsman->state_zero_value_addr[pc]);
        for (pc = 0; pc < 4; pc++) SYNC_POST_SCALAR(bsman->state_zero_counter_addr[pc]);
        for (pc = 0; pc < 12; pc++) SYNC_POST_SCALAR(bsman->state_zero_target_addr[pc]);
#undef SYNC_POST_SCALAR
        /* Transaction commit: all transparent trace sites validated above. */
        _sw(bsman->activation_replacement[0], bsman->activation_addr);
        _sw(bsman->activation_replacement[1], bsman->activation_addr + 4);
        _sw(bsman->call_replacement, bsman->caller_addr);
        _sw(bsman->prefix_replacement[0], bsman->activation_addr + 0x34);
        _sw(0, bsman->activation_addr + 0x38);
        _sw(bsman->prefix_replacement[1], bsman->activation_addr + 0x44);
        _sw(bsman->prefix_replacement[2], bsman->activation_addr + 0x94);
        _sw(0, bsman->activation_addr + 0x98);
        _sw(bsman->prefix_replacement[3], bsman->activation_addr + 0x2C);
        _sw(bsman->post_replacement[0], bsman->activation_addr + 0xB0);
        _sw(bsman->post_replacement[1], bsman->activation_addr + 0xDC);
        _sw(bsman->post_replacement[2], bsman->activation_addr + 0xE8);
        _sw(bsman->post_replacement[3], bsman->activation_addr + 0xF8);
        _sw(bsman->post_replacement[4], bsman->activation_addr + 0x10C);
        if (bsman->post_impose_vcall_enabled) {
            _sw(bsman->post_impose_vcall_replacement,
                    bsman->activation_addr + 0x120);
            bsman->post_impose_vcall_install = 1;
        }
        if (bsman->post_minus_one_vcall64_enabled) {
            _sw(bsman->post_minus_one_vcall64_replacement,
                    bsman->activation_addr + 0x138);
            bsman->post_minus_one_vcall64_install = 1;
        }
        if (bsman->collection_paf_fcf265d8_enabled) {
            _sw(bsman->collection_paf_fcf265d8_replacement,
                    bsman->activation_addr + 0x170);
            bsman->collection_paf_fcf265d8_install = 1;
        }
        if (bsman->collection_paf_9a285882_enabled) {
            _sw(bsman->collection_paf_9a285882_replacement,
                    bsman->activation_addr + 0x180);
            bsman->collection_paf_9a285882_install = 1;
        }
        if (bsman->post_collection_paf_fcf265d8_enabled) {
            _sw(bsman->post_collection_paf_fcf265d8_replacement,
                    bsman->activation_addr + 0x1A4);
            bsman->post_collection_paf_fcf265d8_install = 1;
        }
        if (bsman->masked_paf_c59fc3d0_enabled) {
            _sw(bsman->masked_paf_c59fc3d0_replacement,
                    bsman->activation_addr + 0x1C0);
            bsman->masked_paf_c59fc3d0_install = 1;
        }
        if (bsman->masked_paf_c59fc3d0_second_enabled) {
            _sw(bsman->masked_paf_c59fc3d0_second_replacement,
                    bsman->activation_addr + 0x1E0);
            bsman->masked_paf_c59fc3d0_second_install = 1;
        }
        if (bsman->activation_wide_enabled &&
                bsman->activation_wide_validation) {
            static const unsigned int wide_offset[6] = {
                0x1F8, 0x200, 0x20C, 0x214, 0x21C, 0x22C
            };
            unsigned int wide_index;
            _sw(bsman->activation_wide_pre_replacement,
                    bsman->activation_addr + 0x1E8);
            for (wide_index = 0; wide_index < 6; wide_index++)
                _sw(bsman->activation_wide_replacement[wide_index],
                        bsman->activation_addr + wide_offset[wide_index]);
        }
        for (pc = 0; pc < 7; pc++) {
            static const unsigned int site_offset[7] = {
                0x27C, 0x288, 0x298, 0x2A4, 0x2B4, 0x2BC, 0x2C8
            };
            _sw(bsman->state_zero_replacement[pc],
                    bsman->activation_addr + site_offset[pc]);
        }
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->activation_addr, 8);
        sceKernelIcacheInvalidateRange((const void *)bsman->activation_addr, 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)bsman->caller_addr, 4);
        sceKernelIcacheInvalidateRange((const void *)bsman->caller_addr, 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x34), 8);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x34), 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x44), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x44), 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x94), 8);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x94), 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x2C), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x2C), 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0xB0), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0xB0), 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0xDC), 8);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0xDC), 8);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0xE8), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0xE8), 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0xF8), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0xF8), 4);
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x10C), 4);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x10C), 4);
        if (bsman->post_impose_vcall_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x120), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x120), 4);
            bsman->post_impose_vcall_cache_sync = 1;
        }
        if (bsman->post_minus_one_vcall64_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x138), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x138), 4);
            bsman->post_minus_one_vcall64_cache_sync = 1;
        }
        if (bsman->collection_paf_fcf265d8_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x170), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x170), 4);
            bsman->collection_paf_fcf265d8_cache_sync = 1;
        }
        if (bsman->collection_paf_9a285882_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x180), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x180), 4);
            bsman->collection_paf_9a285882_cache_sync = 1;
        }
        if (bsman->post_collection_paf_fcf265d8_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1A4), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1A4), 4);
            bsman->post_collection_paf_fcf265d8_cache_sync = 1;
        }
        if (bsman->masked_paf_c59fc3d0_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1C0), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1C0), 4);
            bsman->masked_paf_c59fc3d0_cache_sync = 1;
        }
        if (bsman->masked_paf_c59fc3d0_second_enabled) {
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E0), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E0), 4);
            bsman->masked_paf_c59fc3d0_second_cache_sync = 1;
        }
        if (bsman->activation_wide_enabled &&
                bsman->activation_wide_validation) {
            static const unsigned int wide_offset[6] = {
                0x1F8, 0x200, 0x20C, 0x214, 0x21C, 0x22C
            };
            unsigned int wide_index;
            sceKernelDcacheWritebackInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E8), 4);
            sceKernelIcacheInvalidateRange(
                    (const void *)(bsman->activation_addr + 0x1E8), 4);
            for (wide_index = 0; wide_index < 6; wide_index++) {
                sceKernelDcacheWritebackInvalidateRange(
                        (const void *)(bsman->activation_addr +
                            wide_offset[wide_index]), 4);
                sceKernelIcacheInvalidateRange(
                        (const void *)(bsman->activation_addr +
                            wide_offset[wide_index]), 4);
            }
            bsman->activation_wide_install = 1;
            bsman->activation_wide_cache_sync = 1;
        }
        sceKernelDcacheWritebackInvalidateRange(
                (const void *)(bsman->activation_addr + 0x27C), 0x50);
        sceKernelIcacheInvalidateRange(
                (const void *)(bsman->activation_addr + 0x27C), 0x50);
        bsman->activation_install = 1;
        bsman->activation_cache_sync = 1;
    }

    if (!bsman->enabled) return;

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
	ini_gets("Experimental", "PSP1000ActivationTrace", "Disabled",
			psp1000ActivationTrace, sizeof(psp1000ActivationTrace), config);
	ini_gets("Experimental", "PSP1000PafPresentCompat", "Disabled",
			psp1000PafPresentCompat, sizeof(psp1000PafPresentCompat), config);
	ini_gets("Experimental", "PSP1000BSManNotLinkedCompat", "Disabled",
			psp1000BSManNotLinkedCompat,
			sizeof(psp1000BSManNotLinkedCompat), config);
	ini_gets("Experimental", "PSP1000Consumer14020Compat", "Disabled",
			psp1000Consumer14020Compat,
			sizeof(psp1000Consumer14020Compat), config);
	ini_gets("Experimental", "PSP1000Consumer13F6CCompat", "Disabled",
			psp1000Consumer13F6CCompat,
			sizeof(psp1000Consumer13F6CCompat), config);
	ini_gets("Experimental", "PSP1000PafCapabilityMaskCompat", "Disabled",
			psp1000PafCapabilityMaskCompat,
			sizeof(psp1000PafCapabilityMaskCompat), config);
	ini_gets("Experimental", "PSP1000StateZero15To14Compat", "Disabled",
			psp1000StateZero15To14Compat,
			sizeof(psp1000StateZero15To14Compat), config);
	ini_gets("Experimental", "PSP1000ImposeParam8000000DCompat", "Disabled",
			psp1000ImposeParam8000000DCompat,
			sizeof(psp1000ImposeParam8000000DCompat), config);
	ini_gets("Experimental", "PSP1000PostImposeVCallTrace", "Disabled",
			psp1000PostImposeVCallTrace,
			sizeof(psp1000PostImposeVCallTrace), config);
	ini_gets("Experimental", "PSP1000PostMinusOneVCall64Trace", "Disabled",
			psp1000PostMinusOneVCall64Trace,
			sizeof(psp1000PostMinusOneVCall64Trace), config);
	ini_gets("Experimental", "PSP1000PostVCall64CollectionTrace", "Disabled",
			psp1000PostVCall64CollectionTrace,
			sizeof(psp1000PostVCall64CollectionTrace), config);
	ini_gets("Experimental", "PSP1000CollectionPafFCF265D8Trace", "Disabled",
			psp1000CollectionPafFCF265D8Trace,
			sizeof(psp1000CollectionPafFCF265D8Trace), config);
	ini_gets("Experimental", "PSP1000CollectionPaf9A285882Trace", "Disabled",
			psp1000CollectionPaf9A285882Trace,
			sizeof(psp1000CollectionPaf9A285882Trace), config);
	ini_gets("Experimental", "PSP1000PostCollectionPafFCF265D8Trace", "Disabled",
			psp1000PostCollectionPafFCF265D8Trace,
			sizeof(psp1000PostCollectionPafFCF265D8Trace), config);
	ini_gets("Experimental", "PSP1000MaskedPafC59FC3D0Trace", "Disabled",
			psp1000MaskedPafC59FC3D0Trace,
			sizeof(psp1000MaskedPafC59FC3D0Trace), config);
	ini_gets("Experimental", "PSP1000MaskedPafC59FC3D0SecondTrace", "Disabled",
			psp1000MaskedPafC59FC3D0SecondTrace,
			sizeof(psp1000MaskedPafC59FC3D0SecondTrace), config);
	ini_gets("Experimental", "PSP1000ActivationWideTrace", "Disabled",
			psp1000ActivationWideTrace,
			sizeof(psp1000ActivationWideTrace), config);
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
		slide_diag.bsman.activation_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000ActivationTrace, "Enabled") == 0 &&
			strcmp(psp1000BSManClosedShim, "Disabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0;
		slide_diag.bsman.paf_compat_enabled =
			slide_diag.bsman.activation_enabled &&
			strcmp(psp1000PafPresentCompat, "Enabled") == 0;
		slide_diag.bsman.bsman_not_linked_compat_enabled =
			slide_diag.bsman.activation_enabled &&
			strcmp(psp1000BSManNotLinkedCompat, "Enabled") == 0;
		slide_diag.bsman.consumer_14020_compat_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0 &&
			strcmp(psp1000Consumer14020Compat, "Enabled") == 0;
		slide_diag.bsman.consumer_13f6c_compat_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0 &&
			strcmp(psp1000Consumer13F6CCompat, "Enabled") == 0;
		slide_diag.bsman.paf_mask_compat_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0 &&
			strcmp(psp1000PafCapabilityMaskCompat, "Enabled") == 0;
		slide_diag.bsman.state_zero_15to14_compat_enabled =
			devkit == 0x06060110 &&
			strcmp(psp1000Diagnostics, "Enabled") == 0 &&
			strcmp(psp1000SlideTriggerMode,
					"DangerousCaller58D4") == 0 &&
			strcmp(psp1000StateZero15To14Compat, "Enabled") == 0;
		slide_diag.bsman.post_vsh_compat_enabled =
			slide_diag.bsman.activation_enabled &&
			strcmp(psp1000ImposeParam8000000DCompat, "Enabled") == 0;
		slide_diag.bsman.post_impose_vcall_enabled =
			slide_diag.bsman.post_vsh_compat_enabled &&
			strcmp(psp1000PostImposeVCallTrace, "Enabled") == 0;
		slide_diag.bsman.post_minus_one_vcall64_enabled =
			slide_diag.bsman.post_impose_vcall_enabled &&
			strcmp(psp1000PostMinusOneVCall64Trace, "Enabled") == 0;
		slide_diag.bsman.post_vcall64_collection_enabled =
			slide_diag.bsman.post_minus_one_vcall64_enabled &&
			strcmp(psp1000PostVCall64CollectionTrace, "Enabled") == 0;
		slide_diag.bsman.collection_paf_fcf265d8_enabled =
			slide_diag.bsman.post_vcall64_collection_enabled &&
			strcmp(psp1000CollectionPafFCF265D8Trace, "Enabled") == 0;
		slide_diag.bsman.collection_paf_9a285882_enabled =
			slide_diag.bsman.collection_paf_fcf265d8_enabled &&
			strcmp(psp1000CollectionPaf9A285882Trace, "Enabled") == 0;
		slide_diag.bsman.post_collection_paf_fcf265d8_enabled =
			slide_diag.bsman.collection_paf_9a285882_enabled &&
			strcmp(psp1000PostCollectionPafFCF265D8Trace, "Enabled") == 0;
		slide_diag.bsman.masked_paf_c59fc3d0_enabled =
			slide_diag.bsman.post_collection_paf_fcf265d8_enabled &&
			strcmp(psp1000MaskedPafC59FC3D0Trace, "Enabled") == 0;
		slide_diag.bsman.masked_paf_c59fc3d0_second_enabled =
			slide_diag.bsman.masked_paf_c59fc3d0_enabled &&
			strcmp(psp1000MaskedPafC59FC3D0SecondTrace, "Enabled") == 0;
		slide_diag.bsman.activation_wide_enabled =
			slide_diag.bsman.masked_paf_c59fc3d0_second_enabled &&
			strcmp(psp1000ActivationWideTrace, "Enabled") == 0;
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
		if (slide_diag.bsman.activation_enabled)
			zeroCtrlDiagnosticsText(
					"[experiment] psp1000_activation_trace=enabled_natural\n");
		if (slide_diag.bsman.paf_compat_enabled)
			zeroCtrlDiagnosticsText(
					"[experiment] psp1000_paf_present_compat="
					"callsite_only_zero_to_one\n");
		if (slide_diag.bsman.bsman_not_linked_compat_enabled)
			zeroCtrlDiagnosticsText(
					"[experiment] psp1000_bsman_not_linked_compat="
					"callsite_only_8002013a_to_zero\n");
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
