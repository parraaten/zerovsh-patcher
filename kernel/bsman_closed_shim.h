#ifndef ZEROCTRL_BSMAN_CLOSED_SHIM_H
#define ZEROCTRL_BSMAN_CLOSED_SHIM_H

#include <psptypes.h>

typedef struct {
    u32 leaf_addr;
    u32 leaf_end_addr;
    u32 hit_count_addr;
    u32 activation_leaf_addr;
    u32 activation_leaf_end_addr;
    u32 activation_resume_addr;
    u32 activation_hits_addr;
    u32 bsman_call_leaf_addr;
    u32 bsman_call_leaf_end_addr;
    u32 bsman_call_target_addr;
    u32 bsman_call_hits_addr;
    u32 trace_stage_addr;
    u32 bsman_call_ra_addr;
    u32 bsman_return_leaf_addr;
    u32 bsman_return_leaf_end_addr;
    u32 prefix_result_leaf_addr;
    u32 prefix_result_leaf_end_addr;
    u32 prefix_result_zero_addr;
    u32 prefix_result_nonzero_addr;
    u32 prefix_flag_leaf_addr;
    u32 prefix_flag_leaf_end_addr;
    u32 prefix_flag_zero_addr;
    u32 prefix_flag_nonzero_addr;
    u32 prefix_mask_leaf_addr;
    u32 prefix_mask_leaf_end_addr;
    u32 prefix_mask_equal_addr;
    u32 prefix_mask_unequal_addr;
    u32 prefix_mask_delay_value_addr;
    u32 prefix_path_mask_addr;
    u32 prefix_result_zero_hits_addr;
    u32 prefix_result_nonzero_hits_addr;
    u32 prefix_flag_zero_hits_addr;
    u32 prefix_flag_nonzero_hits_addr;
    u32 prefix_mask_equal_hits_addr;
    u32 prefix_mask_unequal_hits_addr;
    u32 prefix_paf_call_leaf_addr;
    u32 prefix_paf_call_leaf_end_addr;
    u32 prefix_paf_return_leaf_addr;
    u32 prefix_paf_return_leaf_end_addr;
    u32 prefix_paf_target_addr;
    u32 prefix_paf_ra_addr;
} ZeroCtrlBSManClosedRegistration;

typedef char ZeroCtrlBSManClosedRegistration_size[
    sizeof(ZeroCtrlBSManClosedRegistration) == 164 ? 1 : -1];

#endif
