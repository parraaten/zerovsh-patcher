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
} ZeroCtrlBSManClosedRegistration;

typedef char ZeroCtrlBSManClosedRegistration_size[
    sizeof(ZeroCtrlBSManClosedRegistration) == 44 ? 1 : -1];

#endif
