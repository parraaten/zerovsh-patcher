#ifndef ZEROCTRL_BSMAN_CLOSED_SHIM_H
#define ZEROCTRL_BSMAN_CLOSED_SHIM_H

#include <psptypes.h>

typedef struct {
    u32 leaf_addr;
    u32 leaf_end_addr;
    u32 hit_count_addr;
} ZeroCtrlBSManClosedRegistration;

typedef char ZeroCtrlBSManClosedRegistration_size[
    sizeof(ZeroCtrlBSManClosedRegistration) == 12 ? 1 : -1];

#endif
