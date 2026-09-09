#ifndef ZEROCTRL_SONY_START_TRACE_H
#define ZEROCTRL_SONY_START_TRACE_H

#include <psptypes.h>

/* Private user/kernel ABI: addresses are always serialized as 32-bit values. */
typedef struct {
    u32 entry_addr;
    u32 entry_end_addr;
    u32 exit_addr;
    u32 exit_end_addr;
    u32 resume_slot_addr;
    u32 caller_ra_slot_addr;
    u32 entry_seen_addr;
    u32 return_seen_addr;
    u32 result_addr;
} ZeroCtrlSonyStartTraceRegistration;

#define ZEROCTRL_STATIC_ASSERT(name, expression) \
    typedef char zeroctrl_static_assert_##name[(expression) ? 1 : -1]

ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_size,
        sizeof(ZeroCtrlSonyStartTraceRegistration) == 36);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_entry_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, entry_addr) == 0);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_entry_end_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, entry_end_addr) == 4);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_exit_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, exit_addr) == 8);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_exit_end_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, exit_end_addr) == 12);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_resume_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, resume_slot_addr) == 16);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_caller_ra_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, caller_ra_slot_addr) == 20);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_entry_seen_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, entry_seen_addr) == 24);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_return_seen_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, return_seen_addr) == 28);
ZEROCTRL_STATIC_ASSERT(sony_start_trace_registration_result_offset,
        __builtin_offsetof(ZeroCtrlSonyStartTraceRegistration, result_addr) == 32);

#endif
