.macro CREATE_STUB funcname
    .set noreorder
    .globl \funcname
    .type \funcname @function
    .ent \funcname, 0
\funcname:
    nop
    nop
    j 0
    nop
    .end \funcname
.endm 


CREATE_STUB add_sysconf_item_stub
CREATE_STUB slide_check_stub
CREATE_STUB slide_start_stub

/*
 * VSH calls these leaves directly.  They deliberately avoid gp, the stack,
 * imports, and C-generated prologues.  The linker resolves the paired HI16 /
 * LO16 relocations for each dedicated counter.
 */
.macro CREATE_TRIGGER_STUB funcname, counter
    .set noreorder
    .globl \funcname
    .type \funcname @function
    .ent \funcname, 0
\funcname:
    lui     $t0, %hi(\counter)
    lw      $t1, %lo(\counter)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(\counter)($t0)
    jr      $ra
    addiu   $v0, $zero, 1
    .end \funcname
.endm

CREATE_TRIGGER_STUB zeroCtrlTrigger58D4, zeroCtrlTrigger58D4Hits
CREATE_TRIGGER_STUB zeroCtrlTrigger13F6C, zeroCtrlTrigger13F6CHits
CREATE_TRIGGER_STUB zeroCtrlTrigger14020, zeroCtrlTrigger14020Hits
CREATE_TRIGGER_STUB zeroCtrlGlobalPredicate6F84True, zeroCtrlGlobalPredicate6F84Hits

.section .bss
.align 2
.globl zeroCtrlTrigger58D4Hits
zeroCtrlTrigger58D4Hits: .space 4
.globl zeroCtrlTrigger13F6CHits
zeroCtrlTrigger13F6CHits: .space 4
.globl zeroCtrlTrigger14020Hits
zeroCtrlTrigger14020Hits: .space 4
.globl zeroCtrlGlobalPredicate6F84Hits
zeroCtrlGlobalPredicate6F84Hits: .space 4

.section .text
.set noreorder
.globl zeroCtrlSonyModuleStartWrapper
.type zeroCtrlSonyModuleStartWrapper @function
.ent zeroCtrlSonyModuleStartWrapper, 0
zeroCtrlSonyModuleStartWrapper:
    addiu   $sp, $sp, -16
    sw      $ra, 12($sp)
    lui     $t0, %hi(zeroCtrlSonyModuleStartEntrySeen)
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSonyModuleStartEntrySeen)($t0)
    lui     $t0, %hi(zeroCtrlSonyModuleStartOriginal)
    lw      $t9, %lo(zeroCtrlSonyModuleStartOriginal)($t0)
    jalr    $t9
    nop
    lui     $t0, %hi(zeroCtrlSonyModuleStartResult)
    sw      $v0, %lo(zeroCtrlSonyModuleStartResult)($t0)
    lui     $t0, %hi(zeroCtrlSonyModuleStartReturnSeen)
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSonyModuleStartReturnSeen)($t0)
    lw      $ra, 12($sp)
    addiu   $sp, $sp, 16
    jr      $ra
    nop
.globl zeroCtrlSonyModuleStartWrapperEnd
zeroCtrlSonyModuleStartWrapperEnd:
.end zeroCtrlSonyModuleStartWrapper

.section .bss
.align 2
.globl zeroCtrlSonyModuleStartOriginal
zeroCtrlSonyModuleStartOriginal: .space 4
.globl zeroCtrlSonyModuleStartEntrySeen
zeroCtrlSonyModuleStartEntrySeen: .space 4
.globl zeroCtrlSonyModuleStartReturnSeen
zeroCtrlSonyModuleStartReturnSeen: .space 4
.globl zeroCtrlSonyModuleStartResult
zeroCtrlSonyModuleStartResult: .space 4
