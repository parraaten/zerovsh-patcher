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
.globl zeroCtrlSonyModuleStartEntryTrace
.type zeroCtrlSonyModuleStartEntryTrace @function
.ent zeroCtrlSonyModuleStartEntryTrace, 0
zeroCtrlSonyModuleStartEntryTrace:
    lui     $t0, %hi(zeroCtrlSonyModuleStartEntrySeen)
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSonyModuleStartEntrySeen)($t0)
    lui     $t0, %hi(zeroCtrlSonyModuleStartCallerRA)
    sw      $ra, %lo(zeroCtrlSonyModuleStartCallerRA)($t0)
    lui     $ra, %hi(zeroCtrlSonyModuleStartExitTrace)
    addiu   $ra, $ra, %lo(zeroCtrlSonyModuleStartExitTrace)
    addiu   $sp, $sp, -16
    sw      $s0, 0($sp)
    lui     $t0, %hi(zeroCtrlSonyModuleStartResume)
    lw      $t9, %lo(zeroCtrlSonyModuleStartResume)($t0)
    jr      $t9
    nop
.globl zeroCtrlSonyModuleStartEntryTraceEnd
zeroCtrlSonyModuleStartEntryTraceEnd:
.end zeroCtrlSonyModuleStartEntryTrace

.globl zeroCtrlSonyModuleStartExitTrace
.type zeroCtrlSonyModuleStartExitTrace @function
.ent zeroCtrlSonyModuleStartExitTrace, 0
zeroCtrlSonyModuleStartExitTrace:
    lui     $t0, %hi(zeroCtrlSonyModuleStartResult)
    sw      $v0, %lo(zeroCtrlSonyModuleStartResult)($t0)
    lui     $t0, %hi(zeroCtrlSonyModuleStartReturnSeen)
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSonyModuleStartReturnSeen)($t0)
    lui     $t0, %hi(zeroCtrlSonyModuleStartCallerRA)
    lw      $t9, %lo(zeroCtrlSonyModuleStartCallerRA)($t0)
    jr      $t9
    nop
.globl zeroCtrlSonyModuleStartExitTraceEnd
zeroCtrlSonyModuleStartExitTraceEnd:
.end zeroCtrlSonyModuleStartExitTrace

.section .bss
.align 2
.globl zeroCtrlSonyModuleStartResume
zeroCtrlSonyModuleStartResume: .space 4
.globl zeroCtrlSonyModuleStartCallerRA
zeroCtrlSonyModuleStartCallerRA: .space 4
.globl zeroCtrlSonyModuleStartEntrySeen
zeroCtrlSonyModuleStartEntrySeen: .space 4
.globl zeroCtrlSonyModuleStartReturnSeen
zeroCtrlSonyModuleStartReturnSeen: .space 4
.globl zeroCtrlSonyModuleStartResult
zeroCtrlSonyModuleStartResult: .space 4

/*
 * Strategy-B BSMan leaf.  CLOSED=0 is a strong static inference from the
 * Sony caller's beq v0,zero closed/non-open path.  This leaf has no stack,
 * gp, calls, imports, I/O, allocation, or hardware access.
 */
.section .text
.set noreorder
.globl zeroCtrlBSManClosedLeaf
.type zeroCtrlBSManClosedLeaf @function
.ent zeroCtrlBSManClosedLeaf, 0
zeroCtrlBSManClosedLeaf:
    lui     $t0, %hi(zeroCtrlBSManClosedHits)
    lw      $t1, %lo(zeroCtrlBSManClosedHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlBSManClosedHits)($t0)
    jr      $ra
    addu    $v0, $zero, $zero
.globl zeroCtrlBSManClosedLeafEnd
zeroCtrlBSManClosedLeafEnd:
.end zeroCtrlBSManClosedLeaf

.section .bss
.align 2
.globl zeroCtrlBSManClosedHits
zeroCtrlBSManClosedHits: .space 4

/* Transparent localization leaves: fixed-state writes only, no calls/stack/gp. */
.section .text
.set noreorder
.globl zeroCtrlSlideActivationTrace
zeroCtrlSlideActivationTrace:
    lui     $t0, %hi(zeroCtrlSlideActivationHits)
    lw      $t1, %lo(zeroCtrlSlideActivationHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlSlideActivationHits)($t0)
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
    addiu   $sp, $sp, -32
    sw      $s1, 4($sp)
    lui     $t0, %hi(zeroCtrlSlideActivationResume)
    lw      $t9, %lo(zeroCtrlSlideActivationResume)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlideActivationTraceEnd
zeroCtrlSlideActivationTraceEnd:

.globl zeroCtrlBSManCallTrace
zeroCtrlBSManCallTrace:
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    addiu   $t1, $zero, 2
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
    lui     $t0, %hi(zeroCtrlBSManCallHits)
    lw      $t1, %lo(zeroCtrlBSManCallHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlBSManCallHits)($t0)
    lui     $t0, %hi(zeroCtrlBSManCallRA)
    sw      $ra, %lo(zeroCtrlBSManCallRA)($t0)
    lui     $ra, %hi(zeroCtrlBSManReturnTrace)
    addiu   $ra, $ra, %lo(zeroCtrlBSManReturnTrace)
    lui     $t0, %hi(zeroCtrlBSManCallTarget)
    lw      $t9, %lo(zeroCtrlBSManCallTarget)($t0)
    jr      $t9
    nop
.globl zeroCtrlBSManCallTraceEnd
zeroCtrlBSManCallTraceEnd:

.globl zeroCtrlBSManReturnTrace
zeroCtrlBSManReturnTrace:
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    addiu   $t1, $zero, 3
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
    lui     $t0, %hi(zeroCtrlBSManCallRA)
    lw      $t9, %lo(zeroCtrlBSManCallRA)($t0)
    jr      $t9
    nop
.globl zeroCtrlBSManReturnTraceEnd
zeroCtrlBSManReturnTraceEnd:

.section .bss
.align 2
.globl zeroCtrlSlideActivationResume
zeroCtrlSlideActivationResume: .space 4
.globl zeroCtrlSlideActivationHits
zeroCtrlSlideActivationHits: .space 4
.globl zeroCtrlBSManCallTarget
zeroCtrlBSManCallTarget: .space 4
.globl zeroCtrlBSManCallHits
zeroCtrlBSManCallHits: .space 4
.globl zeroCtrlSlideTraceStage
zeroCtrlSlideTraceStage: .space 4
.globl zeroCtrlBSManCallRA
zeroCtrlBSManCallRA: .space 4
