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
.type zeroCtrlSlideActivationTrace @function
.ent zeroCtrlSlideActivationTrace, 0
zeroCtrlSlideActivationTrace:
    lui     $t0, %hi(zeroCtrlSlideActivationHits)
    lw      $t1, %lo(zeroCtrlSlideActivationHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlSlideActivationHits)($t0)
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0001
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    lw      $t2, %lo(zeroCtrlSlideTraceStage)($t0)
    bnez    $t2, 1f
    nop
    addiu   $t1, $zero, 1
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
1:
    addiu   $sp, $sp, -32
    sw      $s1, 4($sp)
    lui     $t0, %hi(zeroCtrlSlideActivationResume)
    lw      $t9, %lo(zeroCtrlSlideActivationResume)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlideActivationTraceEnd
zeroCtrlSlideActivationTraceEnd:
.end zeroCtrlSlideActivationTrace

.globl zeroCtrlBSManCallTrace
.type zeroCtrlBSManCallTrace @function
.ent zeroCtrlBSManCallTrace, 0
zeroCtrlBSManCallTrace:
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0100
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    lw      $t2, %lo(zeroCtrlSlideTraceStage)($t0)
    sltiu   $t2, $t2, 2
    beqz    $t2, 2f
    nop
    addiu   $t1, $zero, 2
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
2:
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
.end zeroCtrlBSManCallTrace

.globl zeroCtrlBSManReturnTrace
.type zeroCtrlBSManReturnTrace @function
.ent zeroCtrlBSManReturnTrace, 0
zeroCtrlBSManReturnTrace:
    lui     $t0, %hi(zeroCtrlPostBSManNaturalResult)
    sw      $v0, %lo(zeroCtrlPostBSManNaturalResult)($t0)
    lui     $t0, %hi(zeroCtrlPostBSManCompatMode)
    lw      $t1, %lo(zeroCtrlPostBSManCompatMode)($t0)
    beqz    $t1, 20f
    lui     $t2, 0x8002
    ori     $t2, $t2, 0x013A
    bne     $v0, $t2, 20f
    nop
    move    $v0, $zero
    lui     $t0, %hi(zeroCtrlPostBSManSubstitutionHits)
    lw      $t1, %lo(zeroCtrlPostBSManSubstitutionHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlPostBSManSubstitutionHits)($t0)
20:
    lui     $t0, %hi(zeroCtrlPostBSManEffectiveResult)
    sw      $v0, %lo(zeroCtrlPostBSManEffectiveResult)($t0)
    lui     $t0, %hi(zeroCtrlPostBSManReturnHits)
    lw      $t1, %lo(zeroCtrlPostBSManReturnHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlPostBSManReturnHits)($t0)
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0001
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0200
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlideTraceStage)
    addiu   $t1, $zero, 3
    sw      $t1, %lo(zeroCtrlSlideTraceStage)($t0)
    lui     $t0, %hi(zeroCtrlBSManCallRA)
    lw      $ra, %lo(zeroCtrlBSManCallRA)($t0)
    jr      $ra
    nop
.globl zeroCtrlBSManReturnTraceEnd
zeroCtrlBSManReturnTraceEnd:
.end zeroCtrlBSManReturnTrace

/*
 * Prefix branch tracers reproduce only the displaced Sony branch semantics.
 * They record fixed scalar bits and jump to validated natural basic blocks.
 */
.macro RECORD_PREFIX_COUNTER counter
    lui     $t0, %hi(\counter)
    lw      $t2, %lo(\counter)($t0)
    addiu   $t2, $t2, 1
    sw      $t2, %lo(\counter)($t0)
.endm

.globl zeroCtrlPostBSManBranchTrace
.type zeroCtrlPostBSManBranchTrace @function
.ent zeroCtrlPostBSManBranchTrace, 0
zeroCtrlPostBSManBranchTrace:
    lui     $t0, %hi(zeroCtrlPostStateNaturalValue)
    sw      $v0, %lo(zeroCtrlPostStateNaturalValue)($t0)
    lui     $t0, %hi(zeroCtrlPostBSManEffectiveResult)
    lw      $t2, %lo(zeroCtrlPostBSManEffectiveResult)($t0)
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0002
    beqz    $t2, 8f
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0004
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlPostBSManNonzeroHits
    lui     $t0, %hi(zeroCtrlPostBSManNonzero)
    lw      $t9, %lo(zeroCtrlPostBSManNonzero)($t0)
    b       9f
    nop
8:
    RECORD_PREFIX_COUNTER zeroCtrlPostBSManZeroHits
    lui     $t0, %hi(zeroCtrlPostBSManZero)
    lw      $t9, %lo(zeroCtrlPostBSManZero)($t0)
9:
    jr      $t9
    nop
.globl zeroCtrlPostBSManBranchTraceEnd
zeroCtrlPostBSManBranchTraceEnd:
.end zeroCtrlPostBSManBranchTrace

.globl zeroCtrlPostStateBranchTrace
.type zeroCtrlPostStateBranchTrace @function
.ent zeroCtrlPostStateBranchTrace, 0
zeroCtrlPostStateBranchTrace:
    lui     $t0, %hi(zeroCtrlPostStateNaturalValue)
    lw      $t2, %lo(zeroCtrlPostStateNaturalValue)($t0)
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0008
    beqz    $t2, 10f
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0010
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlPostStateNonzeroHits
    lui     $t0, %hi(zeroCtrlPostStateNonzero)
    lw      $t9, %lo(zeroCtrlPostStateNonzero)($t0)
    b       11f
    nop
10:
    RECORD_PREFIX_COUNTER zeroCtrlPostStateZeroHits
    lui     $t0, %hi(zeroCtrlPostStateZero)
    lw      $t9, %lo(zeroCtrlPostStateZero)($t0)
11:
    jr      $t9
    nop
.globl zeroCtrlPostStateBranchTraceEnd
zeroCtrlPostStateBranchTraceEnd:
.end zeroCtrlPostStateBranchTrace

.globl zeroCtrlPostPafCallTrace
.type zeroCtrlPostPafCallTrace @function
.ent zeroCtrlPostPafCallTrace, 0
zeroCtrlPostPafCallTrace:
    lui     $t0, %hi(zeroCtrlPostPafCall0RA)
    lw      $t2, %lo(zeroCtrlPostPafCall0RA)($t0)
    bne     $ra, $t2, 12f
    nop
    RECORD_PREFIX_COUNTER zeroCtrlPostPafEntry0Hits
    addiu   $t2, $zero, 0x0020
    b       13f
    nop
12:
    RECORD_PREFIX_COUNTER zeroCtrlPostPafEntry1Hits
    addiu   $t2, $zero, 0x0080
13:
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    or      $t1, $t1, $t2
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    lui     $t0, %hi(zeroCtrlPostPafSavedRA)
    sw      $ra, %lo(zeroCtrlPostPafSavedRA)($t0)
    lui     $ra, %hi(zeroCtrlPostPafReturnTrace)
    addiu   $ra, $ra, %lo(zeroCtrlPostPafReturnTrace)
    lui     $t0, %hi(zeroCtrlPostPafTarget)
    lw      $t9, %lo(zeroCtrlPostPafTarget)($t0)
    jr      $t9
    nop
.globl zeroCtrlPostPafCallTraceEnd
zeroCtrlPostPafCallTraceEnd:
.end zeroCtrlPostPafCallTrace

.globl zeroCtrlPostPafReturnTrace
.type zeroCtrlPostPafReturnTrace @function
.ent zeroCtrlPostPafReturnTrace, 0
zeroCtrlPostPafReturnTrace:
    lui     $t0, %hi(zeroCtrlPostPafSavedRA)
    lw      $t9, %lo(zeroCtrlPostPafSavedRA)($t0)
    lui     $t0, %hi(zeroCtrlPostPafCall0RA)
    lw      $t2, %lo(zeroCtrlPostPafCall0RA)($t0)
    bne     $t9, $t2, 14f
    nop
    lui     $t0, %hi(zeroCtrlPostPafResult0)
    sw      $v0, %lo(zeroCtrlPostPafResult0)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlPostPafReturn0Hits
    addiu   $t2, $zero, 0x0040
    b       15f
    nop
14:
    lui     $t0, %hi(zeroCtrlPostPafResult1)
    sw      $v0, %lo(zeroCtrlPostPafResult1)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlPostPafReturn1Hits
    addiu   $t2, $zero, 0x0100
15:
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    or      $t1, $t1, $t2
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    move    $ra, $t9
    jr      $ra
    nop
.globl zeroCtrlPostPafReturnTraceEnd
zeroCtrlPostPafReturnTraceEnd:
.end zeroCtrlPostPafReturnTrace

.globl zeroCtrlPostVshCallTrace
.type zeroCtrlPostVshCallTrace @function
.ent zeroCtrlPostVshCallTrace, 0
zeroCtrlPostVshCallTrace:
    RECORD_PREFIX_COUNTER zeroCtrlPostVshEntryHits
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0200
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    lui     $t0, %hi(zeroCtrlPostVshSavedRA)
    sw      $ra, %lo(zeroCtrlPostVshSavedRA)($t0)
    lui     $ra, %hi(zeroCtrlPostVshReturnTrace)
    addiu   $ra, $ra, %lo(zeroCtrlPostVshReturnTrace)
    lui     $t0, %hi(zeroCtrlPostVshTarget)
    lw      $t9, %lo(zeroCtrlPostVshTarget)($t0)
    jr      $t9
    nop
.globl zeroCtrlPostVshCallTraceEnd
zeroCtrlPostVshCallTraceEnd:
.end zeroCtrlPostVshCallTrace

.globl zeroCtrlPostVshReturnTrace
.type zeroCtrlPostVshReturnTrace @function
.ent zeroCtrlPostVshReturnTrace, 0
zeroCtrlPostVshReturnTrace:
    lui     $t0, %hi(zeroCtrlPostVshNaturalResult)
    sw      $v0, %lo(zeroCtrlPostVshNaturalResult)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlPostVshReturnHits
    lui     $t0, %hi(zeroCtrlPostPathMask)
    lw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    ori     $t1, $t1, 0x0400
    sw      $t1, %lo(zeroCtrlPostPathMask)($t0)
    lui     $t0, %hi(zeroCtrlPostVshSavedRA)
    lw      $ra, %lo(zeroCtrlPostVshSavedRA)($t0)
    jr      $ra
    nop
.globl zeroCtrlPostVshReturnTraceEnd
zeroCtrlPostVshReturnTraceEnd:
.end zeroCtrlPostVshReturnTrace

/* T15 state-zero path leaves preserve relocated delay slots at each patch. */
.globl zeroCtrlStateZeroCompareTrace
.type zeroCtrlStateZeroCompareTrace @function
.ent zeroCtrlStateZeroCompareTrace, 0
zeroCtrlStateZeroCompareTrace:
    lui     $t0, %hi(zeroCtrlStateZeroCompareLeft)
    sw      $s2, %lo(zeroCtrlStateZeroCompareLeft)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroCompareRight)
    sw      $v1, %lo(zeroCtrlStateZeroCompareRight)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlStateZeroEntryHits
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    ori     $t1, $t1, 0x0001
    beq     $s2, $v1, 30f
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroCompareUnequal)
    lw      $t9, %lo(zeroCtrlStateZeroCompareUnequal)($t0)
    b       31f
    nop
30:
    ori     $t1, $t1, 0x0002
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroCompareEqual)
    lw      $t9, %lo(zeroCtrlStateZeroCompareEqual)($t0)
31:
    jr      $t9
    nop
.globl zeroCtrlStateZeroCompareTraceEnd
zeroCtrlStateZeroCompareTraceEnd:
.end zeroCtrlStateZeroCompareTrace

.globl zeroCtrlStateZeroWordTrace
.type zeroCtrlStateZeroWordTrace @function
.ent zeroCtrlStateZeroWordTrace, 0
zeroCtrlStateZeroWordTrace:
    lui     $t0, %hi(zeroCtrlStateZeroWordValue)
    sw      $v1, %lo(zeroCtrlStateZeroWordValue)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    ori     $t1, $t1, 0x0004
    bnez    $v1, 32f
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroWordZero)
    lw      $t9, %lo(zeroCtrlStateZeroWordZero)($t0)
    b       33f
    nop
32:
    ori     $t1, $t1, 0x0008
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroWordNonzero)
    lw      $t9, %lo(zeroCtrlStateZeroWordNonzero)($t0)
33:
    jr      $t9
    nop
.globl zeroCtrlStateZeroWordTraceEnd
zeroCtrlStateZeroWordTraceEnd:
.end zeroCtrlStateZeroWordTrace

.globl zeroCtrlStateZeroByteTrace
.type zeroCtrlStateZeroByteTrace @function
.ent zeroCtrlStateZeroByteTrace, 0
zeroCtrlStateZeroByteTrace:
    lui     $t0, %hi(zeroCtrlStateZeroByteValue)
    sw      $v1, %lo(zeroCtrlStateZeroByteValue)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    ori     $t1, $t1, 0x0010
    bnez    $v1, 34f
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroByteZero)
    lw      $t9, %lo(zeroCtrlStateZeroByteZero)($t0)
    b       35f
    nop
34:
    ori     $t1, $t1, 0x0020
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroByteNonzero)
    lw      $t9, %lo(zeroCtrlStateZeroByteNonzero)($t0)
35:
    jr      $t9
    nop
.globl zeroCtrlStateZeroByteTraceEnd
zeroCtrlStateZeroByteTraceEnd:
.end zeroCtrlStateZeroByteTrace

.globl zeroCtrlStateZeroVCallTrace
.type zeroCtrlStateZeroVCallTrace @function
.ent zeroCtrlStateZeroVCallTrace, 0
zeroCtrlStateZeroVCallTrace:
    addiu   $sp, $sp, -8
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    lui     $t0, %hi(zeroCtrlStateZeroVCallTarget)
    sw      $v0, %lo(zeroCtrlStateZeroVCallTarget)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroVCallRA)
    sw      $ra, %lo(zeroCtrlStateZeroVCallRA)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroVCallHits)
    lw      $t1, %lo(zeroCtrlStateZeroVCallHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlStateZeroVCallHits)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    ori     $t1, $t1, 0x0040
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $ra, %hi(zeroCtrlStateZeroVReturnTrace)
    addiu   $ra, $ra, %lo(zeroCtrlStateZeroVReturnTrace)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    addiu   $sp, $sp, 8
    jr      $v0
    nop
.globl zeroCtrlStateZeroVCallTraceEnd
zeroCtrlStateZeroVCallTraceEnd:
.end zeroCtrlStateZeroVCallTrace

.globl zeroCtrlStateZeroVReturnTrace
.type zeroCtrlStateZeroVReturnTrace @function
.ent zeroCtrlStateZeroVReturnTrace, 0
zeroCtrlStateZeroVReturnTrace:
    addiu   $sp, $sp, -8
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    lui     $t0, %hi(zeroCtrlStateZeroVCallResult)
    sw      $v0, %lo(zeroCtrlStateZeroVCallResult)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroVReturnHits)
    lw      $t1, %lo(zeroCtrlStateZeroVReturnHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlStateZeroVReturnHits)($t0)
    lui     $t0, %hi(zeroCtrlStateZero15To14CompatMode)
    lw      $t1, %lo(zeroCtrlStateZero15To14CompatMode)($t0)
    beqz    $t1, 65f
    nop
    addiu   $t1, $zero, 15
    bne     $v0, $t1, 65f
    nop
    addiu   $v0, $zero, 14
    lui     $t0, %hi(zeroCtrlStateZero15To14SubstitutionHits)
    lw      $t1, %lo(zeroCtrlStateZero15To14SubstitutionHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlStateZero15To14SubstitutionHits)($t0)
65:
    lui     $t0, %hi(zeroCtrlStateZero15To14EffectiveResult)
    sw      $v0, %lo(zeroCtrlStateZero15To14EffectiveResult)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    ori     $t1, $t1, 0x0080
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroVCallRA)
    lw      $ra, %lo(zeroCtrlStateZeroVCallRA)($t0)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    addiu   $sp, $sp, 8
    jr      $ra
    nop
.globl zeroCtrlStateZeroVReturnTraceEnd
zeroCtrlStateZeroVReturnTraceEnd:
.end zeroCtrlStateZeroVReturnTrace

.globl zeroCtrlField12CWriteTrace
.type zeroCtrlField12CWriteTrace @function
.ent zeroCtrlField12CWriteTrace, 0
zeroCtrlField12CWriteTrace:
    addiu   $sp, $sp, -12
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    lui     $t0, %hi(zeroCtrlField12CWriteHits)
    lw      $t1, %lo(zeroCtrlField12CWriteHits)($t0)
    bnez    $t1, 40f
    nop
    lui     $t0, %hi(zeroCtrlField12CWriteFirst)
    sw      $s3, %lo(zeroCtrlField12CWriteFirst)($t0)
    b       41f
    nop
40:
    lui     $t0, %hi(zeroCtrlField12CWriteLast)
    lw      $t2, %lo(zeroCtrlField12CWriteLast)($t0)
    beq     $t2, $s3, 41f
    nop
    lui     $t0, %hi(zeroCtrlField12CWriteChanges)
    lw      $t2, %lo(zeroCtrlField12CWriteChanges)($t0)
    addiu   $t2, $t2, 1
    sw      $t2, %lo(zeroCtrlField12CWriteChanges)($t0)
41:
    lui     $t0, %hi(zeroCtrlField12CWriteLast)
    sw      $s3, %lo(zeroCtrlField12CWriteLast)($t0)
    lui     $t0, %hi(zeroCtrlField12CWriteContext)
    sw      $v0, %lo(zeroCtrlField12CWriteContext)($t0)
    lui     $t0, %hi(zeroCtrlField12CWriteHits)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlField12CWriteHits)($t0)
    lui     $t0, %hi(zeroCtrlField12CWriteResume)
    lw      $t2, %lo(zeroCtrlField12CWriteResume)($t0)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    addiu   $sp, $sp, 12
    jr      $t2
    lw      $t2, -4($sp)
.globl zeroCtrlField12CWriteTraceEnd
zeroCtrlField12CWriteTraceEnd:
.end zeroCtrlField12CWriteTrace

.globl zeroCtrlCase14Trace
.type zeroCtrlCase14Trace @function
.ent zeroCtrlCase14Trace, 0
zeroCtrlCase14Trace:
    addiu   $sp, $sp, -12
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    lui     $t0, %hi(zeroCtrlCase14Hits)
    lw      $t1, %lo(zeroCtrlCase14Hits)($t0)
    bnez    $t1, 50f
    nop
    lui     $t0, %hi(zeroCtrlCase14FirstRA)
    sw      $ra, %lo(zeroCtrlCase14FirstRA)($t0)
    b       51f
    nop
50:
    lui     $t0, %hi(zeroCtrlCase14LastRA)
    lw      $t2, %lo(zeroCtrlCase14LastRA)($t0)
    beq     $t2, $ra, 51f
    nop
    lui     $t0, %hi(zeroCtrlCase14RAChanges)
    lw      $t2, %lo(zeroCtrlCase14RAChanges)($t0)
    addiu   $t2, $t2, 1
    sw      $t2, %lo(zeroCtrlCase14RAChanges)($t0)
51:
    lui     $t0, %hi(zeroCtrlCase14LastRA)
    sw      $ra, %lo(zeroCtrlCase14LastRA)($t0)
    lui     $t0, %hi(zeroCtrlCase14Hits)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlCase14Hits)($t0)
    lui     $t0, %hi(zeroCtrlCase14Resume)
    lw      $t2, %lo(zeroCtrlCase14Resume)($t0)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    addiu   $sp, $sp, 12
    jr      $t2
    lw      $t2, -4($sp)
.globl zeroCtrlCase14TraceEnd
zeroCtrlCase14TraceEnd:
.end zeroCtrlCase14Trace

.globl zeroCtrlDispatchEntryTrace
.type zeroCtrlDispatchEntryTrace @function
.ent zeroCtrlDispatchEntryTrace, 0
zeroCtrlDispatchEntryTrace:
    addiu   $sp, $sp, -12
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    lui     $t0, %hi(zeroCtrlDispatchEntryHits)
    lw      $t1, %lo(zeroCtrlDispatchEntryHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlDispatchEntryHits)($t0)
    addiu   $t2, $zero, 14
    bne     $a0, $t2, 61f
    nop
    lui     $t0, %hi(zeroCtrlDispatchCase14Hits)
    lw      $t1, %lo(zeroCtrlDispatchCase14Hits)($t0)
    bnez    $t1, 60f
    nop
    lui     $t0, %hi(zeroCtrlDispatchCase14FirstRA)
    sw      $ra, %lo(zeroCtrlDispatchCase14FirstRA)($t0)
    b       62f
    nop
60:
    lui     $t0, %hi(zeroCtrlDispatchCase14LastRA)
    lw      $t2, %lo(zeroCtrlDispatchCase14LastRA)($t0)
    beq     $t2, $ra, 62f
    nop
    lui     $t0, %hi(zeroCtrlDispatchCase14RAChanges)
    lw      $t2, %lo(zeroCtrlDispatchCase14RAChanges)($t0)
    addiu   $t2, $t2, 1
    sw      $t2, %lo(zeroCtrlDispatchCase14RAChanges)($t0)
62:
    lui     $t0, %hi(zeroCtrlDispatchCase14LastRA)
    sw      $ra, %lo(zeroCtrlDispatchCase14LastRA)($t0)
    lui     $t0, %hi(zeroCtrlDispatchCase14Hits)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlDispatchCase14Hits)($t0)
61:
    lui     $t0, %hi(zeroCtrlDispatchEntryResume)
    lw      $t2, %lo(zeroCtrlDispatchEntryResume)($t0)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    addiu   $sp, $sp, 12
    addiu   $sp, $sp, -0x40
    sw      $s2, 0x18($sp)
    jr      $t2
    lw      $t2, 0x3C($sp)
.globl zeroCtrlDispatchEntryTraceEnd
zeroCtrlDispatchEntryTraceEnd:
.end zeroCtrlDispatchEntryTrace

.macro CONSUMER_6F84_TRACE name, counter, result, target
.globl \name
.type \name @function
.ent \name, 0
\name:
    addiu   $sp, $sp, -16
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    sw      $ra, 12($sp)
    lui     $t0, %hi(\counter)
    lw      $t1, %lo(\counter)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(\counter)($t0)
    lui     $t0, %hi(\target)
    lw      $t2, %lo(\target)($t0)
    jalr    $t2
    nop
    lui     $t0, %hi(\result)
    sw      $v0, %lo(\result)($t0)
    lw      $t2, 8($sp)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    lw      $ra, 12($sp)
    addiu   $sp, $sp, 16
    jr      $ra
    nop
.globl \name\()End
\name\()End:
.end \name
.endm

.globl zeroCtrlConsumer13F6CTrace
.type zeroCtrlConsumer13F6CTrace @function
.ent zeroCtrlConsumer13F6CTrace, 0
zeroCtrlConsumer13F6CTrace:
    addiu   $sp, $sp, -16
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    sw      $ra, 12($sp)
    lui     $t0, %hi(zeroCtrlConsumer13F6CHits)
    lw      $t1, %lo(zeroCtrlConsumer13F6CHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlConsumer13F6CHits)($t0)
    lui     $t0, %hi(zeroCtrlConsumer6F84Target)
    lw      $t2, %lo(zeroCtrlConsumer6F84Target)($t0)
    jalr    $t2
    nop
    lui     $t0, %hi(zeroCtrlConsumer13F6CNaturalResult)
    sw      $v0, %lo(zeroCtrlConsumer13F6CNaturalResult)($t0)
    lui     $t0, %hi(zeroCtrlConsumer13F6CCompatMode)
    lw      $t1, %lo(zeroCtrlConsumer13F6CCompatMode)($t0)
    beqz    $t1, 63f
    nop
    bnez    $v0, 63f
    nop
    addiu   $v0, $zero, 1
    lui     $t0, %hi(zeroCtrlConsumer13F6CSubstitutionHits)
    lw      $t1, %lo(zeroCtrlConsumer13F6CSubstitutionHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlConsumer13F6CSubstitutionHits)($t0)
63:
    lui     $t0, %hi(zeroCtrlConsumer13F6CEffectiveResult)
    sw      $v0, %lo(zeroCtrlConsumer13F6CEffectiveResult)($t0)
    lw      $t2, 8($sp)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    lw      $ra, 12($sp)
    addiu   $sp, $sp, 16
    jr      $ra
    nop
.globl zeroCtrlConsumer13F6CTraceEnd
zeroCtrlConsumer13F6CTraceEnd:
.end zeroCtrlConsumer13F6CTrace

.globl zeroCtrlConsumer14020Trace
.type zeroCtrlConsumer14020Trace @function
.ent zeroCtrlConsumer14020Trace, 0
zeroCtrlConsumer14020Trace:
    addiu   $sp, $sp, -16
    sw      $t0, 0($sp)
    sw      $t1, 4($sp)
    sw      $t2, 8($sp)
    sw      $ra, 12($sp)
    lui     $t0, %hi(zeroCtrlConsumer14020Hits)
    lw      $t1, %lo(zeroCtrlConsumer14020Hits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlConsumer14020Hits)($t0)
    lui     $t0, %hi(zeroCtrlConsumer6F84Target)
    lw      $t2, %lo(zeroCtrlConsumer6F84Target)($t0)
    jalr    $t2
    nop
    lui     $t0, %hi(zeroCtrlConsumer14020NaturalResult)
    sw      $v0, %lo(zeroCtrlConsumer14020NaturalResult)($t0)
    lui     $t0, %hi(zeroCtrlConsumer14020CompatMode)
    lw      $t1, %lo(zeroCtrlConsumer14020CompatMode)($t0)
    beqz    $t1, 62f
    nop
    bnez    $v0, 62f
    nop
    addiu   $v0, $zero, 1
    lui     $t0, %hi(zeroCtrlConsumer14020SubstitutionHits)
    lw      $t1, %lo(zeroCtrlConsumer14020SubstitutionHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlConsumer14020SubstitutionHits)($t0)
62:
    lui     $t0, %hi(zeroCtrlConsumer14020EffectiveResult)
    sw      $v0, %lo(zeroCtrlConsumer14020EffectiveResult)($t0)
    lw      $t2, 8($sp)
    lw      $t1, 4($sp)
    lw      $t0, 0($sp)
    lw      $ra, 12($sp)
    addiu   $sp, $sp, 16
    jr      $ra
    nop
.globl zeroCtrlConsumer14020TraceEnd
zeroCtrlConsumer14020TraceEnd:
.end zeroCtrlConsumer14020Trace

CONSUMER_6F84_TRACE zeroCtrlCapability6F44Trace, zeroCtrlCapability6F44Hits, zeroCtrlCapability6F44NaturalResult, zeroCtrlCapability6F44Target
CONSUMER_6F84_TRACE zeroCtrlCapability6FC4Trace, zeroCtrlCapability6FC4Hits, zeroCtrlCapability6FC4NaturalResult, zeroCtrlCapability6FC4Target
CONSUMER_6F84_TRACE zeroCtrlCapability7004Trace, zeroCtrlCapability7004Hits, zeroCtrlCapability7004NaturalResult, zeroCtrlCapability7004Target

.globl zeroCtrlPafCapabilityMaskTrace
.type zeroCtrlPafCapabilityMaskTrace @function
.ent zeroCtrlPafCapabilityMaskTrace, 0
zeroCtrlPafCapabilityMaskTrace:
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskNatural)
    sw      $a0, %lo(zeroCtrlPafCapabilityMaskNatural)($t0)
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskHits)
    lw      $t1, %lo(zeroCtrlPafCapabilityMaskHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlPafCapabilityMaskHits)($t0)
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskCompatMode)
    lw      $t1, %lo(zeroCtrlPafCapabilityMaskCompatMode)($t0)
    beqz    $t1, 64f
    nop
    addiu   $t2, $zero, 2
    bne     $a0, $t2, 64f
    nop
    addiu   $a0, $zero, 0x1E9
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskSubstitutionHits)
    lw      $t1, %lo(zeroCtrlPafCapabilityMaskSubstitutionHits)($t0)
    addiu   $t1, $t1, 1
    sw      $t1, %lo(zeroCtrlPafCapabilityMaskSubstitutionHits)($t0)
64:
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskEffective)
    sw      $a0, %lo(zeroCtrlPafCapabilityMaskEffective)($t0)
    lui     $t0, %hi(zeroCtrlPafCapabilityMaskTarget)
    lw      $t2, %lo(zeroCtrlPafCapabilityMaskTarget)($t0)
    jr      $t2
    nop
.globl zeroCtrlPafCapabilityMaskTraceEnd
zeroCtrlPafCapabilityMaskTraceEnd:
.end zeroCtrlPafCapabilityMaskTrace

.macro STATE_ZERO_CLASS name, limit, bit_true, bit_false, true_slot, false_slot, rejoin
.globl \name
.type \name @function
.ent \name, 0
\name:
    lui     $t0, %hi(zeroCtrlStateZeroVCallResult)
    lw      $t2, %lo(zeroCtrlStateZeroVCallResult)($t0)
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    slti    $t2, $t2, \limit
    beqz    $t2, 36f
    nop
    ori     $t1, $t1, \bit_true
    .if \rejoin
    RECORD_PREFIX_COUNTER zeroCtrlStateZeroRejoinHits
    .endif
    lui     $t0, %hi(\true_slot)
    lw      $t9, %lo(\true_slot)($t0)
    b       37f
    nop
36:
    ori     $t1, $t1, \bit_false
    lui     $t0, %hi(\false_slot)
    lw      $t9, %lo(\false_slot)($t0)
37:
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    jr      $t9
    nop
.end \name
.endm

STATE_ZERO_CLASS zeroCtrlStateZeroClass15Trace, 15, 0x0100, 0x0200, \
    zeroCtrlStateZeroClass15True, zeroCtrlStateZeroClass15False, 1
.globl zeroCtrlStateZeroClass15TraceEnd
zeroCtrlStateZeroClass15TraceEnd:
STATE_ZERO_CLASS zeroCtrlStateZeroClass17Trace, 17, 0x0400, 0x0800, \
    zeroCtrlStateZeroClass17True, zeroCtrlStateZeroClass17False, 0
.globl zeroCtrlStateZeroClass17TraceEnd
zeroCtrlStateZeroClass17TraceEnd:

.globl zeroCtrlStateZeroClass18Trace
.type zeroCtrlStateZeroClass18Trace @function
.ent zeroCtrlStateZeroClass18Trace, 0
zeroCtrlStateZeroClass18Trace:
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    lw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    addiu   $t2, $zero, 18
    bne     $v1, $t2, 38f
    nop
    ori     $t1, $t1, 0x1000
    lui     $t0, %hi(zeroCtrlStateZeroClass18Equal)
    lw      $t9, %lo(zeroCtrlStateZeroClass18Equal)($t0)
    b       39f
    nop
38:
    ori     $t1, $t1, 0x2000
    RECORD_PREFIX_COUNTER zeroCtrlStateZeroRejoinHits
    lui     $t0, %hi(zeroCtrlStateZeroClass18Unequal)
    lw      $t9, %lo(zeroCtrlStateZeroClass18Unequal)($t0)
39:
    lui     $t0, %hi(zeroCtrlStateZeroPathMask)
    sw      $t1, %lo(zeroCtrlStateZeroPathMask)($t0)
    jr      $t9
    nop
.globl zeroCtrlStateZeroClass18TraceEnd
zeroCtrlStateZeroClass18TraceEnd:
.end zeroCtrlStateZeroClass18Trace

.globl zeroCtrlSlidePrefixPafCallTrace
.type zeroCtrlSlidePrefixPafCallTrace @function
.ent zeroCtrlSlidePrefixPafCallTrace, 0
zeroCtrlSlidePrefixPafCallTrace:
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0002
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlidePrefixPafRA)
    sw      $ra, %lo(zeroCtrlSlidePrefixPafRA)($t0)
    lui     $ra, %hi(zeroCtrlSlidePrefixPafReturnTrace)
    addiu   $ra, $ra, %lo(zeroCtrlSlidePrefixPafReturnTrace)
    lui     $t0, %hi(zeroCtrlSlidePrefixPafTarget)
    lw      $t9, %lo(zeroCtrlSlidePrefixPafTarget)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlidePrefixPafCallTraceEnd
zeroCtrlSlidePrefixPafCallTraceEnd:
.end zeroCtrlSlidePrefixPafCallTrace

.globl zeroCtrlSlidePrefixPafReturnTrace
.type zeroCtrlSlidePrefixPafReturnTrace @function
.ent zeroCtrlSlidePrefixPafReturnTrace, 0
zeroCtrlSlidePrefixPafReturnTrace:
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0004
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    lui     $t0, %hi(zeroCtrlSlidePrefixPafNaturalResult)
    sw      $v0, %lo(zeroCtrlSlidePrefixPafNaturalResult)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixPafReturnHits
    lui     $t0, %hi(zeroCtrlSlidePrefixPafCompatMode)
    lw      $t2, %lo(zeroCtrlSlidePrefixPafCompatMode)($t0)
    beqz    $t2, 7f
    nop
    bnez    $v0, 7f
    nop
    lui     $t0, %hi(zeroCtrlSlidePrefixPafSubstitutionHits)
    lw      $t2, %lo(zeroCtrlSlidePrefixPafSubstitutionHits)($t0)
    addiu   $t2, $t2, 1
    sw      $t2, %lo(zeroCtrlSlidePrefixPafSubstitutionHits)($t0)
    addiu   $v0, $zero, 1
7:
    lui     $t0, %hi(zeroCtrlSlidePrefixPafRA)
    lw      $ra, %lo(zeroCtrlSlidePrefixPafRA)($t0)
    jr      $ra
    nop
.globl zeroCtrlSlidePrefixPafReturnTraceEnd
zeroCtrlSlidePrefixPafReturnTraceEnd:
.end zeroCtrlSlidePrefixPafReturnTrace

.globl zeroCtrlSlidePrefixResultTrace
.type zeroCtrlSlidePrefixResultTrace @function
.ent zeroCtrlSlidePrefixResultTrace, 0
zeroCtrlSlidePrefixResultTrace:
    lw      $ra, 28($sp)
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    beqz    $v0, 3f
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0008
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixResultNonzeroHits
    lui     $t0, %hi(zeroCtrlSlidePrefixResultNonzero)
    lw      $t9, %lo(zeroCtrlSlidePrefixResultNonzero)($t0)
    jr      $t9
    nop
3:
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixResultZeroHits
    lui     $t0, %hi(zeroCtrlSlidePrefixResultZero)
    lw      $t9, %lo(zeroCtrlSlidePrefixResultZero)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlidePrefixResultTraceEnd
zeroCtrlSlidePrefixResultTraceEnd:
.end zeroCtrlSlidePrefixResultTrace

.globl zeroCtrlSlidePrefixFlagTrace
.type zeroCtrlSlidePrefixFlagTrace @function
.ent zeroCtrlSlidePrefixFlagTrace, 0
zeroCtrlSlidePrefixFlagTrace:
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0010
    beqz    $v1, 4f
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0020
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixFlagNonzeroHits
    lui     $t0, %hi(zeroCtrlSlidePrefixFlagNonzero)
    lw      $t9, %lo(zeroCtrlSlidePrefixFlagNonzero)($t0)
    jr      $t9
    nop
4:
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixFlagZeroHits
    lui     $t0, %hi(zeroCtrlSlidePrefixFlagZero)
    lw      $t9, %lo(zeroCtrlSlidePrefixFlagZero)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlidePrefixFlagTraceEnd
zeroCtrlSlidePrefixFlagTraceEnd:
.end zeroCtrlSlidePrefixFlagTrace

.globl zeroCtrlSlidePrefixMaskTrace
.type zeroCtrlSlidePrefixMaskTrace @function
.ent zeroCtrlSlidePrefixMaskTrace, 0
zeroCtrlSlidePrefixMaskTrace:
    lui     $t0, %hi(zeroCtrlSlidePrefixPathMask)
    lw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0040
    addiu   $t2, $zero, 0x0101
    bne     $v1, $t2, 5f
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    ori     $t1, $t1, 0x0080
    sw      $t1, %lo(zeroCtrlSlidePrefixPathMask)($t0)
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixMaskEqualHits
    lui     $t0, %hi(zeroCtrlSlidePrefixMaskEqual)
    lw      $t9, %lo(zeroCtrlSlidePrefixMaskEqual)($t0)
    b       6f
    nop
5:
    RECORD_PREFIX_COUNTER zeroCtrlSlidePrefixMaskUnequalHits
    lui     $t0, %hi(zeroCtrlSlidePrefixMaskUnequal)
    lw      $t9, %lo(zeroCtrlSlidePrefixMaskUnequal)($t0)
6:
    lui     $t0, %hi(zeroCtrlSlidePrefixMaskDelayValue)
    lw      $v0, %lo(zeroCtrlSlidePrefixMaskDelayValue)($t0)
    jr      $t9
    nop
.globl zeroCtrlSlidePrefixMaskTraceEnd
zeroCtrlSlidePrefixMaskTraceEnd:
.end zeroCtrlSlidePrefixMaskTrace

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
.globl zeroCtrlSlidePrefixResultZero
zeroCtrlSlidePrefixResultZero: .space 4
.globl zeroCtrlSlidePrefixResultNonzero
zeroCtrlSlidePrefixResultNonzero: .space 4
.globl zeroCtrlSlidePrefixFlagZero
zeroCtrlSlidePrefixFlagZero: .space 4
.globl zeroCtrlSlidePrefixFlagNonzero
zeroCtrlSlidePrefixFlagNonzero: .space 4
.globl zeroCtrlSlidePrefixMaskEqual
zeroCtrlSlidePrefixMaskEqual: .space 4
.globl zeroCtrlSlidePrefixMaskUnequal
zeroCtrlSlidePrefixMaskUnequal: .space 4
.globl zeroCtrlSlidePrefixMaskDelayValue
zeroCtrlSlidePrefixMaskDelayValue: .space 4
.globl zeroCtrlSlidePrefixPathMask
zeroCtrlSlidePrefixPathMask: .space 4
.globl zeroCtrlSlidePrefixResultZeroHits
zeroCtrlSlidePrefixResultZeroHits: .space 4
.globl zeroCtrlSlidePrefixResultNonzeroHits
zeroCtrlSlidePrefixResultNonzeroHits: .space 4
.globl zeroCtrlSlidePrefixFlagZeroHits
zeroCtrlSlidePrefixFlagZeroHits: .space 4
.globl zeroCtrlSlidePrefixFlagNonzeroHits
zeroCtrlSlidePrefixFlagNonzeroHits: .space 4
.globl zeroCtrlSlidePrefixMaskEqualHits
zeroCtrlSlidePrefixMaskEqualHits: .space 4
.globl zeroCtrlSlidePrefixMaskUnequalHits
zeroCtrlSlidePrefixMaskUnequalHits: .space 4
.globl zeroCtrlSlidePrefixPafTarget
zeroCtrlSlidePrefixPafTarget: .space 4
.globl zeroCtrlSlidePrefixPafRA
zeroCtrlSlidePrefixPafRA: .space 4
.globl zeroCtrlSlidePrefixPafCompatMode
zeroCtrlSlidePrefixPafCompatMode: .space 4
.globl zeroCtrlSlidePrefixPafNaturalResult
zeroCtrlSlidePrefixPafNaturalResult: .space 4
.globl zeroCtrlSlidePrefixPafSubstitutionHits
zeroCtrlSlidePrefixPafSubstitutionHits: .space 4
.globl zeroCtrlSlidePrefixPafReturnHits
zeroCtrlSlidePrefixPafReturnHits: .space 4
.globl zeroCtrlPostPathMask
zeroCtrlPostPathMask: .space 4
.globl zeroCtrlPostBSManNaturalResult
zeroCtrlPostBSManNaturalResult: .space 4
.globl zeroCtrlPostBSManCompatMode
zeroCtrlPostBSManCompatMode: .space 4
.globl zeroCtrlPostBSManSubstitutionHits
zeroCtrlPostBSManSubstitutionHits: .space 4
.globl zeroCtrlPostBSManEffectiveResult
zeroCtrlPostBSManEffectiveResult: .space 4
.globl zeroCtrlPostBSManReturnHits
zeroCtrlPostBSManReturnHits: .space 4
.globl zeroCtrlPostBSManZero
zeroCtrlPostBSManZero: .space 4
.globl zeroCtrlPostBSManNonzero
zeroCtrlPostBSManNonzero: .space 4
.globl zeroCtrlPostBSManZeroHits
zeroCtrlPostBSManZeroHits: .space 4
.globl zeroCtrlPostBSManNonzeroHits
zeroCtrlPostBSManNonzeroHits: .space 4
.globl zeroCtrlPostStateZero
zeroCtrlPostStateZero: .space 4
.globl zeroCtrlPostStateNonzero
zeroCtrlPostStateNonzero: .space 4
.globl zeroCtrlPostStateDelayValue
zeroCtrlPostStateDelayValue: .space 4
.globl zeroCtrlPostStateNaturalValue
zeroCtrlPostStateNaturalValue: .space 4
.globl zeroCtrlPostStateZeroHits
zeroCtrlPostStateZeroHits: .space 4
.globl zeroCtrlPostStateNonzeroHits
zeroCtrlPostStateNonzeroHits: .space 4
.globl zeroCtrlPostPafTarget
zeroCtrlPostPafTarget: .space 4
.globl zeroCtrlPostPafCall0RA
zeroCtrlPostPafCall0RA: .space 4
.globl zeroCtrlPostPafCall1RA
zeroCtrlPostPafCall1RA: .space 4
.globl zeroCtrlPostPafSavedRA
zeroCtrlPostPafSavedRA: .space 4
.globl zeroCtrlPostPafResult0
zeroCtrlPostPafResult0: .space 4
.globl zeroCtrlPostPafResult1
zeroCtrlPostPafResult1: .space 4
.globl zeroCtrlPostPafReturn0Hits
zeroCtrlPostPafReturn0Hits: .space 4
.globl zeroCtrlPostPafReturn1Hits
zeroCtrlPostPafReturn1Hits: .space 4
.globl zeroCtrlPostVshTarget
zeroCtrlPostVshTarget: .space 4
.globl zeroCtrlPostVshSavedRA
zeroCtrlPostVshSavedRA: .space 4
.globl zeroCtrlPostVshNaturalResult
zeroCtrlPostVshNaturalResult: .space 4
.globl zeroCtrlPostVshReturnHits
zeroCtrlPostVshReturnHits: .space 4
.globl zeroCtrlPostPafEntry0Hits
zeroCtrlPostPafEntry0Hits: .space 4
.globl zeroCtrlPostPafEntry1Hits
zeroCtrlPostPafEntry1Hits: .space 4
.globl zeroCtrlPostVshEntryHits
zeroCtrlPostVshEntryHits: .space 4
.globl zeroCtrlStateZeroPathMask
zeroCtrlStateZeroPathMask: .space 4
.globl zeroCtrlStateZeroCompareLeft
zeroCtrlStateZeroCompareLeft: .space 4
.globl zeroCtrlStateZeroCompareRight
zeroCtrlStateZeroCompareRight: .space 4
.globl zeroCtrlStateZeroWordValue
zeroCtrlStateZeroWordValue: .space 4
.globl zeroCtrlStateZeroByteValue
zeroCtrlStateZeroByteValue: .space 4
.globl zeroCtrlStateZeroVCallTarget
zeroCtrlStateZeroVCallTarget: .space 4
.globl zeroCtrlStateZeroVCallRA
zeroCtrlStateZeroVCallRA: .space 4
.globl zeroCtrlStateZeroVCallResult
zeroCtrlStateZeroVCallResult: .space 4
.globl zeroCtrlStateZeroEntryHits
zeroCtrlStateZeroEntryHits: .space 4
.globl zeroCtrlStateZeroVCallHits
zeroCtrlStateZeroVCallHits: .space 4
.globl zeroCtrlStateZeroVReturnHits
zeroCtrlStateZeroVReturnHits: .space 4
.globl zeroCtrlStateZero15To14CompatMode
zeroCtrlStateZero15To14CompatMode: .space 4
.globl zeroCtrlStateZero15To14EffectiveResult
zeroCtrlStateZero15To14EffectiveResult: .space 4
.globl zeroCtrlStateZero15To14SubstitutionHits
zeroCtrlStateZero15To14SubstitutionHits: .space 4
.globl zeroCtrlStateZeroRejoinHits
zeroCtrlStateZeroRejoinHits: .space 4
.globl zeroCtrlStateZeroCompareEqual
zeroCtrlStateZeroCompareEqual: .space 4
.globl zeroCtrlStateZeroCompareUnequal
zeroCtrlStateZeroCompareUnequal: .space 4
.globl zeroCtrlStateZeroWordZero
zeroCtrlStateZeroWordZero: .space 4
.globl zeroCtrlStateZeroWordNonzero
zeroCtrlStateZeroWordNonzero: .space 4
.globl zeroCtrlStateZeroByteZero
zeroCtrlStateZeroByteZero: .space 4
.globl zeroCtrlStateZeroByteNonzero
zeroCtrlStateZeroByteNonzero: .space 4
.globl zeroCtrlStateZeroClass15True
zeroCtrlStateZeroClass15True: .space 4
.globl zeroCtrlStateZeroClass15False
zeroCtrlStateZeroClass15False: .space 4
.globl zeroCtrlStateZeroClass17True
zeroCtrlStateZeroClass17True: .space 4
.globl zeroCtrlStateZeroClass17False
zeroCtrlStateZeroClass17False: .space 4
.globl zeroCtrlStateZeroClass18Equal
zeroCtrlStateZeroClass18Equal: .space 4
.globl zeroCtrlStateZeroClass18Unequal
zeroCtrlStateZeroClass18Unequal: .space 4
.globl zeroCtrlField12CWriteResume
zeroCtrlField12CWriteResume: .space 4
.globl zeroCtrlField12CWriteHits
zeroCtrlField12CWriteHits: .space 4
.globl zeroCtrlField12CWriteFirst
zeroCtrlField12CWriteFirst: .space 4
.globl zeroCtrlField12CWriteLast
zeroCtrlField12CWriteLast: .space 4
.globl zeroCtrlField12CWriteChanges
zeroCtrlField12CWriteChanges: .space 4
.globl zeroCtrlField12CWriteContext
zeroCtrlField12CWriteContext: .space 4
.globl zeroCtrlCase14Resume
zeroCtrlCase14Resume: .space 4
.globl zeroCtrlCase14Hits
zeroCtrlCase14Hits: .space 4
.globl zeroCtrlCase14FirstRA
zeroCtrlCase14FirstRA: .space 4
.globl zeroCtrlCase14LastRA
zeroCtrlCase14LastRA: .space 4
.globl zeroCtrlCase14RAChanges
zeroCtrlCase14RAChanges: .space 4
.globl zeroCtrlDispatchEntryResume
zeroCtrlDispatchEntryResume: .space 4
.globl zeroCtrlDispatchEntryHits
zeroCtrlDispatchEntryHits: .space 4
.globl zeroCtrlDispatchCase14Hits
zeroCtrlDispatchCase14Hits: .space 4
.globl zeroCtrlDispatchCase14FirstRA
zeroCtrlDispatchCase14FirstRA: .space 4
.globl zeroCtrlDispatchCase14LastRA
zeroCtrlDispatchCase14LastRA: .space 4
.globl zeroCtrlDispatchCase14RAChanges
zeroCtrlDispatchCase14RAChanges: .space 4
.globl zeroCtrlConsumer6F84Target
zeroCtrlConsumer6F84Target: .space 4
.globl zeroCtrlConsumer13F6CHits
zeroCtrlConsumer13F6CHits: .space 4
.globl zeroCtrlConsumer14020Hits
zeroCtrlConsumer14020Hits: .space 4
.globl zeroCtrlConsumer13F6CNaturalResult
zeroCtrlConsumer13F6CNaturalResult: .space 4
.globl zeroCtrlConsumer14020NaturalResult
zeroCtrlConsumer14020NaturalResult: .space 4
.globl zeroCtrlConsumer14020CompatMode
zeroCtrlConsumer14020CompatMode: .space 4
.globl zeroCtrlConsumer14020EffectiveResult
zeroCtrlConsumer14020EffectiveResult: .space 4
.globl zeroCtrlConsumer14020SubstitutionHits
zeroCtrlConsumer14020SubstitutionHits: .space 4
.globl zeroCtrlConsumer13F6CCompatMode
zeroCtrlConsumer13F6CCompatMode: .space 4
.globl zeroCtrlConsumer13F6CEffectiveResult
zeroCtrlConsumer13F6CEffectiveResult: .space 4
.globl zeroCtrlConsumer13F6CSubstitutionHits
zeroCtrlConsumer13F6CSubstitutionHits: .space 4
.globl zeroCtrlCapability6F44Hits
zeroCtrlCapability6F44Hits: .space 4
.globl zeroCtrlCapability6F44NaturalResult
zeroCtrlCapability6F44NaturalResult: .space 4
.globl zeroCtrlCapability6FC4Hits
zeroCtrlCapability6FC4Hits: .space 4
.globl zeroCtrlCapability6FC4NaturalResult
zeroCtrlCapability6FC4NaturalResult: .space 4
.globl zeroCtrlCapability7004Hits
zeroCtrlCapability7004Hits: .space 4
.globl zeroCtrlCapability7004NaturalResult
zeroCtrlCapability7004NaturalResult: .space 4
.globl zeroCtrlCapability6F44Target
zeroCtrlCapability6F44Target: .space 4
.globl zeroCtrlCapability6FC4Target
zeroCtrlCapability6FC4Target: .space 4
.globl zeroCtrlCapability7004Target
zeroCtrlCapability7004Target: .space 4
.globl zeroCtrlPafCapabilityMaskNatural
zeroCtrlPafCapabilityMaskNatural: .space 4
.globl zeroCtrlPafCapabilityMaskHits
zeroCtrlPafCapabilityMaskHits: .space 4
.globl zeroCtrlPafCapabilityMaskTarget
zeroCtrlPafCapabilityMaskTarget: .space 4
.globl zeroCtrlPafCapabilityMaskCompatMode
zeroCtrlPafCapabilityMaskCompatMode: .space 4
.globl zeroCtrlPafCapabilityMaskEffective
zeroCtrlPafCapabilityMaskEffective: .space 4
.globl zeroCtrlPafCapabilityMaskSubstitutionHits
zeroCtrlPafCapabilityMaskSubstitutionHits: .space 4
