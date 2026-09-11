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

#include <time.h>

//Headers
#include <pspsdk.h>
#include <psputilsforkernel.h>
#include <pspiofilemgr.h>
#include <pspiofilemgr_fcntl.h>
#include <pspsysmem_kernel.h>
#include <pspctrl.h>
#include <psprtc.h>
#include <pspsuspend.h>
#include <psppower.h>

#include <string.h>
#include <stdio.h>

// from CFW SDK
#include "../kernel/psploadcore.h"
#include "../kernel/systemctrl.h"
#include "../kernel/systemctrl_se.h"
#include "../kernel/sony_start_trace.h"
#include "../kernel/bsman_closed_shim.h"

PSP_MODULE_INFO("ZeroVSH_Patcher_User", 0x0007, 0, 1);

#define UNUSED __attribute__((unused))
#define MAKE_CALL(a, f) _sw(0x0C000000 | (((u32)(f) >> 2) & 0x03FFFFFF), a); 
#define REDIRECT_FUNCTION(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a); _sw(0x00000000, a+4); 
#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a);

int devkit;

enum zeroCtrlSlideState {
        ZERO_SLIDE_LOADING = 1,
        ZERO_SLIDE_STARTING,
        ZERO_SLIDE_STARTED,
        ZERO_SLIDE_STOPPING,
	ZERO_SLIDE_STOPPED,
	ZERO_SLIDE_UNLOADED,
};


typedef struct
{
        void *unk; //0
        int id; //4
        char *regkey; //8
        char *text; //C
        char *subtitle; //10
        char *page; //14
} SceSysconfItem; //18

STMOD_HANDLER previous = NULL;

void (* AddSysconfItem)(u32 *option, SceSysconfItem **item) = NULL;
void add_sysconf_item_stub();

void slide_check_stub();

void (* origFuncInit)(u32 *unk0) = NULL;
void slide_start_stub();

int zeroCtrlGetSlideState(void);
void zeroCtrlSetSlideState(int state);

int zeroCtrlGetSlideConfig(const char *item, const char *value);
void zeroCtrlSetSlideConfig(const char *item, char *value);

int zeroCtrlContrast2Hour(void);
int zeroCtrlGetModel(void);
int zeroCtrlIsPsp1000SlideExperimentEnabled(void);
void zeroCtrlRecordVshSlideTarget(int modid, unsigned int text_addr,
        unsigned int text_size, unsigned int module_start_addr,
        unsigned int elf_entry_addr, unsigned int target,
        unsigned int stub_58d4, unsigned int stub_13f6c,
        unsigned int stub_14020, unsigned int counter_58d4,
        unsigned int counter_13f6c, unsigned int counter_14020,
        unsigned int global_stub, unsigned int global_counter);
void zeroCtrlRegisterSonyStartTrace(
        const ZeroCtrlSonyStartTraceRegistration *registration);
void zeroCtrlRegisterBSManClosedShim(
        const ZeroCtrlBSManClosedRegistration *registration);
void zeroCtrlSetLEDState(void);
void zeroCtrlSetBrightness(void);
void zeroCtrlSetClockSpeed(void);

int model;
static ZeroCtrlSonyStartTraceRegistration sonyStartTraceRegistration;
static ZeroCtrlBSManClosedRegistration bsmanClosedRegistration;

//OK
void *zeroCtrlRedir2Stub(u32 address, void *stub, void *func) {
	_sw(_lw(address), (u32)stub);
	_sw(_lw(address + 4), (u32)stub + 4);
    
	MAKE_JUMP((u32)stub + 8, address + 8);
	REDIRECT_FUNCTION(address, func);
    
	return stub;
}
//OK
void zeroCtrlAddSysconfItem(u32 *option, SceSysconfItem **item) {
	if(strcmp((* item)->page, "page_psp_config_slide_action") == 0) {
		return;
	}
	
	AddSysconfItem(option, item);
}
//OK
int zeroCtrlDummyFunc(void) {
	return -1;
}
//OK
int zeroCtrlDummyFunc2(void) {
	return 0;
}
extern int zeroCtrlTrigger58D4(void);
extern int zeroCtrlTrigger13F6C(void);
extern int zeroCtrlTrigger14020(void);
extern volatile unsigned int zeroCtrlTrigger58D4Hits;
extern volatile unsigned int zeroCtrlTrigger13F6CHits;
extern volatile unsigned int zeroCtrlTrigger14020Hits;
extern int zeroCtrlGlobalPredicate6F84True(void);
extern volatile unsigned int zeroCtrlGlobalPredicate6F84Hits;
extern void zeroCtrlSonyModuleStartEntryTrace(void);
extern void zeroCtrlSonyModuleStartEntryTraceEnd(void);
extern void zeroCtrlSonyModuleStartExitTrace(void);
extern void zeroCtrlSonyModuleStartExitTraceEnd(void);
extern volatile unsigned int zeroCtrlSonyModuleStartResume;
extern volatile unsigned int zeroCtrlSonyModuleStartCallerRA;
extern volatile unsigned int zeroCtrlSonyModuleStartEntrySeen;
extern volatile unsigned int zeroCtrlSonyModuleStartReturnSeen;
extern volatile unsigned int zeroCtrlSonyModuleStartResult;
extern int zeroCtrlBSManClosedLeaf(void);
extern void zeroCtrlBSManClosedLeafEnd(void);
extern volatile unsigned int zeroCtrlBSManClosedHits;
extern void zeroCtrlSlideActivationTrace(void);
extern void zeroCtrlSlideActivationTraceEnd(void);
extern volatile unsigned int zeroCtrlSlideActivationResume;
extern volatile unsigned int zeroCtrlSlideActivationHits;
extern void zeroCtrlBSManCallTrace(void);
extern void zeroCtrlBSManCallTraceEnd(void);
extern volatile unsigned int zeroCtrlBSManCallTarget;
extern volatile unsigned int zeroCtrlBSManCallHits;
extern volatile unsigned int zeroCtrlSlideTraceStage;
extern volatile unsigned int zeroCtrlBSManCallRA;
extern void zeroCtrlBSManReturnTrace(void);
extern void zeroCtrlBSManReturnTraceEnd(void);
extern void zeroCtrlSlidePrefixResultTrace(void);
extern void zeroCtrlSlidePrefixResultTraceEnd(void);
extern void zeroCtrlSlidePrefixFlagTrace(void);
extern void zeroCtrlSlidePrefixFlagTraceEnd(void);
extern void zeroCtrlSlidePrefixMaskTrace(void);
extern void zeroCtrlSlidePrefixMaskTraceEnd(void);
extern volatile unsigned int zeroCtrlSlidePrefixResultZero;
extern volatile unsigned int zeroCtrlSlidePrefixResultNonzero;
extern volatile unsigned int zeroCtrlSlidePrefixFlagZero;
extern volatile unsigned int zeroCtrlSlidePrefixFlagNonzero;
extern volatile unsigned int zeroCtrlSlidePrefixMaskEqual;
extern volatile unsigned int zeroCtrlSlidePrefixMaskUnequal;
extern volatile unsigned int zeroCtrlSlidePrefixMaskDelayValue;
extern volatile unsigned int zeroCtrlSlidePrefixPathMask;
extern volatile unsigned int zeroCtrlSlidePrefixResultZeroHits;
extern volatile unsigned int zeroCtrlSlidePrefixResultNonzeroHits;
extern volatile unsigned int zeroCtrlSlidePrefixFlagZeroHits;
extern volatile unsigned int zeroCtrlSlidePrefixFlagNonzeroHits;
extern volatile unsigned int zeroCtrlSlidePrefixMaskEqualHits;
extern volatile unsigned int zeroCtrlSlidePrefixMaskUnequalHits;
extern void zeroCtrlSlidePrefixPafCallTrace(void);
extern void zeroCtrlSlidePrefixPafCallTraceEnd(void);
extern void zeroCtrlSlidePrefixPafReturnTrace(void);
extern void zeroCtrlSlidePrefixPafReturnTraceEnd(void);
extern volatile unsigned int zeroCtrlSlidePrefixPafTarget;
extern volatile unsigned int zeroCtrlSlidePrefixPafRA;
extern volatile unsigned int zeroCtrlSlidePrefixPafCompatMode;
extern volatile unsigned int zeroCtrlSlidePrefixPafNaturalResult;
extern volatile unsigned int zeroCtrlSlidePrefixPafSubstitutionHits;
extern volatile unsigned int zeroCtrlSlidePrefixPafReturnHits;
extern void zeroCtrlPostBSManBranchTrace(void), zeroCtrlPostBSManBranchTraceEnd(void);
extern void zeroCtrlPostStateBranchTrace(void), zeroCtrlPostStateBranchTraceEnd(void);
extern void zeroCtrlPostPafCallTrace(void), zeroCtrlPostPafCallTraceEnd(void);
extern void zeroCtrlPostPafReturnTrace(void), zeroCtrlPostPafReturnTraceEnd(void);
extern void zeroCtrlPostVshCallTrace(void), zeroCtrlPostVshCallTraceEnd(void);
extern void zeroCtrlPostVshReturnTrace(void), zeroCtrlPostVshReturnTraceEnd(void);
extern volatile unsigned int zeroCtrlPostPathMask;
extern volatile unsigned int zeroCtrlPostBSManNaturalResult, zeroCtrlPostBSManReturnHits;
extern volatile unsigned int zeroCtrlPostBSManCompatMode;
extern volatile unsigned int zeroCtrlPostBSManSubstitutionHits;
extern volatile unsigned int zeroCtrlPostBSManEffectiveResult;
extern volatile unsigned int zeroCtrlPostBSManZero, zeroCtrlPostBSManNonzero;
extern volatile unsigned int zeroCtrlPostBSManZeroHits, zeroCtrlPostBSManNonzeroHits;
extern volatile unsigned int zeroCtrlPostStateZero, zeroCtrlPostStateNonzero;
extern volatile unsigned int zeroCtrlPostStateDelayValue;
extern volatile unsigned int zeroCtrlPostStateNaturalValue;
extern volatile unsigned int zeroCtrlPostStateZeroHits, zeroCtrlPostStateNonzeroHits;
extern volatile unsigned int zeroCtrlPostPafTarget, zeroCtrlPostPafCall0RA;
extern volatile unsigned int zeroCtrlPostPafCall1RA, zeroCtrlPostPafSavedRA;
extern volatile unsigned int zeroCtrlPostPafResult0, zeroCtrlPostPafResult1;
extern volatile unsigned int zeroCtrlPostPafReturn0Hits, zeroCtrlPostPafReturn1Hits;
extern volatile unsigned int zeroCtrlPostVshTarget, zeroCtrlPostVshSavedRA;
extern volatile unsigned int zeroCtrlPostVshNaturalResult, zeroCtrlPostVshReturnHits;
extern volatile unsigned int zeroCtrlPostVshArgument, zeroCtrlPostVshCompatMode;
extern volatile unsigned int zeroCtrlPostVshEffectiveResult;
extern volatile unsigned int zeroCtrlPostVshSubstitutionHits;
extern void zeroCtrlPostImposeVCallTrace(void), zeroCtrlPostImposeVCallTraceEnd(void);
extern void zeroCtrlPostImposeVCallReturnTrace(void);
extern void zeroCtrlPostImposeVCallReturnTraceEnd(void);
extern volatile unsigned int zeroCtrlPostImposeVCallTarget;
extern volatile unsigned int zeroCtrlPostImposeVCallSavedRA;
extern volatile unsigned int zeroCtrlPostImposeVCallNaturalResult;
extern volatile unsigned int zeroCtrlPostImposeVCallHits;
extern volatile unsigned int zeroCtrlPostImposeVCallReturnHits;
extern void zeroCtrlPostMinusOneVCall64Trace(void), zeroCtrlPostMinusOneVCall64TraceEnd(void);
extern void zeroCtrlPostMinusOneVCall64ReturnTrace(void);
extern void zeroCtrlPostMinusOneVCall64ReturnTraceEnd(void);
extern volatile unsigned int zeroCtrlPostMinusOneVCall64Target;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64SavedRA;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64NaturalResult;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64Hits;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64ReturnHits;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64CollectionEnabled;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64CountSnapshot;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64ArraySnapshot;
extern volatile unsigned int zeroCtrlPostMinusOneVCall64ArrayReadHits;
extern void zeroCtrlCollectionPafFCF265D8Trace(void);
extern void zeroCtrlCollectionPafFCF265D8TraceEnd(void);
extern volatile unsigned int zeroCtrlCollectionPafFCF265D8LastItem;
extern volatile unsigned int zeroCtrlCollectionPafFCF265D8NaturalResult;
extern volatile unsigned int zeroCtrlCollectionPafFCF265D8Hits;
extern volatile unsigned int zeroCtrlCollectionPafFCF265D8NonzeroHits;
extern void zeroCtrlCollectionPaf9A285882Trace(void);
extern void zeroCtrlCollectionPaf9A285882TraceEnd(void);
extern volatile unsigned int zeroCtrlCollectionPaf9A285882LastItem;
extern volatile unsigned int zeroCtrlCollectionPaf9A285882NaturalResult;
extern volatile unsigned int zeroCtrlCollectionPaf9A285882Hits;
extern volatile unsigned int zeroCtrlCollectionPaf9A285882NonzeroHits;
extern volatile unsigned int zeroCtrlCollectionPaf9A285882ZeroResumeTarget;
extern volatile unsigned int zeroCtrlCollectionPaf9A285882NonzeroTarget;
extern void zeroCtrlPostCollectionPafFCF265D8Trace(void);
extern void zeroCtrlPostCollectionPafFCF265D8TraceEnd(void);
extern volatile unsigned int zeroCtrlPostCollectionPafFCF265D8NaturalResult;
extern volatile unsigned int zeroCtrlPostCollectionPafFCF265D8Hits;
extern volatile unsigned int zeroCtrlPostCollectionPafFCF265D8NonzeroHits;
extern volatile unsigned int zeroCtrlPostCollectionPafFCF265D8ZeroResumeTarget;
extern volatile unsigned int zeroCtrlPostCollectionPafFCF265D8NonzeroTarget;
extern void zeroCtrlMaskedPafC59FC3D0Trace(void);
extern void zeroCtrlMaskedPafC59FC3D0TraceEnd(void);
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0DecisionValue;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0Hits;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0NonzeroHits;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0ZeroResumeTarget;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0NonzeroTarget;
extern void zeroCtrlMaskedPafC59FC3D0SecondTrace(void);
extern void zeroCtrlMaskedPafC59FC3D0SecondTraceEnd(void);
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0SecondDecisionValue;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0SecondHits;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0SecondNonzeroHits;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0SecondZeroResumeTarget;
extern volatile unsigned int zeroCtrlMaskedPafC59FC3D0SecondNonzeroTarget;
extern volatile unsigned int zeroCtrlPostPafEntry0Hits, zeroCtrlPostPafEntry1Hits;
extern volatile unsigned int zeroCtrlPostVshEntryHits;
extern void zeroCtrlStateZeroCompareTrace(void), zeroCtrlStateZeroCompareTraceEnd(void);
extern void zeroCtrlStateZeroWordTrace(void), zeroCtrlStateZeroWordTraceEnd(void);
extern void zeroCtrlStateZeroByteTrace(void), zeroCtrlStateZeroByteTraceEnd(void);
extern void zeroCtrlStateZeroVCallTrace(void), zeroCtrlStateZeroVCallTraceEnd(void);
extern void zeroCtrlStateZeroVReturnTrace(void), zeroCtrlStateZeroVReturnTraceEnd(void);
extern void zeroCtrlStateZeroClass15Trace(void), zeroCtrlStateZeroClass15TraceEnd(void);
extern void zeroCtrlStateZeroClass17Trace(void), zeroCtrlStateZeroClass17TraceEnd(void);
extern void zeroCtrlStateZeroClass18Trace(void), zeroCtrlStateZeroClass18TraceEnd(void);
extern volatile unsigned int zeroCtrlStateZeroPathMask;
extern volatile unsigned int zeroCtrlStateZeroCompareLeft, zeroCtrlStateZeroCompareRight;
extern volatile unsigned int zeroCtrlStateZeroWordValue, zeroCtrlStateZeroByteValue;
extern volatile unsigned int zeroCtrlStateZeroVCallTarget, zeroCtrlStateZeroVCallRA;
extern volatile unsigned int zeroCtrlStateZeroVCallResult;
extern volatile unsigned int zeroCtrlStateZeroEntryHits, zeroCtrlStateZeroVCallHits;
extern volatile unsigned int zeroCtrlStateZeroVReturnHits, zeroCtrlStateZeroRejoinHits;
extern volatile unsigned int zeroCtrlStateZero15To14CompatMode;
extern volatile unsigned int zeroCtrlStateZero15To14EffectiveResult;
extern volatile unsigned int zeroCtrlStateZero15To14SubstitutionHits;
extern volatile unsigned int zeroCtrlStateZeroCompareEqual, zeroCtrlStateZeroCompareUnequal;
extern volatile unsigned int zeroCtrlStateZeroWordZero, zeroCtrlStateZeroWordNonzero;
extern volatile unsigned int zeroCtrlStateZeroByteZero, zeroCtrlStateZeroByteNonzero;
extern volatile unsigned int zeroCtrlStateZeroClass15True, zeroCtrlStateZeroClass15False;
extern volatile unsigned int zeroCtrlStateZeroClass17True, zeroCtrlStateZeroClass17False;
extern volatile unsigned int zeroCtrlStateZeroClass18Equal, zeroCtrlStateZeroClass18Unequal;
extern void zeroCtrlField12CWriteTrace(void), zeroCtrlField12CWriteTraceEnd(void);
extern volatile unsigned int zeroCtrlField12CWriteResume, zeroCtrlField12CWriteHits;
extern volatile unsigned int zeroCtrlField12CWriteFirst, zeroCtrlField12CWriteLast;
extern volatile unsigned int zeroCtrlField12CWriteChanges, zeroCtrlField12CWriteContext;
extern void zeroCtrlCase14Trace(void), zeroCtrlCase14TraceEnd(void);
extern volatile unsigned int zeroCtrlCase14Resume, zeroCtrlCase14Hits;
extern volatile unsigned int zeroCtrlCase14FirstRA, zeroCtrlCase14LastRA;
extern volatile unsigned int zeroCtrlCase14RAChanges;
extern void zeroCtrlDispatchEntryTrace(void), zeroCtrlDispatchEntryTraceEnd(void);
extern volatile unsigned int zeroCtrlDispatchEntryResume, zeroCtrlDispatchEntryHits;
extern volatile unsigned int zeroCtrlDispatchCase14Hits, zeroCtrlDispatchCase14FirstRA;
extern volatile unsigned int zeroCtrlDispatchCase14LastRA, zeroCtrlDispatchCase14RAChanges;
extern void zeroCtrlConsumer13F6CTrace(void), zeroCtrlConsumer13F6CTraceEnd(void);
extern void zeroCtrlConsumer14020Trace(void), zeroCtrlConsumer14020TraceEnd(void);
extern volatile unsigned int zeroCtrlConsumer6F84Target;
extern volatile unsigned int zeroCtrlConsumer13F6CHits, zeroCtrlConsumer14020Hits;
extern volatile unsigned int zeroCtrlConsumer13F6CNaturalResult;
extern volatile unsigned int zeroCtrlConsumer14020NaturalResult;
extern volatile unsigned int zeroCtrlConsumer14020CompatMode;
extern volatile unsigned int zeroCtrlConsumer14020EffectiveResult;
extern volatile unsigned int zeroCtrlConsumer14020SubstitutionHits;
extern volatile unsigned int zeroCtrlConsumer13F6CCompatMode;
extern volatile unsigned int zeroCtrlConsumer13F6CEffectiveResult;
extern volatile unsigned int zeroCtrlConsumer13F6CSubstitutionHits;
extern void zeroCtrlCapability6F44Trace(void), zeroCtrlCapability6F44TraceEnd(void);
extern void zeroCtrlCapability6FC4Trace(void), zeroCtrlCapability6FC4TraceEnd(void);
extern void zeroCtrlCapability7004Trace(void), zeroCtrlCapability7004TraceEnd(void);
extern void zeroCtrlPafCapabilityMaskTrace(void), zeroCtrlPafCapabilityMaskTraceEnd(void);
extern volatile unsigned int zeroCtrlCapability6F44Target, zeroCtrlCapability6FC4Target;
extern volatile unsigned int zeroCtrlCapability7004Target, zeroCtrlPafCapabilityMaskTarget;
extern volatile unsigned int zeroCtrlCapability6F44Hits, zeroCtrlCapability6FC4Hits;
extern volatile unsigned int zeroCtrlCapability7004Hits, zeroCtrlPafCapabilityMaskHits;
extern volatile unsigned int zeroCtrlCapability6F44NaturalResult;
extern volatile unsigned int zeroCtrlCapability6FC4NaturalResult;
extern volatile unsigned int zeroCtrlCapability7004NaturalResult;
extern volatile unsigned int zeroCtrlPafCapabilityMaskNatural;
extern volatile unsigned int zeroCtrlPafCapabilityMaskCompatMode;
extern volatile unsigned int zeroCtrlPafCapabilityMaskEffective;
extern volatile unsigned int zeroCtrlPafCapabilityMaskSubstitutionHits;
//OK
int zeroCtrlGetCurrentClockLocalTime(ScePspDateTime *ptime) {
	int ret, level;		
	int k1 = pspSdkSetK1(0);	
	
	ret = sceRtcGetCurrentClockLocalTime(ptime);
	level = zeroCtrlContrast2Hour();
	
	if(level != -1) {
		ptime->hour = level;
		ptime->minute = 0;
	}
	
	pspSdkSetK1(k1);
	return ret;
}
//OK
void InjectionEntryFuncInit(u32 *unk0) {
	zeroCtrlSetLEDState();	
	zeroCtrlSetBrightness();
	zeroCtrlSetClockSpeed();
	
	origFuncInit(unk0);
}
//OK
int OnModuleStart(SceModule2 *mod) {       
	int psp1000_experiment = zeroCtrlIsPsp1000SlideExperimentEnabled();
	if(((model != 0) && (model != 4)) || psp1000_experiment) {
		if(strcmp(mod->modname, "vsh_module") == 0) {
			if(psp1000_experiment) {
				unsigned int target = mod->text_addr + 0x6F84;
				if(devkit == 0x06060110) {
					zeroCtrlRecordVshSlideTarget(mod->modid, mod->text_addr,
							mod->text_size, mod->module_start_func,
							mod->entry_addr, target,
							(unsigned int)zeroCtrlTrigger58D4,
							(unsigned int)zeroCtrlTrigger13F6C,
							(unsigned int)zeroCtrlTrigger14020,
							(unsigned int)&zeroCtrlTrigger58D4Hits,
							(unsigned int)&zeroCtrlTrigger13F6CHits,
							(unsigned int)&zeroCtrlTrigger14020Hits,
							(unsigned int)zeroCtrlGlobalPredicate6F84True,
							(unsigned int)&zeroCtrlGlobalPredicate6F84Hits);
				}
			} else if(devkit == 0x06020010) {								
				zeroCtrlRedir2Stub(mod->text_addr+0x6D78, slide_check_stub, zeroCtrlDummyFunc);			
			} else if((devkit >= 0x06030010) && (devkit <= 0x06030910)) {		
				zeroCtrlRedir2Stub(mod->text_addr+0x6F6C, slide_check_stub, zeroCtrlDummyFunc);
			} else if((devkit == 0x06060010) || (devkit == 0x06060110)) {
				zeroCtrlRedir2Stub(mod->text_addr+0x6F84, slide_check_stub, zeroCtrlDummyFunc);
			}
		} else if(!psp1000_experiment && strcmp(mod->modname, "sysconf_plugin_module") == 0) {
			if(devkit == 0x06020010) {			
				AddSysconfItem = zeroCtrlRedir2Stub(mod->text_addr+0x27918, add_sysconf_item_stub, zeroCtrlAddSysconfItem);		
			} else if((devkit >= 0x06030010) && (devkit <= 0x06030910)) {			
				AddSysconfItem = zeroCtrlRedir2Stub(mod->text_addr+0x2828C, add_sysconf_item_stub, zeroCtrlAddSysconfItem);		
			} else if((devkit == 0x06060010) || (devkit == 0x06060110)) {
				AddSysconfItem = zeroCtrlRedir2Stub(mod->text_addr+0x286AC, add_sysconf_item_stub, zeroCtrlAddSysconfItem);			
			}
			
			//To avoid the 'open slide' prompt after format 
			MAKE_CALL(mod->text_addr+0x240, zeroCtrlDummyFunc2);
		}  
	}
	
	if(!psp1000_experiment && strcmp(mod->modname, "slide_plugin_module") == 0) {
		MAKE_CALL(mod->text_addr+0xC990, zeroCtrlGetCurrentClockLocalTime);
		origFuncInit = zeroCtrlRedir2Stub(mod->text_addr+0x9038, slide_start_stub, InjectionEntryFuncInit);		
	}
	
       return previous ? previous(mod) : 0;
}
//OK
int module_start(SceSize args UNUSED, void *argp UNUSED) {
	model = zeroCtrlGetModel();
	devkit = sceKernelDevkitVersion();
	sonyStartTraceRegistration.entry_addr =
			(u32)zeroCtrlSonyModuleStartEntryTrace;
	sonyStartTraceRegistration.entry_end_addr =
			(u32)zeroCtrlSonyModuleStartEntryTraceEnd;
	sonyStartTraceRegistration.exit_addr =
			(u32)zeroCtrlSonyModuleStartExitTrace;
	sonyStartTraceRegistration.exit_end_addr =
			(u32)zeroCtrlSonyModuleStartExitTraceEnd;
	sonyStartTraceRegistration.resume_slot_addr =
			(u32)&zeroCtrlSonyModuleStartResume;
	sonyStartTraceRegistration.caller_ra_slot_addr =
			(u32)&zeroCtrlSonyModuleStartCallerRA;
	sonyStartTraceRegistration.entry_seen_addr =
			(u32)&zeroCtrlSonyModuleStartEntrySeen;
	sonyStartTraceRegistration.return_seen_addr =
			(u32)&zeroCtrlSonyModuleStartReturnSeen;
	sonyStartTraceRegistration.result_addr =
			(u32)&zeroCtrlSonyModuleStartResult;
	zeroCtrlRegisterSonyStartTrace(&sonyStartTraceRegistration);
	bsmanClosedRegistration.leaf_addr = (u32)zeroCtrlBSManClosedLeaf;
	bsmanClosedRegistration.leaf_end_addr = (u32)zeroCtrlBSManClosedLeafEnd;
	bsmanClosedRegistration.hit_count_addr =
			(u32)&zeroCtrlBSManClosedHits;
	bsmanClosedRegistration.activation_leaf_addr =
			(u32)zeroCtrlSlideActivationTrace;
	bsmanClosedRegistration.activation_leaf_end_addr =
			(u32)zeroCtrlSlideActivationTraceEnd;
	bsmanClosedRegistration.activation_resume_addr =
			(u32)&zeroCtrlSlideActivationResume;
	bsmanClosedRegistration.activation_hits_addr =
			(u32)&zeroCtrlSlideActivationHits;
	bsmanClosedRegistration.bsman_call_leaf_addr = (u32)zeroCtrlBSManCallTrace;
	bsmanClosedRegistration.bsman_call_leaf_end_addr =
			(u32)zeroCtrlBSManCallTraceEnd;
	bsmanClosedRegistration.bsman_call_target_addr =
			(u32)&zeroCtrlBSManCallTarget;
	bsmanClosedRegistration.bsman_call_hits_addr =
			(u32)&zeroCtrlBSManCallHits;
	bsmanClosedRegistration.trace_stage_addr = (u32)&zeroCtrlSlideTraceStage;
	bsmanClosedRegistration.bsman_call_ra_addr = (u32)&zeroCtrlBSManCallRA;
	bsmanClosedRegistration.bsman_return_leaf_addr =
			(u32)zeroCtrlBSManReturnTrace;
	bsmanClosedRegistration.bsman_return_leaf_end_addr =
			(u32)zeroCtrlBSManReturnTraceEnd;
	bsmanClosedRegistration.prefix_result_leaf_addr =
			(u32)zeroCtrlSlidePrefixResultTrace;
	bsmanClosedRegistration.prefix_result_leaf_end_addr =
			(u32)zeroCtrlSlidePrefixResultTraceEnd;
	bsmanClosedRegistration.prefix_result_zero_addr =
			(u32)&zeroCtrlSlidePrefixResultZero;
	bsmanClosedRegistration.prefix_result_nonzero_addr =
			(u32)&zeroCtrlSlidePrefixResultNonzero;
	bsmanClosedRegistration.prefix_flag_leaf_addr =
			(u32)zeroCtrlSlidePrefixFlagTrace;
	bsmanClosedRegistration.prefix_flag_leaf_end_addr =
			(u32)zeroCtrlSlidePrefixFlagTraceEnd;
	bsmanClosedRegistration.prefix_flag_zero_addr =
			(u32)&zeroCtrlSlidePrefixFlagZero;
	bsmanClosedRegistration.prefix_flag_nonzero_addr =
			(u32)&zeroCtrlSlidePrefixFlagNonzero;
	bsmanClosedRegistration.prefix_mask_leaf_addr =
			(u32)zeroCtrlSlidePrefixMaskTrace;
	bsmanClosedRegistration.prefix_mask_leaf_end_addr =
			(u32)zeroCtrlSlidePrefixMaskTraceEnd;
	bsmanClosedRegistration.prefix_mask_equal_addr =
			(u32)&zeroCtrlSlidePrefixMaskEqual;
	bsmanClosedRegistration.prefix_mask_unequal_addr =
			(u32)&zeroCtrlSlidePrefixMaskUnequal;
	bsmanClosedRegistration.prefix_mask_delay_value_addr =
			(u32)&zeroCtrlSlidePrefixMaskDelayValue;
	bsmanClosedRegistration.prefix_path_mask_addr =
			(u32)&zeroCtrlSlidePrefixPathMask;
	bsmanClosedRegistration.prefix_result_zero_hits_addr =
			(u32)&zeroCtrlSlidePrefixResultZeroHits;
	bsmanClosedRegistration.prefix_result_nonzero_hits_addr =
			(u32)&zeroCtrlSlidePrefixResultNonzeroHits;
	bsmanClosedRegistration.prefix_flag_zero_hits_addr =
			(u32)&zeroCtrlSlidePrefixFlagZeroHits;
	bsmanClosedRegistration.prefix_flag_nonzero_hits_addr =
			(u32)&zeroCtrlSlidePrefixFlagNonzeroHits;
	bsmanClosedRegistration.prefix_mask_equal_hits_addr =
			(u32)&zeroCtrlSlidePrefixMaskEqualHits;
	bsmanClosedRegistration.prefix_mask_unequal_hits_addr =
			(u32)&zeroCtrlSlidePrefixMaskUnequalHits;
	bsmanClosedRegistration.prefix_paf_call_leaf_addr =
			(u32)zeroCtrlSlidePrefixPafCallTrace;
	bsmanClosedRegistration.prefix_paf_call_leaf_end_addr =
			(u32)zeroCtrlSlidePrefixPafCallTraceEnd;
	bsmanClosedRegistration.prefix_paf_return_leaf_addr =
			(u32)zeroCtrlSlidePrefixPafReturnTrace;
	bsmanClosedRegistration.prefix_paf_return_leaf_end_addr =
			(u32)zeroCtrlSlidePrefixPafReturnTraceEnd;
	bsmanClosedRegistration.prefix_paf_target_addr =
			(u32)&zeroCtrlSlidePrefixPafTarget;
	bsmanClosedRegistration.prefix_paf_ra_addr =
			(u32)&zeroCtrlSlidePrefixPafRA;
	bsmanClosedRegistration.prefix_paf_compat_mode_addr =
			(u32)&zeroCtrlSlidePrefixPafCompatMode;
	bsmanClosedRegistration.prefix_paf_natural_result_addr =
			(u32)&zeroCtrlSlidePrefixPafNaturalResult;
	bsmanClosedRegistration.prefix_paf_substitution_hits_addr =
			(u32)&zeroCtrlSlidePrefixPafSubstitutionHits;
	bsmanClosedRegistration.prefix_paf_return_hits_addr =
			(u32)&zeroCtrlSlidePrefixPafReturnHits;
	bsmanClosedRegistration.post_path_mask_addr = (u32)&zeroCtrlPostPathMask;
	bsmanClosedRegistration.bsman_natural_result_addr =
			(u32)&zeroCtrlPostBSManNaturalResult;
	bsmanClosedRegistration.bsman_compat_mode_addr =
			(u32)&zeroCtrlPostBSManCompatMode;
	bsmanClosedRegistration.bsman_substitution_hits_addr =
			(u32)&zeroCtrlPostBSManSubstitutionHits;
	bsmanClosedRegistration.bsman_effective_result_addr =
			(u32)&zeroCtrlPostBSManEffectiveResult;
	bsmanClosedRegistration.bsman_return_hits_addr =
			(u32)&zeroCtrlPostBSManReturnHits;
	bsmanClosedRegistration.post_bs_branch_leaf_addr =
			(u32)zeroCtrlPostBSManBranchTrace;
	bsmanClosedRegistration.post_bs_branch_leaf_end_addr =
			(u32)zeroCtrlPostBSManBranchTraceEnd;
	bsmanClosedRegistration.post_bs_zero_addr = (u32)&zeroCtrlPostBSManZero;
	bsmanClosedRegistration.post_bs_nonzero_addr = (u32)&zeroCtrlPostBSManNonzero;
	bsmanClosedRegistration.post_bs_zero_hits_addr =
			(u32)&zeroCtrlPostBSManZeroHits;
	bsmanClosedRegistration.post_bs_nonzero_hits_addr =
			(u32)&zeroCtrlPostBSManNonzeroHits;
	bsmanClosedRegistration.post_state_branch_leaf_addr =
			(u32)zeroCtrlPostStateBranchTrace;
	bsmanClosedRegistration.post_state_branch_leaf_end_addr =
			(u32)zeroCtrlPostStateBranchTraceEnd;
	bsmanClosedRegistration.post_state_zero_addr = (u32)&zeroCtrlPostStateZero;
	bsmanClosedRegistration.post_state_nonzero_addr = (u32)&zeroCtrlPostStateNonzero;
	bsmanClosedRegistration.post_state_delay_value_addr =
			(u32)&zeroCtrlPostStateDelayValue;
	bsmanClosedRegistration.post_state_natural_value_addr =
			(u32)&zeroCtrlPostStateNaturalValue;
	bsmanClosedRegistration.post_state_zero_hits_addr =
			(u32)&zeroCtrlPostStateZeroHits;
	bsmanClosedRegistration.post_state_nonzero_hits_addr =
			(u32)&zeroCtrlPostStateNonzeroHits;
	bsmanClosedRegistration.post_paf_call_leaf_addr = (u32)zeroCtrlPostPafCallTrace;
	bsmanClosedRegistration.post_paf_call_leaf_end_addr =
			(u32)zeroCtrlPostPafCallTraceEnd;
	bsmanClosedRegistration.post_paf_return_leaf_addr =
			(u32)zeroCtrlPostPafReturnTrace;
	bsmanClosedRegistration.post_paf_return_leaf_end_addr =
			(u32)zeroCtrlPostPafReturnTraceEnd;
	bsmanClosedRegistration.post_paf_target_addr = (u32)&zeroCtrlPostPafTarget;
	bsmanClosedRegistration.post_paf_call0_ra_addr = (u32)&zeroCtrlPostPafCall0RA;
	bsmanClosedRegistration.post_paf_call1_ra_addr = (u32)&zeroCtrlPostPafCall1RA;
	bsmanClosedRegistration.post_paf_saved_ra_addr = (u32)&zeroCtrlPostPafSavedRA;
	bsmanClosedRegistration.post_paf_result0_addr = (u32)&zeroCtrlPostPafResult0;
	bsmanClosedRegistration.post_paf_result1_addr = (u32)&zeroCtrlPostPafResult1;
	bsmanClosedRegistration.post_paf_return0_hits_addr =
			(u32)&zeroCtrlPostPafReturn0Hits;
	bsmanClosedRegistration.post_paf_return1_hits_addr =
			(u32)&zeroCtrlPostPafReturn1Hits;
	bsmanClosedRegistration.post_vsh_call_leaf_addr = (u32)zeroCtrlPostVshCallTrace;
	bsmanClosedRegistration.post_vsh_call_leaf_end_addr =
			(u32)zeroCtrlPostVshCallTraceEnd;
	bsmanClosedRegistration.post_vsh_return_leaf_addr =
			(u32)zeroCtrlPostVshReturnTrace;
	bsmanClosedRegistration.post_vsh_return_leaf_end_addr =
			(u32)zeroCtrlPostVshReturnTraceEnd;
	bsmanClosedRegistration.post_vsh_target_addr = (u32)&zeroCtrlPostVshTarget;
	bsmanClosedRegistration.post_vsh_saved_ra_addr = (u32)&zeroCtrlPostVshSavedRA;
	bsmanClosedRegistration.post_vsh_natural_result_addr =
			(u32)&zeroCtrlPostVshNaturalResult;
	bsmanClosedRegistration.post_vsh_return_hits_addr =
			(u32)&zeroCtrlPostVshReturnHits;
	bsmanClosedRegistration.post_paf_entry0_hits_addr =
			(u32)&zeroCtrlPostPafEntry0Hits;
	bsmanClosedRegistration.post_paf_entry1_hits_addr =
			(u32)&zeroCtrlPostPafEntry1Hits;
	bsmanClosedRegistration.post_vsh_entry_hits_addr =
			(u32)&zeroCtrlPostVshEntryHits;
	bsmanClosedRegistration.state_zero_cmp_leaf_addr = (u32)zeroCtrlStateZeroCompareTrace;
	bsmanClosedRegistration.state_zero_cmp_leaf_end_addr = (u32)zeroCtrlStateZeroCompareTraceEnd;
	bsmanClosedRegistration.state_zero_word_leaf_addr = (u32)zeroCtrlStateZeroWordTrace;
	bsmanClosedRegistration.state_zero_word_leaf_end_addr = (u32)zeroCtrlStateZeroWordTraceEnd;
	bsmanClosedRegistration.state_zero_byte_leaf_addr = (u32)zeroCtrlStateZeroByteTrace;
	bsmanClosedRegistration.state_zero_byte_leaf_end_addr = (u32)zeroCtrlStateZeroByteTraceEnd;
	bsmanClosedRegistration.state_zero_vcall_leaf_addr = (u32)zeroCtrlStateZeroVCallTrace;
	bsmanClosedRegistration.state_zero_vcall_leaf_end_addr = (u32)zeroCtrlStateZeroVCallTraceEnd;
	bsmanClosedRegistration.state_zero_vreturn_leaf_addr = (u32)zeroCtrlStateZeroVReturnTrace;
	bsmanClosedRegistration.state_zero_vreturn_leaf_end_addr = (u32)zeroCtrlStateZeroVReturnTraceEnd;
	bsmanClosedRegistration.state_zero_class15_leaf_addr = (u32)zeroCtrlStateZeroClass15Trace;
	bsmanClosedRegistration.state_zero_class15_leaf_end_addr = (u32)zeroCtrlStateZeroClass15TraceEnd;
	bsmanClosedRegistration.state_zero_class17_leaf_addr = (u32)zeroCtrlStateZeroClass17Trace;
	bsmanClosedRegistration.state_zero_class17_leaf_end_addr = (u32)zeroCtrlStateZeroClass17TraceEnd;
	bsmanClosedRegistration.state_zero_class18_leaf_addr = (u32)zeroCtrlStateZeroClass18Trace;
	bsmanClosedRegistration.state_zero_class18_leaf_end_addr = (u32)zeroCtrlStateZeroClass18TraceEnd;
	bsmanClosedRegistration.state_zero_path_mask_addr = (u32)&zeroCtrlStateZeroPathMask;
	bsmanClosedRegistration.state_zero_cmp_left_addr = (u32)&zeroCtrlStateZeroCompareLeft;
	bsmanClosedRegistration.state_zero_cmp_right_addr = (u32)&zeroCtrlStateZeroCompareRight;
	bsmanClosedRegistration.state_zero_word_value_addr = (u32)&zeroCtrlStateZeroWordValue;
	bsmanClosedRegistration.state_zero_byte_value_addr = (u32)&zeroCtrlStateZeroByteValue;
	bsmanClosedRegistration.state_zero_vcall_target_addr = (u32)&zeroCtrlStateZeroVCallTarget;
	bsmanClosedRegistration.state_zero_vcall_ra_addr = (u32)&zeroCtrlStateZeroVCallRA;
	bsmanClosedRegistration.state_zero_vcall_result_addr = (u32)&zeroCtrlStateZeroVCallResult;
	bsmanClosedRegistration.state_zero_entry_hits_addr = (u32)&zeroCtrlStateZeroEntryHits;
	bsmanClosedRegistration.state_zero_vcall_hits_addr = (u32)&zeroCtrlStateZeroVCallHits;
	bsmanClosedRegistration.state_zero_vreturn_hits_addr = (u32)&zeroCtrlStateZeroVReturnHits;
	bsmanClosedRegistration.state_zero_rejoin_hits_addr = (u32)&zeroCtrlStateZeroRejoinHits;
	bsmanClosedRegistration.state_zero_cmp_equal_addr = (u32)&zeroCtrlStateZeroCompareEqual;
	bsmanClosedRegistration.state_zero_cmp_unequal_addr = (u32)&zeroCtrlStateZeroCompareUnequal;
	bsmanClosedRegistration.state_zero_word_zero_addr = (u32)&zeroCtrlStateZeroWordZero;
	bsmanClosedRegistration.state_zero_word_nonzero_addr = (u32)&zeroCtrlStateZeroWordNonzero;
	bsmanClosedRegistration.state_zero_byte_zero_addr = (u32)&zeroCtrlStateZeroByteZero;
	bsmanClosedRegistration.state_zero_byte_nonzero_addr = (u32)&zeroCtrlStateZeroByteNonzero;
	bsmanClosedRegistration.state_zero_class15_true_addr = (u32)&zeroCtrlStateZeroClass15True;
	bsmanClosedRegistration.state_zero_class15_false_addr = (u32)&zeroCtrlStateZeroClass15False;
	bsmanClosedRegistration.state_zero_class17_true_addr = (u32)&zeroCtrlStateZeroClass17True;
	bsmanClosedRegistration.state_zero_class17_false_addr = (u32)&zeroCtrlStateZeroClass17False;
	bsmanClosedRegistration.state_zero_class18_equal_addr = (u32)&zeroCtrlStateZeroClass18Equal;
	bsmanClosedRegistration.state_zero_class18_unequal_addr = (u32)&zeroCtrlStateZeroClass18Unequal;
	bsmanClosedRegistration.field12c_write_leaf_addr = (u32)zeroCtrlField12CWriteTrace;
	bsmanClosedRegistration.field12c_write_leaf_end_addr = (u32)zeroCtrlField12CWriteTraceEnd;
	bsmanClosedRegistration.field12c_write_resume_addr = (u32)&zeroCtrlField12CWriteResume;
	bsmanClosedRegistration.field12c_write_hits_addr = (u32)&zeroCtrlField12CWriteHits;
	bsmanClosedRegistration.field12c_write_first_addr = (u32)&zeroCtrlField12CWriteFirst;
	bsmanClosedRegistration.field12c_write_last_addr = (u32)&zeroCtrlField12CWriteLast;
	bsmanClosedRegistration.field12c_write_changes_addr = (u32)&zeroCtrlField12CWriteChanges;
	bsmanClosedRegistration.field12c_write_context_addr = (u32)&zeroCtrlField12CWriteContext;
	bsmanClosedRegistration.case14_leaf_addr = (u32)zeroCtrlCase14Trace;
	bsmanClosedRegistration.case14_leaf_end_addr = (u32)zeroCtrlCase14TraceEnd;
	bsmanClosedRegistration.case14_resume_addr = (u32)&zeroCtrlCase14Resume;
	bsmanClosedRegistration.case14_hits_addr = (u32)&zeroCtrlCase14Hits;
	bsmanClosedRegistration.case14_first_ra_addr = (u32)&zeroCtrlCase14FirstRA;
	bsmanClosedRegistration.case14_last_ra_addr = (u32)&zeroCtrlCase14LastRA;
	bsmanClosedRegistration.case14_ra_changes_addr = (u32)&zeroCtrlCase14RAChanges;
	bsmanClosedRegistration.dispatch_entry_leaf_addr = (u32)zeroCtrlDispatchEntryTrace;
	bsmanClosedRegistration.dispatch_entry_leaf_end_addr = (u32)zeroCtrlDispatchEntryTraceEnd;
	bsmanClosedRegistration.dispatch_entry_resume_addr = (u32)&zeroCtrlDispatchEntryResume;
	bsmanClosedRegistration.dispatch_entry_hits_addr = (u32)&zeroCtrlDispatchEntryHits;
	bsmanClosedRegistration.dispatch_case14_hits_addr = (u32)&zeroCtrlDispatchCase14Hits;
	bsmanClosedRegistration.dispatch_case14_first_ra_addr = (u32)&zeroCtrlDispatchCase14FirstRA;
	bsmanClosedRegistration.dispatch_case14_last_ra_addr = (u32)&zeroCtrlDispatchCase14LastRA;
	bsmanClosedRegistration.dispatch_case14_ra_changes_addr = (u32)&zeroCtrlDispatchCase14RAChanges;
	bsmanClosedRegistration.consumer_13f6c_leaf_addr = (u32)zeroCtrlConsumer13F6CTrace;
	bsmanClosedRegistration.consumer_13f6c_leaf_end_addr = (u32)zeroCtrlConsumer13F6CTraceEnd;
	bsmanClosedRegistration.consumer_14020_leaf_addr = (u32)zeroCtrlConsumer14020Trace;
	bsmanClosedRegistration.consumer_14020_leaf_end_addr = (u32)zeroCtrlConsumer14020TraceEnd;
	bsmanClosedRegistration.consumer_6f84_target_addr = (u32)&zeroCtrlConsumer6F84Target;
	bsmanClosedRegistration.consumer_13f6c_hits_addr = (u32)&zeroCtrlConsumer13F6CHits;
	bsmanClosedRegistration.consumer_14020_hits_addr = (u32)&zeroCtrlConsumer14020Hits;
	bsmanClosedRegistration.consumer_13f6c_result_addr =
			(u32)&zeroCtrlConsumer13F6CNaturalResult;
	bsmanClosedRegistration.consumer_14020_result_addr =
			(u32)&zeroCtrlConsumer14020NaturalResult;
	bsmanClosedRegistration.consumer_14020_compat_mode_addr =
			(u32)&zeroCtrlConsumer14020CompatMode;
	bsmanClosedRegistration.consumer_14020_effective_result_addr =
			(u32)&zeroCtrlConsumer14020EffectiveResult;
	bsmanClosedRegistration.consumer_14020_substitution_hits_addr =
			(u32)&zeroCtrlConsumer14020SubstitutionHits;
	bsmanClosedRegistration.consumer_13f6c_compat_mode_addr =
			(u32)&zeroCtrlConsumer13F6CCompatMode;
	bsmanClosedRegistration.consumer_13f6c_effective_result_addr =
			(u32)&zeroCtrlConsumer13F6CEffectiveResult;
	bsmanClosedRegistration.consumer_13f6c_substitution_hits_addr =
			(u32)&zeroCtrlConsumer13F6CSubstitutionHits;
	bsmanClosedRegistration.capability_leaf_addr[0] = (u32)zeroCtrlCapability6F44Trace;
	bsmanClosedRegistration.capability_leaf_addr[1] = (u32)zeroCtrlCapability6FC4Trace;
	bsmanClosedRegistration.capability_leaf_addr[2] = (u32)zeroCtrlCapability7004Trace;
	bsmanClosedRegistration.capability_leaf_end_addr[0] = (u32)zeroCtrlCapability6F44TraceEnd;
	bsmanClosedRegistration.capability_leaf_end_addr[1] = (u32)zeroCtrlCapability6FC4TraceEnd;
	bsmanClosedRegistration.capability_leaf_end_addr[2] = (u32)zeroCtrlCapability7004TraceEnd;
	bsmanClosedRegistration.capability_target_addr[0] = (u32)&zeroCtrlCapability6F44Target;
	bsmanClosedRegistration.capability_target_addr[1] = (u32)&zeroCtrlCapability6FC4Target;
	bsmanClosedRegistration.capability_target_addr[2] = (u32)&zeroCtrlCapability7004Target;
	bsmanClosedRegistration.capability_hits_addr[0] = (u32)&zeroCtrlCapability6F44Hits;
	bsmanClosedRegistration.capability_hits_addr[1] = (u32)&zeroCtrlCapability6FC4Hits;
	bsmanClosedRegistration.capability_hits_addr[2] = (u32)&zeroCtrlCapability7004Hits;
	bsmanClosedRegistration.capability_result_addr[0] = (u32)&zeroCtrlCapability6F44NaturalResult;
	bsmanClosedRegistration.capability_result_addr[1] = (u32)&zeroCtrlCapability6FC4NaturalResult;
	bsmanClosedRegistration.capability_result_addr[2] = (u32)&zeroCtrlCapability7004NaturalResult;
	bsmanClosedRegistration.paf_mask_leaf_addr = (u32)zeroCtrlPafCapabilityMaskTrace;
	bsmanClosedRegistration.paf_mask_leaf_end_addr = (u32)zeroCtrlPafCapabilityMaskTraceEnd;
	bsmanClosedRegistration.paf_mask_target_addr = (u32)&zeroCtrlPafCapabilityMaskTarget;
	bsmanClosedRegistration.paf_mask_hits_addr = (u32)&zeroCtrlPafCapabilityMaskHits;
	bsmanClosedRegistration.paf_mask_natural_addr = (u32)&zeroCtrlPafCapabilityMaskNatural;
	bsmanClosedRegistration.paf_mask_compat_mode_addr = (u32)&zeroCtrlPafCapabilityMaskCompatMode;
	bsmanClosedRegistration.paf_mask_effective_addr = (u32)&zeroCtrlPafCapabilityMaskEffective;
	bsmanClosedRegistration.paf_mask_substitution_hits_addr =
			(u32)&zeroCtrlPafCapabilityMaskSubstitutionHits;
	bsmanClosedRegistration.state_zero_15to14_compat_mode_addr =
			(u32)&zeroCtrlStateZero15To14CompatMode;
	bsmanClosedRegistration.state_zero_15to14_effective_result_addr =
			(u32)&zeroCtrlStateZero15To14EffectiveResult;
	bsmanClosedRegistration.state_zero_15to14_substitution_hits_addr =
			(u32)&zeroCtrlStateZero15To14SubstitutionHits;
	bsmanClosedRegistration.post_vsh_argument_addr = (u32)&zeroCtrlPostVshArgument;
	bsmanClosedRegistration.post_vsh_compat_mode_addr = (u32)&zeroCtrlPostVshCompatMode;
	bsmanClosedRegistration.post_vsh_effective_result_addr =
			(u32)&zeroCtrlPostVshEffectiveResult;
	bsmanClosedRegistration.post_vsh_substitution_hits_addr =
			(u32)&zeroCtrlPostVshSubstitutionHits;
	bsmanClosedRegistration.post_impose_vcall_leaf_addr =
			(u32)zeroCtrlPostImposeVCallTrace;
	bsmanClosedRegistration.post_impose_vcall_leaf_end_addr =
			(u32)zeroCtrlPostImposeVCallTraceEnd;
	bsmanClosedRegistration.post_impose_vcall_return_leaf_addr =
			(u32)zeroCtrlPostImposeVCallReturnTrace;
	bsmanClosedRegistration.post_impose_vcall_return_leaf_end_addr =
			(u32)zeroCtrlPostImposeVCallReturnTraceEnd;
	bsmanClosedRegistration.post_impose_vcall_target_addr =
			(u32)&zeroCtrlPostImposeVCallTarget;
	bsmanClosedRegistration.post_impose_vcall_saved_ra_addr =
			(u32)&zeroCtrlPostImposeVCallSavedRA;
	bsmanClosedRegistration.post_impose_vcall_natural_result_addr =
			(u32)&zeroCtrlPostImposeVCallNaturalResult;
	bsmanClosedRegistration.post_impose_vcall_hits_addr =
			(u32)&zeroCtrlPostImposeVCallHits;
	bsmanClosedRegistration.post_impose_vcall_return_hits_addr =
			(u32)&zeroCtrlPostImposeVCallReturnHits;
	bsmanClosedRegistration.post_minus_one_vcall64_leaf_addr =
			(u32)zeroCtrlPostMinusOneVCall64Trace;
	bsmanClosedRegistration.post_minus_one_vcall64_leaf_end_addr =
			(u32)zeroCtrlPostMinusOneVCall64TraceEnd;
	bsmanClosedRegistration.post_minus_one_vcall64_return_leaf_addr =
			(u32)zeroCtrlPostMinusOneVCall64ReturnTrace;
	bsmanClosedRegistration.post_minus_one_vcall64_return_leaf_end_addr =
			(u32)zeroCtrlPostMinusOneVCall64ReturnTraceEnd;
	bsmanClosedRegistration.post_minus_one_vcall64_target_addr =
			(u32)&zeroCtrlPostMinusOneVCall64Target;
	bsmanClosedRegistration.post_minus_one_vcall64_saved_ra_addr =
			(u32)&zeroCtrlPostMinusOneVCall64SavedRA;
	bsmanClosedRegistration.post_minus_one_vcall64_natural_result_addr =
			(u32)&zeroCtrlPostMinusOneVCall64NaturalResult;
	bsmanClosedRegistration.post_minus_one_vcall64_hits_addr =
			(u32)&zeroCtrlPostMinusOneVCall64Hits;
	bsmanClosedRegistration.post_minus_one_vcall64_return_hits_addr =
			(u32)&zeroCtrlPostMinusOneVCall64ReturnHits;
	bsmanClosedRegistration.post_minus_one_vcall64_collection_enabled_addr =
			(u32)&zeroCtrlPostMinusOneVCall64CollectionEnabled;
	bsmanClosedRegistration.post_minus_one_vcall64_count_snapshot_addr =
			(u32)&zeroCtrlPostMinusOneVCall64CountSnapshot;
	bsmanClosedRegistration.post_minus_one_vcall64_array_snapshot_addr =
			(u32)&zeroCtrlPostMinusOneVCall64ArraySnapshot;
	bsmanClosedRegistration.post_minus_one_vcall64_array_read_hits_addr =
			(u32)&zeroCtrlPostMinusOneVCall64ArrayReadHits;
	bsmanClosedRegistration.collection_paf_fcf265d8_leaf_addr =
			(u32)zeroCtrlCollectionPafFCF265D8Trace;
	bsmanClosedRegistration.collection_paf_fcf265d8_leaf_end_addr =
			(u32)zeroCtrlCollectionPafFCF265D8TraceEnd;
	bsmanClosedRegistration.collection_paf_fcf265d8_last_item_addr =
			(u32)&zeroCtrlCollectionPafFCF265D8LastItem;
	bsmanClosedRegistration.collection_paf_fcf265d8_natural_result_addr =
			(u32)&zeroCtrlCollectionPafFCF265D8NaturalResult;
	bsmanClosedRegistration.collection_paf_fcf265d8_hits_addr =
			(u32)&zeroCtrlCollectionPafFCF265D8Hits;
	bsmanClosedRegistration.collection_paf_fcf265d8_nonzero_hits_addr =
			(u32)&zeroCtrlCollectionPafFCF265D8NonzeroHits;
	bsmanClosedRegistration.collection_paf_9a285882_leaf_addr = (u32)zeroCtrlCollectionPaf9A285882Trace;
	bsmanClosedRegistration.collection_paf_9a285882_leaf_end_addr = (u32)zeroCtrlCollectionPaf9A285882TraceEnd;
	bsmanClosedRegistration.collection_paf_9a285882_last_item_addr = (u32)&zeroCtrlCollectionPaf9A285882LastItem;
	bsmanClosedRegistration.collection_paf_9a285882_natural_result_addr = (u32)&zeroCtrlCollectionPaf9A285882NaturalResult;
	bsmanClosedRegistration.collection_paf_9a285882_hits_addr = (u32)&zeroCtrlCollectionPaf9A285882Hits;
	bsmanClosedRegistration.collection_paf_9a285882_nonzero_hits_addr = (u32)&zeroCtrlCollectionPaf9A285882NonzeroHits;
	bsmanClosedRegistration.collection_paf_9a285882_zero_resume_target_addr = (u32)&zeroCtrlCollectionPaf9A285882ZeroResumeTarget;
	bsmanClosedRegistration.collection_paf_9a285882_nonzero_target_addr = (u32)&zeroCtrlCollectionPaf9A285882NonzeroTarget;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_leaf_addr = (u32)zeroCtrlPostCollectionPafFCF265D8Trace;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_leaf_end_addr = (u32)zeroCtrlPostCollectionPafFCF265D8TraceEnd;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_natural_result_addr = (u32)&zeroCtrlPostCollectionPafFCF265D8NaturalResult;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_hits_addr = (u32)&zeroCtrlPostCollectionPafFCF265D8Hits;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_nonzero_hits_addr = (u32)&zeroCtrlPostCollectionPafFCF265D8NonzeroHits;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_zero_resume_target_addr = (u32)&zeroCtrlPostCollectionPafFCF265D8ZeroResumeTarget;
	bsmanClosedRegistration.post_collection_paf_fcf265d8_nonzero_target_addr = (u32)&zeroCtrlPostCollectionPafFCF265D8NonzeroTarget;
	bsmanClosedRegistration.masked_paf_c59fc3d0_leaf_addr = (u32)zeroCtrlMaskedPafC59FC3D0Trace;
	bsmanClosedRegistration.masked_paf_c59fc3d0_leaf_end_addr = (u32)zeroCtrlMaskedPafC59FC3D0TraceEnd;
	bsmanClosedRegistration.masked_paf_c59fc3d0_decision_value_addr = (u32)&zeroCtrlMaskedPafC59FC3D0DecisionValue;
	bsmanClosedRegistration.masked_paf_c59fc3d0_hits_addr = (u32)&zeroCtrlMaskedPafC59FC3D0Hits;
	bsmanClosedRegistration.masked_paf_c59fc3d0_nonzero_hits_addr = (u32)&zeroCtrlMaskedPafC59FC3D0NonzeroHits;
	bsmanClosedRegistration.masked_paf_c59fc3d0_zero_resume_target_addr = (u32)&zeroCtrlMaskedPafC59FC3D0ZeroResumeTarget;
	bsmanClosedRegistration.masked_paf_c59fc3d0_nonzero_target_addr = (u32)&zeroCtrlMaskedPafC59FC3D0NonzeroTarget;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_leaf_addr = (u32)zeroCtrlMaskedPafC59FC3D0SecondTrace;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_leaf_end_addr = (u32)zeroCtrlMaskedPafC59FC3D0SecondTraceEnd;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_decision_value_addr = (u32)&zeroCtrlMaskedPafC59FC3D0SecondDecisionValue;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_hits_addr = (u32)&zeroCtrlMaskedPafC59FC3D0SecondHits;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_nonzero_hits_addr = (u32)&zeroCtrlMaskedPafC59FC3D0SecondNonzeroHits;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_zero_resume_target_addr = (u32)&zeroCtrlMaskedPafC59FC3D0SecondZeroResumeTarget;
	bsmanClosedRegistration.masked_paf_c59fc3d0_second_nonzero_target_addr = (u32)&zeroCtrlMaskedPafC59FC3D0SecondNonzeroTarget;
	zeroCtrlRegisterBSManClosedShim(&bsmanClosedRegistration);
	
	previous = sctrlHENSetStartModuleHandler(OnModuleStart);        
	return 0;
}
//OK
int module_stop(SceSize args UNUSED, void *argp UNUSED) {
    return 0;
}
