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
    ZeroCtrlVshGlobalReference vsh_global_references[VSH_REFERENCE_LIMIT];
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

void zeroCtrlRecordVshSlideTarget(int modid, unsigned int text_addr,
        unsigned int text_size, unsigned int module_start_addr,
        unsigned int elf_entry_addr, unsigned int target) {
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
            zeroCtrlScanVshDirectReferences(text_addr, text_size);
            zeroCtrlScanVshGlobalReferences(text_addr, text_size);
            slide_diag.vsh_code_capture_result = 0;
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

static void zeroCtrlWriteVshSlideEvidence(void) {
    unsigned int i;
    unsigned int j;
    char line[160];

    if (!slide_diag.vsh_module_seen) return;
    zeroCtrlDiagnosticsEvent("vsh_modid", slide_diag.vsh_modid);
    zeroCtrlDiagnosticsEvent("vsh_text_addr", slide_diag.vsh_text_addr);
    zeroCtrlDiagnosticsEvent("vsh_text_size", slide_diag.vsh_text_size);
    zeroCtrlDiagnosticsEvent("vsh_module_start_func_addr",
            slide_diag.vsh_module_start_addr);
    zeroCtrlDiagnosticsEvent("vsh_elf_entry_addr", slide_diag.vsh_elf_entry_addr);
    zeroCtrlDiagnosticsEvent("vsh_slide_target", slide_diag.vsh_slide_target);
    zeroCtrlDiagnosticsEvent("vsh_slide_target_in_text",
            slide_diag.vsh_target_in_text);
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
    zeroCtrlDiagnosticsEvent("vsh_global_reference_total",
            slide_diag.vsh_global_reference_total);
    zeroCtrlDiagnosticsEvent("vsh_global_reference_stored",
            slide_diag.vsh_global_reference_count);
    zeroCtrlDiagnosticsEvent("vsh_global_reference_overflow",
            slide_diag.vsh_global_reference_overflow);
    for (i = 0; i < slide_diag.vsh_global_reference_count; i++) {
        ZeroCtrlVshGlobalReference *ref = &slide_diag.vsh_global_references[i];
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
}

static int zeroCtrlWriteSlideDiagnostics(SceSize args UNUSED, void *argp UNUSED) {
    int waited = 0;
    unsigned int written = 0;

    slide_diag.writer_alive = 1;
    zeroCtrlDiagnosticsText("[checkpoint] slide_diag_writer_alive\n");
    while (!slide_diag.saw_probe && waited < 3000000) {
        zeroCtrlWriteSlideCheckpoints(&written);
        sceKernelDelayThread(10000);
        waited += 10000;
    }
    zeroCtrlWriteSlideCheckpoints(&written);
    if (!slide_diag.saw_probe) {
        char line[128];
        snprintf(line, sizeof(line),
                "[state] request=%d rco_request=%d probe=%d start=%d\n",
                slide_diag.saw_request, slide_diag.saw_rco_request,
                slide_diag.saw_probe, slide_diag.saw_start);
        zeroCtrlDiagnosticsText(line);
        zeroCtrlWriteVshSlideEvidence();
        zeroCtrlDiagnosticsText("[event] slide_probe_not_seen timeout_us=3000000\n");
        slide_diag.deferred_thread_started = 0;
        sceKernelExitDeleteThread(0);
        return 0;
    }

    waited = 0;
    while (!slide_diag.saw_start && waited < 2000000) {
        zeroCtrlWriteSlideCheckpoints(&written);
        sceKernelDelayThread(10000);
        waited += 10000;
    }
    zeroCtrlWriteSlideCheckpoints(&written);
    if (slide_diag.saw_start) {
        /* Delay is measured from the observed pre-entrypoint callback. */
        sceKernelDelayThread(750000);
        zeroCtrlDiagnosticsCapturePartitions(&slide_diag.delayed_or_timeout);
    } else {
        zeroCtrlDiagnosticsCapturePartitions(&slide_diag.delayed_or_timeout);
    }

    zeroCtrlWriteVshSlideEvidence();
    if (slide_diag.saw_request) zeroCtrlDiagnosticsText("[event] slide_request_seen\n");
    if (slide_diag.saw_rco_request) zeroCtrlDiagnosticsText("[event] slide_rco_request_seen\n");
    zeroCtrlDiagnosticsText("[event] slide_probe_seen\n");
    zeroCtrlDiagnosticsEvent("slide_probe_result", slide_diag.probe_result);
    zeroCtrlDiagnosticsWritePartitions("at_slide_plugin_probe", &slide_diag.at_probe);
    if (slide_diag.saw_start) {
        zeroCtrlDiagnosticsText("[event] slide_module_start_seen\n");
        zeroCtrlDiagnosticsEvent("slide_module_modid", slide_diag.module.modid);
        zeroCtrlDiagnosticsWritePartitions("slide_plugin_pre_start", &slide_diag.pre_start);
        zeroCtrlDiagnosticsModule(&slide_diag.module);
        zeroCtrlDiagnosticsText("[experiment] sony_module_start_control=noop\n");
        zeroCtrlDiagnosticsEvent("slide_module_start_func_addr",
                slide_diag.module_start_addr);
        zeroCtrlDiagnosticsEvent("slide_elf_entry_addr", slide_diag.elf_entry_addr);
        zeroCtrlDiagnosticsEvent("slide_module_start_in_segment",
                slide_diag.module_start_in_segment);
        if (slide_diag.module_start_patch_result > 0) {
            zeroCtrlDiagnosticsEvent("slide_module_start_original_word0",
                    slide_diag.module_start_original[0]);
            zeroCtrlDiagnosticsEvent("slide_module_start_original_word1",
                    slide_diag.module_start_original[1]);
            zeroCtrlDiagnosticsText("[experiment] sony_module_start_control=noop_applied\n");
            zeroCtrlDiagnosticsEvent("slide_module_start_patch_applied", 1);
        } else {
            zeroCtrlDiagnosticsText("[experiment] slide_module_start_validation=failed\n");
            zeroCtrlDiagnosticsEvent("slide_module_start_patch_skipped",
                    slide_diag.module_start_patch_result);
        }
        zeroCtrlDiagnosticsWritePartitions("slide_plugin_delayed",
                &slide_diag.delayed_or_timeout);
    } else {
        zeroCtrlDiagnosticsText("[event] slide_module_start_not_seen timeout_us=2000000\n");
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

static int zeroCtrlValidateModuleStart(const SceModule2 *mod,
        unsigned int target) {
    unsigned int i;

    if (target == 0) return -1;
    if (target == 0xFFFFFFFF) return -2;
    if ((target & 3) != 0) return -3;
    if (mod->text_size < 8 || target < mod->text_addr ||
            target - mod->text_addr > mod->text_size - 8) {
        return -4;
    }
    for (i = 0; i < mod->nsegment && i < 4; i++) {
        unsigned int start = mod->segmentaddr[i];
        unsigned int size = mod->segmentsize[i];
        if (target >= start && size >= 8 && target - start <= size - 8) {
            return 1;
        }
    }
    return -5;
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
                slide_diag.module_start_target_read = 1;
                slide_diag.module_start_patch_result =
                        zeroCtrlValidateModuleStart(mod,
                                slide_diag.module_start_addr);
                slide_diag.module_start_in_segment =
                        slide_diag.module_start_patch_result > 0;
                slide_diag.module_start_validated =
                        slide_diag.module_start_in_segment;
                slide_diag.module_start_validation_complete = 1;
                if (slide_diag.module_start_in_segment) {
                        unsigned int target = slide_diag.module_start_addr;
                        slide_diag.module_start_original[0] = _lw(target);
                        slide_diag.module_start_original[1] = _lw(target + 4);
                        slide_diag.module_start_original_saved = 1;
                        /* MIPS: jr $ra; addiu $v0, $zero, 0 (delay slot). */
                        _sw(0x03E00008, target);
                        _sw(0x24020000, target + 4);
                        slide_diag.module_start_words_written = 1;
                        zeroCtrlDcacheWritebackAll();
                        zeroCtrlIcacheClearAll();
                        slide_diag.module_start_cache_sync_complete = 1;
                }
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
	if (model == 0 && strcmp(psp1000SlidePlugin, "Enabled") == 0 &&
			strcmp(useSlide, "Disabled") == 0) {
		memset(&slide_diag, 0, sizeof(slide_diag));
		slide_diag.armed = 1;
	}

	zeroCtrlDiagnosticsInit(model, devkit, useSlide, redir_path,
			startup_total, startup_largest);
	if (slide_diag.armed) {
		zeroCtrlDiagnosticsText("[phase] psp1000_slide_phase3\n"
				"[experiment] psp1000_slide_optin=enabled\n"
				"[experiment] clock_and_calendar=disabled\n"
				"[experiment] psp1000_vsh_slide_trigger=disabled_control\n"
				"[experiment] vsh_slide_patch=disabled\n"
				"[experiment] vsh_reference_scan=read_only\n"
				"[experiment] vsh_direct_windows=predicate_6f84_only\n"
				"[experiment] button_thread=disabled\n");
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
	set_registry_value("/CONFIG/SYSTEM", "slide_welcome", 1);	
	
	if (slide_diag.armed) {
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
