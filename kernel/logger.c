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

#include <pspsdk.h>
#include <pspiofilemgr.h>
#include <pspsysmem_kernel.h>
#include <stdio.h>
#include <string.h>
#include "logger.h"

/*
 * Diagnostics are intentionally restricted to PSP-1000 and to sparse
 * lifecycle call sites.  In particular, these routines must never be called
 * by the hooked Memory Stick IoOpen/IoGetstat functions: opening this file
 * itself passes through the Memory Stick driver hook.
 */
static int diagnostics_enabled;

static void zeroCtrlDiagnosticsWrite(const char *text)
{
    SceUID fd;

    if (!diagnostics_enabled) {
        return;
    }

    fd = sceIoOpen(ZEROCTRL_DIAGNOSTIC_PATH,
            PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0644);
    if (fd >= 0) {
        sceIoWrite(fd, text, strlen(text));
        sceIoClose(fd);
    }
}

void zeroCtrlDiagnosticsText(const char *text)
{
    zeroCtrlDiagnosticsWrite(text);
}

void zeroCtrlDiagnosticsInit(int enabled, int model, unsigned int devkit,
        const char *clock_and_calendar, const char *redir_path,
        unsigned int startup_total, unsigned int startup_largest)
{
    char line[256];
    SceUID fd;

    diagnostics_enabled = 0;
    if (!enabled || model != 0) {
        return;
    }

    /* Truncate once per VSH session; subsequent records are append-only. */
    fd = sceIoOpen(ZEROCTRL_DIAGNOSTIC_PATH,
            PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }

    diagnostics_enabled = 1;
    snprintf(line, sizeof(line),
            "[ZeroVSH PSP-1000 diagnostics v1]\n"
            "model=%d model_name=PSP-1000 devkit=0x%08X\n",
            model, devkit);
    sceIoWrite(fd, line, strlen(line));
    snprintf(line, sizeof(line),
            "clock_and_calendar=%s redir_path=%s slide_state=locked\n",
            clock_and_calendar, redir_path);
    sceIoWrite(fd, line, strlen(line));
    snprintf(line, sizeof(line),
            "[mem] kernel_start total_free=%u largest_block=%u\n",
            startup_total, startup_largest);
    sceIoWrite(fd, line, strlen(line));
    sceIoClose(fd);
}

void zeroCtrlDiagnosticsEvent(const char *event, int result)
{
    char line[128];

    snprintf(line, sizeof(line), "[event] %s result=0x%08X\n",
            event, (unsigned int)result);
    zeroCtrlDiagnosticsWrite(line);
}

void zeroCtrlDiagnosticsLoaderControl(int wait_iterations)
{
    char line[128];

    snprintf(line, sizeof(line),
            "[experiment] loader_control=no_preload_diagnostics\n"
            "[event] user_module_wait_iterations result=%d\n",
            wait_iterations);
    zeroCtrlDiagnosticsWrite(line);
}

void zeroCtrlDiagnosticsStartControl(void)
{
    zeroCtrlDiagnosticsWrite("[experiment] start_control=deferred_logging\n");
}

void zeroCtrlDiagnosticsMemory(const char *event)
{
    char line[160];

    if (!diagnostics_enabled) {
        return;
    }

    snprintf(line, sizeof(line),
            "[mem] %s total_free=%u largest_block=%u\n", event,
            (unsigned int)sceKernelPartitionTotalFreeMemSize(
                PSP_MEMORY_PARTITION_USER),
            (unsigned int)sceKernelPartitionMaxFreeMemSize(
                PSP_MEMORY_PARTITION_USER));
    zeroCtrlDiagnosticsWrite(line);
}

void zeroCtrlDiagnosticsCapturePartitions(ZeroCtrlPartitionSnapshot *snapshot)
{
    PspSysmemPartitionInfo info;
    int pid;
    ZeroCtrlPartitionEntry *entry;

    if (!snapshot) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->user_total_free = sceKernelPartitionTotalFreeMemSize(
            PSP_MEMORY_PARTITION_USER);
    snapshot->user_largest_block = sceKernelPartitionMaxFreeMemSize(
            PSP_MEMORY_PARTITION_USER);

    /* PSP system-memory partition IDs occupy this small range.  Querying is
     * authoritative: holes and partitions unavailable in this context are
     * omitted rather than treated as valid. */
    for (pid = 1; pid <= ZEROCTRL_PARTITION_COUNT; pid++) {
        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (sceKernelQueryMemoryPartitionInfo(pid, &info) < 0) {
            continue;
        }

        entry = &snapshot->entries[pid - 1];
        entry->valid = 1;
        entry->pid = pid;
        entry->startaddr = (unsigned int)info.startaddr;
        entry->memsize = (unsigned int)info.memsize;
        entry->attr = (unsigned int)info.attr;
        entry->total_free = sceKernelPartitionTotalFreeMemSize(pid);
        entry->largest_block = sceKernelPartitionMaxFreeMemSize(pid);
    }
}

void zeroCtrlDiagnosticsWritePartitions(const char *event,
        const ZeroCtrlPartitionSnapshot *snapshot)
{
    char line[192];
    int i;
    const ZeroCtrlPartitionEntry *entry;

    if (!diagnostics_enabled || !snapshot) {
        return;
    }

    snprintf(line, sizeof(line),
            "[mem] %s total_free=%u largest_block=%u\n", event,
            snapshot->user_total_free, snapshot->user_largest_block);
    zeroCtrlDiagnosticsWrite(line);

    for (i = 0; i < ZEROCTRL_PARTITION_COUNT; i++) {
        entry = &snapshot->entries[i];
        if (!entry->valid) {
            continue;
        }
        snprintf(line, sizeof(line),
                "[partition] %s pid=%d start=0x%08X size=%u attr=0x%08X "
                "total_free=%u largest_block=%u\n",
                event, entry->pid, entry->startaddr, entry->memsize,
                entry->attr, entry->total_free, entry->largest_block);
        zeroCtrlDiagnosticsWrite(line);
    }
}

void zeroCtrlDiagnosticsModule(const SceModule2 *module)
{
    char line[224];
    unsigned int i;
    unsigned int segments;

    if (!diagnostics_enabled) {
        return;
    }

    if (!module) {
        zeroCtrlDiagnosticsEvent("user_module_lookup", -1);
        return;
    }

    snprintf(line, sizeof(line),
            "[module] modid=0x%08X name=%.27s attr=0x%04X mpid_text=%u "
            "mpid_data=%u text=%u data=%u bss=%u nsegment=%u\n",
            (unsigned int)module->modid, module->modname,
            (unsigned int)module->attribute,
            (unsigned int)module->mpid_text,
            (unsigned int)module->mpid_data,
            (unsigned int)module->text_size,
            (unsigned int)module->data_size,
            (unsigned int)module->bss_size,
            (unsigned int)module->nsegment);
    zeroCtrlDiagnosticsWrite(line);

    segments = module->nsegment < 4 ? module->nsegment : 4;
    for (i = 0; i < segments; i++) {
        snprintf(line, sizeof(line),
                "[segment] modid=0x%08X index=%u addr=0x%08X size=%u\n",
                (unsigned int)module->modid, i,
                (unsigned int)module->segmentaddr[i],
                (unsigned int)module->segmentsize[i]);
        zeroCtrlDiagnosticsWrite(line);
    }
}
