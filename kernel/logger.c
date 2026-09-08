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

void zeroCtrlDiagnosticsInit(int model, unsigned int devkit,
        const char *clock_and_calendar, const char *redir_path,
        unsigned int startup_total, unsigned int startup_largest)
{
    char line[256];
    SceUID fd;

    if (model != 0) {
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

void zeroCtrlDiagnosticsMemory(const char *event)
{
    char line[160];

    snprintf(line, sizeof(line),
            "[mem] %s total_free=%u largest_block=%u\n", event,
            (unsigned int)sceKernelPartitionTotalFreeMemSize(
                PSP_MEMORY_PARTITION_USER),
            (unsigned int)sceKernelPartitionMaxFreeMemSize(
                PSP_MEMORY_PARTITION_USER));
    zeroCtrlDiagnosticsWrite(line);
}
