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

#ifndef LOGGER_H_
#define LOGGER_H_

#include <string.h>
#include <stdio.h>
#include "psploadcore.h"

#define ZEROCTRL_DIAGNOSTIC_PATH "ms0:/zerovsh_psp1000.log"
#define ZEROCTRL_PARTITION_COUNT 8

typedef struct {
    int valid;
    int pid;
    unsigned int startaddr;
    unsigned int memsize;
    unsigned int attr;
    unsigned int total_free;
    unsigned int largest_block;
} ZeroCtrlPartitionEntry;

typedef struct {
    unsigned int user_total_free;
    unsigned int user_largest_block;
    ZeroCtrlPartitionEntry entries[ZEROCTRL_PARTITION_COUNT];
} ZeroCtrlPartitionSnapshot;

void zeroCtrlDiagnosticsInit(int model, unsigned int devkit,
        const char *clock_and_calendar, const char *redir_path,
        unsigned int startup_total, unsigned int startup_largest);
void zeroCtrlDiagnosticsEvent(const char *event, int result);
void zeroCtrlDiagnosticsLoaderControl(int wait_iterations);
void zeroCtrlDiagnosticsStartControl(void);
void zeroCtrlDiagnosticsUserStartControl(void);
void zeroCtrlDiagnosticsModuleAttrControl(void);
void zeroCtrlDiagnosticsLoaderApiControl(void);
void zeroCtrlDiagnosticsMemory(const char *event);
void zeroCtrlDiagnosticsCapturePartitions(ZeroCtrlPartitionSnapshot *snapshot);
void zeroCtrlDiagnosticsWritePartitions(const char *event,
        const ZeroCtrlPartitionSnapshot *snapshot);
void zeroCtrlDiagnosticsModule(const SceModule2 *module);

#ifdef DEBUG
#define zeroCtrlWriteDebug(format, ...) printf(format, ## __VA_ARGS__)
#else
#define zeroCtrlWriteDebug(format, ...)
#endif

#endif /* LOGGER_H_ */
