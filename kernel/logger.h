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

void zeroCtrlDiagnosticsInit(int model, unsigned int devkit,
        const char *clock_and_calendar, const char *redir_path,
        unsigned int startup_total, unsigned int startup_largest);
void zeroCtrlDiagnosticsEvent(const char *event, int result);
void zeroCtrlDiagnosticsMemory(const char *event);
void zeroCtrlDiagnosticsPartitions(const char *event);
void zeroCtrlDiagnosticsModule(const SceModule2 *module);

#ifdef DEBUG
#define zeroCtrlWriteDebug(format, ...) printf(format, ## __VA_ARGS__)
#else
#define zeroCtrlWriteDebug(format, ...)
#endif

#endif /* LOGGER_H_ */
