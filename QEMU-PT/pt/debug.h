/* 
# This file is part of Redqueen.
#
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/



#pragma once

#define QEMU_PT_PRINT_PREFIX  "[QEMU-PT]\t"
#define CORE_PREFIX           "Core:      "
#define MEM_PREFIX            "Memory:    "
#define RELOAD_PREFIX         "Reload:    "
#define PT_PREFIX             "PT:        "
#define INTERFACE_PREFIX      "Interface: "
#define REDQUEEN_PREFIX       "Redqueen:  "
#define DISASM_PREFIX         "Disasm:    "

#define COLOR	"\033[1;35m"
#define ENDC	"\033[0m"


#define QEMU_PT_PRINTF(PREFIX, format, ...) printf (QEMU_PT_PRINT_PREFIX COLOR PREFIX format ENDC "\n", ##__VA_ARGS__)
#define QEMU_PT_PRINTF_DBG(PREFIX, format, ...) printf (QEMU_PT_PRINT_PREFIX PREFIX "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)
