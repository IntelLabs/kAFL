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


#ifndef MEMORY_ACCESS_H
#define MEMORY_ACCESS_H

#include "qemu/osdep.h"
#include <linux/kvm.h>
#include "qemu-common.h"
#include "sysemu/kvm_int.h"

bool read_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu);
bool write_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu);
void hexdump_virtual_memory(uint64_t address, uint32_t size, CPUState *cpu);
bool write_virtual_shadow_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu);
bool is_addr_mapped(uint64_t address, CPUState *cpu);
#endif
