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

#ifndef __GUARD_REDQUEEN_PATCHER_STRUCT__
#define __GUARD_REDQUEEN_PATCHER_STRUCT__

#include <stdint.h>
#include <stddef.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "qemu/osdep.h"

#define MAX_INSTRUCTION_SIZE 64
//Patch used to replace cmp instructions. It encodes CMP AL, AL a comparision which always evaluates to true. This can
//be used to remove hash checks that we suspsect can later on be patched.
extern const uint8_t* cmp_patch; 

typedef struct patch_info_s{
  uint64_t addr;
  size_t size;
  uint8_t orig_bytes[MAX_INSTRUCTION_SIZE];
} patch_info_t;

typedef struct patcher_s{

  CPUState *cpu;

  patch_info_t *patches;
  size_t num_patches;
  bool is_currently_applied;
} patcher_t;

patcher_t* patcher_new(CPUState *cpu);

void patcher_free(patcher_t *self);

void patcher_apply_all(patcher_t *self);

void patcher_restore_all(patcher_t *self);

//Doesn't take ownership of addrs
void patcher_set_addrs(patcher_t *self, uint64_t* addrs, size_t num_addrs);

bool patcher_validate_patches(patcher_t *self);

#endif
