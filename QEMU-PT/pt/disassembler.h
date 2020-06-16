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



#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "qemu/osdep.h"
#include "pt/khash.h"
#include "pt/tnt_cache.h"
#include "pt/logger.h"
#ifdef CONFIG_REDQUEEN
#include "pt/redqueen.h"
#endif

KHASH_MAP_INIT_INT(ADDR0, uint64_t)

typedef struct{
	uint16_t opcode;
	uint8_t modrm;
	uint8_t opcode_prefix;
} cofi_ins;

typedef enum cofi_types{
	COFI_TYPE_CONDITIONAL_BRANCH, 
	COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH, 
	COFI_TYPE_INDIRECT_BRANCH, 
	COFI_TYPE_NEAR_RET, 
	COFI_TYPE_FAR_TRANSFERS,
	NO_COFI_TYPE,
	NO_DISASSEMBLY,
} cofi_type;


typedef struct {
	uint64_t ins_addr;
	uint64_t target_addr;
	uint16_t ins_size;
	cofi_type type;
} cofi_header;

typedef struct cofi_list {
	struct cofi_list *list_ptr;
	struct cofi_list *cofi_ptr;
	struct cofi_list *cofi_target_ptr;
	cofi_header cofi;
} cofi_list;

typedef struct disassembler_s{
	uint8_t* code;
	uint64_t min_addr;
	uint64_t max_addr;
	void (*handler)(uint64_t);
	khash_t(ADDR0) *map;
	cofi_list* list_head;
	cofi_list* list_element;
	bool debug;
	bool has_pending_indirect_branch;
  int word_width;
	uint64_t pending_indirect_branch_src;
#ifdef CONFIG_REDQUEEN
	bool redqueen_mode;
	redqueen_t* redqueen_state;
#endif
} disassembler_t;

#ifdef CONFIG_REDQUEEN
disassembler_t* init_disassembler(uint8_t* code, uint64_t min_addr, uint64_t max_addr, int disassembler_word_width, void (*handler)(uint64_t), redqueen_t *redqueen_state);
#else
disassembler_t* init_disassembler(uint8_t* code, uint64_t min_addr, uint64_t max_addr, int disassembler_word_width, void (*handler)(uint64_t));
#endif

int get_capstone_mode(int word_width_in_bits);
void disassembler_flush(disassembler_t* self);
void inform_disassembler_target_ip(disassembler_t* self, uint64_t target_ip);
 __attribute__((hot)) bool trace_disassembler(disassembler_t* self, uint64_t entry_point, uint64_t limit, tnt_cache_t* tnt_cache_state);
void destroy_disassembler(disassembler_t* self);

#endif
