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

#ifndef REDQUEEN_H
#define REDQUEEN_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "qemu/osdep.h"
#include <linux/kvm.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include "asm_decoder.h"

//#define RQ_DEBUG

#define REDQUEEN_MAX_STRCMP_LEN 64
#define REDQUEEN_TRAP_LIMIT	16

#define REG64_NUM 16
#define REG32_NUM 16
//seems we don't want to include rip, since this index is used to acces the qemu cpu structure or something?
#define REG16_NUM 16 
#define REG8L_NUM 16
#define REG8H_NUM  8

#define EXTRA_REG_RIP 16
#define EXTRA_REG_NOP 17

#define REDQUEEN_NO_INSTRUMENTATION 0
#define REDQUEEN_LIGHT_INSTRUMENTATION 1
#define REDQUEEN_SE_INSTRUMENTATION 2
#define REDQUEEN_WHITELIST_INSTRUMENTATION 3

enum reg_types{RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15};

#define RQ_REG64 {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",  "r9",  "r10",  "r11",  "r12",  "r13",  "r14", "r15",   "rip"}
#define RQ_REG32 {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "eip"}
#define RQ_REG16 {"ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",  "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "ip" }
#define RQ_REG8L {"al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
#define RQ_REG8H {"ah",  "ch",  "dh",  "bh",  "sph", "bph", "sih", "dih" } 

enum operand_types{VALUE64, VALUE32, VALUE16, VALUE8, VALUE8H, VALUE8L};

#define CMP_BITMAP_NOP			0
#define CMP_BITMAP_RQ_INSTRUCTION	1
#define CMP_BITMAP_SE_INSTRUCTION	2
#define CMP_BITMAP_BLACKLISTED	  4
#define CMP_BITMAP_TRACE_ENABLED  8
#define CMP_BITMAP_SHOULD_HOOK_SE (CMP_BITMAP_SE_INSTRUCTION|CMP_BITMAP_TRACE_ENABLED)
#define CMP_BITMAP_SHOULD_HOOK_RQ (CMP_BITMAP_RQ_INSTRUCTION)

typedef struct redqueen_s{
	uint8_t* code;
	uint64_t bitmap_size;
	uint8_t* bitmap;
	uint32_t* counter_bitmap;
	uint64_t address_range_start;
	uint64_t address_range_end;
	bool intercept_mode;
	bool trace_mode;
	bool singlestep_enabled;
	int hooks_applied;
	CPUState *cpu;
	uint64_t last_rip;
  uint64_t *breakpoint_whitelist;
  uint64_t num_breakpoint_whitelist;
} redqueen_t;

typedef struct redqueen_workdir_s{
  char* redqueen_results;
  char* symbolic_results;
  char* pt_trace_results;
  char* redqueen_patches;
  char* breakpoint_white;
  char* breakpoint_black;
  char* target_code_dump;
} redqueen_workdir_t;

extern redqueen_workdir_t redqueen_workdir;

void setup_redqueen_workdir(char* workdir);

redqueen_t* new_rq_state(uint8_t *code, uint64_t start_range, uint64_t end_range, CPUState *cpu);
void destroy_rq_state(redqueen_t* self);

void set_rq_instruction(redqueen_t* self, uint64_t addr);
void set_rq_blacklist(redqueen_t* self, uint64_t addr);

void handle_hook(redqueen_t* self);
void handel_se_hook(redqueen_t* self);

void enable_rq_intercept_mode(redqueen_t* self);
void disable_rq_intercept_mode(redqueen_t* self);


bool redqueen_get_operands_at(redqueen_t* self, uint64_t addr, asm_operand_t *op1, asm_operand_t *op2);

void redqueen_register_transition(redqueen_t* self, uint64_t ip, uint64_t transition_val);
void redqueen_trace_enabled(redqueen_t* self, uint64_t ip);
void redqueen_trace_disabled(redqueen_t* self, uint64_t ip);
void redqueen_set_trace_mode(redqueen_t* self);

void set_se_instruction(redqueen_t* self, uint64_t addr);

void dump_se_registers(redqueen_t* self);
void dump_se_memory_access(redqueen_t* self, cs_insn* insn);
void dump_se_return_access(redqueen_t* self, cs_insn* insn);
void dump_se_memory_access_at(redqueen_t* self, uint64_t instr_addr, uint64_t mem_addr);

void redqueen_insert_hooks(redqueen_t* self);
void redqueen_remove_hooks(redqueen_t* self);

#endif
