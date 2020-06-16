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


#ifndef DECODER_H
#define DECODER_H

#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/time.h>
#include <stdbool.h>
#include "pt/tnt_cache.h"
#include "pt/disassembler.h"
#include "pt/logger.h"
#ifdef CONFIG_REDQUEEN
#include "pt/redqueen.h"
#endif

//#define DECODER_LOG

typedef enum decoder_state { 
	TraceDisabled=1, 
	TraceEnabledWithLastIP, 
	TraceEnabledWOLastIP} 
decoder_state_e;

typedef struct DecoderStateMachine{
  decoder_state_e state;
  uint64_t last_ip;
} decoder_state_machine_t;

/*
Used as return type for statemachine updates, start and end are undefined unless valid is true
*/
typedef struct ShouldDisasm{
  uint64_t start;
  uint64_t end;
  bool valid;
} should_disasm_t;


typedef struct decoder_s{
	uint8_t* code;
	uint64_t min_addr;
	uint64_t max_addr;
	void (*handler)(uint64_t);
	uint64_t last_tip;
	uint64_t last_tip_tmp;
	bool fup_bind_pending;
	disassembler_t* disassembler_state;
	tnt_cache_t* tnt_cache_state;
	decoder_state_machine_t* decoder_state;
	should_disasm_t* decoder_state_result;

#ifdef DECODER_LOG
	struct decoder_log_s{
		uint64_t tnt64;
		uint64_t tnt8;
		uint64_t pip;
		uint64_t cbr;
		uint64_t ts;
		uint64_t ovf;
		uint64_t psbc;
		uint64_t psbend;
		uint64_t mnt;
		uint64_t tma;
		uint64_t vmcs;
		uint64_t pad;
		uint64_t tip;
		uint64_t tip_pge;
		uint64_t tip_pgd;
		uint64_t tip_fup;
		uint64_t mode;
	} log;
#endif
} decoder_t;
#ifdef CONFIG_REDQUEEN
decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, int disassembler_word_with,  void (*handler)(uint64_t), redqueen_t *redqueen_state);
#else
decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, int disassembler_word_with, void (*handler)(uint64_t));
#endif
/* returns false if the CPU trashed our tracing run ... thank you Intel btw ... */
 __attribute__((hot)) bool decode_buffer(decoder_t* self, uint8_t* map, size_t len);
void pt_decoder_destroy(decoder_t* self);
void pt_decoder_flush(decoder_t* self);

#endif
