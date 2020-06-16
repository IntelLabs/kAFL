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

typedef struct asm_operand_s{
	char* base;
	char* index;
	char* segment;
	uint64_t offset;
	uint8_t ptr_size;
	uint8_t scale;
	bool was_present;
} asm_operand_t;


void asm_decoder_compile(void);
void asm_decoder_parse_op(char* opstr, asm_operand_t* op);

void asm_decoder_print_op(asm_operand_t* op);

bool asm_decoder_is_imm(asm_operand_t* op);
void asm_decoder_clear(asm_operand_t* op);

bool asm_decoder_op_eql(asm_operand_t* op1, asm_operand_t* op2);
