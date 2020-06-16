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



#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "asm_decoder.h"

static regex_t* op_regex_reg=NULL;
static regex_t* op_regex_const=NULL;
static regex_t* op_regex_mem=NULL;
static regex_t* op_regex_mem_const=NULL;

void asm_decoder_compile(void){
    //const char *begin,*end;
		const char *integer = "(0x[a-f0-9]+|[0-9]+)";
		const char *reg = "(r[abcd]x|r[isb]p|r[sd]i|r[89]|r1[012345]|"
		"e[abcd]x|e[isb]p|e[sd]i|r[89]d|r1[012345]d|"
		"[abcd]x|[isb]p|[sd]i|r[89]w|r1[012345]w|"
		"[abcd]l|[sb]pl|[sd]il|r[89]b|r1[012345]b|"
		"[abcd]h|[sb]ph|[sd]ih|xmm[0-7])";

		const char *ptr= "(byte ptr|word ptr|dword ptr|qword ptr|xmmword ptr)";
		const char *segreg = "(ss|fs|ds|gs|cs|es)";
		const char *scale ="(1|2|4|8)";

		char *str_displace = NULL;
		char *str_displace_const = NULL;
		const char* str_const = "^(-)?(0x[a-f0-9]+|[0-9]+)$";
		char *str_reg = NULL;
		assert(-1 != asprintf(&str_displace,  "^%s (%s:)?\\[(%s ([+\\-]) )?%s(\\*%s)?( ([+\\-]) %s)?\\]$",ptr, segreg, reg, reg, scale, integer));
		assert(-1 != asprintf(&str_displace_const, "^%s (%s:)?\\[%s\\]$", ptr, segreg, integer));
		assert(-1 != asprintf(&str_reg, "^%s$", reg ));

		op_regex_reg = malloc(sizeof(regex_t));
		op_regex_const = malloc(sizeof(regex_t));
		op_regex_mem_const = malloc(sizeof(regex_t));
		op_regex_mem = malloc(sizeof(regex_t));

		assert(!regcomp(op_regex_reg, str_reg, REG_EXTENDED));
		assert(!regcomp(op_regex_const, str_const, REG_EXTENDED));
		assert(!regcomp(op_regex_mem, str_displace, REG_EXTENDED));
		assert(!regcomp(op_regex_mem_const, str_displace_const, REG_EXTENDED));

		free(str_reg);
		free(str_displace);
		free(str_displace_const);
}

void asm_decoder_print_op(asm_operand_t* op){
	if(op->ptr_size){
		printf("%d %s:[%s + %s*%d + 0x%lx]\n", op->ptr_size, op->segment, op->base, op->index, op->scale, op->offset);
		return;
	}
	if(op->base){
		assert(!op->index && !op->offset);
		printf("%s\n",op->base);
		return;
	} 
	assert(!op->index && !op->base && !op->segment);
	printf("0x%lx\n",op->offset);
	return;
}

#define NMATCHES 24

static bool has_match(regmatch_t* matches,size_t i){
	return matches[i].rm_so >= 0;
}
static char *extract_match_str(char* str, regmatch_t* matches, size_t i){
	if(has_match(matches, i)){
		return strndup(str+matches[i].rm_so, matches[i].rm_eo-matches[i].rm_so);
	} 
	return NULL;
}

static char extract_match_char(char* str, regmatch_t* matches, size_t i, char defaultc){
	if(has_match(matches, i)){
		return str[matches[i].rm_so];
	} 
	return defaultc;
}

static uint64_t extract_match_u64(char* str, regmatch_t* matches, size_t i, uint64_t defaulti){
	if(matches[i].rm_so >= 0){
		return strtoull(str+matches[i].rm_so,0,0);
	}
	return defaulti;
}

static uint8_t ptr_size(char desc){
		switch(desc){
			case 'b' : return 1;
			case 'w' : return 2;
			case 'd' : return 4;
			case 'q' : return 8;
			case 'x' : return 16;
			default: 
			printf("failed to parse pointer type %c",desc);
			assert(false);
		}
}

//mutates opstr
void asm_decoder_parse_op(char* opstr, asm_operand_t* op){
	regmatch_t matches[NMATCHES] = {0};
	op->was_present = true;
	if( !regexec(op_regex_const, opstr, NMATCHES, &matches[0], 0) ){
		op->offset = extract_match_u64(opstr, matches, 2, 0);
		//printf("Matches %s const pattern %lx\n", opstr, op->offset);
		if( has_match(matches,1) ) {
			op->offset = -op->offset;
		}
	}else if (!regexec(op_regex_reg, opstr, NMATCHES, &matches[0], 0) ){
		//printf("Matches %s reg pattern\n", opstr);
		op->base = extract_match_str(opstr,matches,1);
	}else if (!regexec(op_regex_mem, opstr, NMATCHES, &matches[0], 0) ){
		//printf("Matches %s mem index pattern\n", opstr);
		op->ptr_size = ptr_size(extract_match_char(opstr, matches, 1,'\0'));
		op->segment = extract_match_str(opstr, matches, 3);
		op->base = extract_match_str(opstr, matches, 5);
		op->index = extract_match_str(opstr, matches, 7);
		op->offset = extract_match_u64(opstr, matches, 12, 0);
		op->scale = extract_match_u64(opstr,matches,9, 1);
		if( extract_match_char(opstr,matches, 11, '+')=='-' ){
			op->offset = -op->offset;
		}
	}else if (!regexec(op_regex_mem_const, opstr, NMATCHES, &matches[0], 0) ){
		//printf("Matches %s mem wo index pattern\n", opstr);
		//for(int j=0; j < NMATCHES; j++){
		//	if(matches[j].rm_so >= 0){
		//		printf("offset: %d (%d..%d) %s\n",j, matches[j].rm_so, matches[j].rm_eo, extract_match_str(opstr,matches,j));
		//	}
		//}
		op->ptr_size = ptr_size(extract_match_char(opstr, matches, 1,'\0'));
		op->segment = extract_match_str(opstr, matches, 3);
		op->offset = extract_match_u64(opstr, matches, 4, 0);
	}else {
		fprintf( stderr,"failed to match opstr %s\n",opstr);
		assert(false);
	}
}


static bool cmp_strings(char* a, char*b ){
	if(a == b){return true;}
	if(a != NULL && b != NULL){return strcmp(a,b)==0;}
	return false;
}

bool asm_decoder_op_eql(asm_operand_t* op1, asm_operand_t* op2){
	if(op1->was_present != op2->was_present) return false;
	if(op1->offset != op2->offset) return false;
	if(op1->ptr_size != op2->ptr_size) return false;
	if(!cmp_strings(op1->base, op2->base)) return false;
	if(!cmp_strings(op1->index, op2->index)) return false;
	if(!cmp_strings(op1->segment, op2->segment)) return false;
	return true;
}

void asm_decoder_clear(asm_operand_t* op){
	if(op->base) {free(op->base);}
	if(op->index) {free(op->index);}
	if(op->segment) {free(op->segment);}
	op->base = NULL;
	op->index = NULL;
	op->segment = NULL;
	op->was_present = false;
	op->offset = 0;
	op->ptr_size=0;
}

bool asm_decoder_is_imm(asm_operand_t* op){
	return !op->base && !op->ptr_size;
}

/*
int main(int argc, char* argv[])
{
		char* tests[] = {
		"byte ptr [0x24ac8057a55c8dbd]",
		"al",
		"0x123",
		"byte ptr [rcx + rbp*2]",
		"dword ptr fs:[rax]",
		"byte ptr ds:[0x23]",
		"byte ptr [rbx - 0x51419c2c]",
		"dword ptr [rdx + rbp*2 - 0x74]",
		"dword ptr [rcx + rbx*4]",
		"dword ptr [rbp + 0x46]",
		"qword ptr [rip - 0x4fb843b2]",
		"byte ptr [rdi]",
		"-0x1ba6",
		"byte ptr ss:[rdi]",
		"byte ptr [rdi*4]", 
		"byte ptr [rdi*4 + 0x123]", 
		NULL};

		compile();
		for(int i = 0; tests[i]; i++){
			asm_operand_t op = {0};
			printf("\n");
			parse_op(tests[i], &op);
			print_op(&op);
		}


    return 0;
}
*/
