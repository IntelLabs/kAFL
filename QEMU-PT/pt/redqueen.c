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

#include <assert.h>
#include "pt/redqueen.h"
#include "pt/memory_access.h"
#include "pt/disassembler.h"
#include "pt/interface.h"
#include <inttypes.h>
#include "file_helper.h"
#include "patcher.h"
#include "debug.h"
#include "asm_decoder.h"

const char* regs64[] = RQ_REG64;
const char* regs32[] = RQ_REG32;
const char* regs16[] = RQ_REG16;
const char* regs8l[] = RQ_REG8L;
const char* regs8h[] = RQ_REG8H;

redqueen_workdir_t redqueen_workdir = {0};

void setup_redqueen_workdir(char* workdir){
   assert(asprintf(&redqueen_workdir.redqueen_results,"%s/redqueen_results.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.symbolic_results,"%s/symbolic_results.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.pt_trace_results,"%s/pt_trace_results.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.redqueen_patches,"%s/redqueen_patches.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.breakpoint_white,"%s/breakpoint_white.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.breakpoint_black,"%s/breakpoint_black.txt", workdir)>0);
   assert(asprintf(&redqueen_workdir.target_code_dump,"%s/target_code_dump.img", workdir)>0);
}

redqueen_t* new_rq_state(uint8_t *code, uint64_t start_range, uint64_t end_range, CPUState *cpu){
	redqueen_t* res = malloc(sizeof(redqueen_t));
	res->code = code;
	res->address_range_start = start_range;
	res->address_range_end = end_range;
	res->cpu = cpu;
	res->intercept_mode = false;
	res->trace_mode = false;
	res->singlestep_enabled = false;
  res->hooks_applied = 0;
	assert((end_range-start_range) < 0x40000000);
	res->bitmap_size = end_range-start_range;
	res->bitmap = malloc(res->bitmap_size);
	res->counter_bitmap = malloc(res->bitmap_size * sizeof(uint32_t));
	memset(res->counter_bitmap, 0x00, (res->bitmap_size * sizeof(uint32_t)));
	res->last_rip = 0x0;
	memset(res->bitmap, CMP_BITMAP_NOP, end_range-start_range);
  res->num_breakpoint_whitelist=0;
  res->breakpoint_whitelist=NULL;

	//FILE* pt_file = fopen("/tmp/redqueen_vm.img", "wb");
	//delete_redqueen_files();
  //fwrite(&start_range, sizeof(uint64_t), 1, pt_file);
	//fwrite(code, sizeof(uint8_t), end_range-start_range, pt_file);
	//fclose(pt_file);
	return res;
}

void redqueen_set_trace_mode(redqueen_t* self){
  delete_trace_files();
  self->trace_mode = true;
}

void destroy_rq_state(redqueen_t* self){
	free(self->bitmap);
	free(self);
}

static void set_rq_trace_enabled_bp(redqueen_t* self, uint64_t addr){
	if(addr >= self->address_range_start && addr <= self->address_range_end){
    self->bitmap[addr-self->address_range_start] |= CMP_BITMAP_TRACE_ENABLED;
  }
}

void set_rq_instruction(redqueen_t* self, uint64_t addr){
	if(addr >= self->address_range_start && addr <= self->address_range_end){
		if( !(self->bitmap[addr-self->address_range_start] & CMP_BITMAP_BLACKLISTED) ){
			self->bitmap[addr-self->address_range_start] |= CMP_BITMAP_RQ_INSTRUCTION; 
		}
	}	
}

void set_se_instruction(redqueen_t* self, uint64_t addr){
	if(addr >= self->address_range_start && addr <= self->address_range_end){
		if( !(self->bitmap[addr-self->address_range_start] & CMP_BITMAP_BLACKLISTED) ){
			self->bitmap[addr-self->address_range_start] |= CMP_BITMAP_SE_INSTRUCTION; 
		}
	}	
}

void set_rq_blacklist(redqueen_t* self, uint64_t addr){
	if(addr >= self->address_range_start && addr <= self->address_range_end){
		self->bitmap[addr-self->address_range_start] |= CMP_BITMAP_BLACKLISTED; 
	}	
}

static void insert_hooks_whitelist(redqueen_t* self){
  for(size_t i = 0; i < self->num_breakpoint_whitelist; i++){
		kvm_insert_breakpoint(self->cpu, self->breakpoint_whitelist[i], 1, 0);
  }
}

static void insert_hooks_bitmap(redqueen_t* self){
	uint64_t c = 0;
	//uint8_t data;
	for(uint64_t i = 0; i < self->bitmap_size; i++){
    int mode = self->cpu->redqueen_instrumentation_mode;
    if(self->bitmap[i] & CMP_BITMAP_BLACKLISTED){ continue; }
    bool should_hook_se = (self->bitmap[i] & CMP_BITMAP_SHOULD_HOOK_SE) && (mode == REDQUEEN_SE_INSTRUMENTATION);
    bool should_hook_rq = (self->bitmap[i] & CMP_BITMAP_SHOULD_HOOK_RQ) && (mode == REDQUEEN_LIGHT_INSTRUMENTATION || REDQUEEN_SE_INSTRUMENTATION);
		if( should_hook_se || should_hook_rq ){
			kvm_insert_breakpoint(self->cpu, (i+self->address_range_start), 1, 0);
			c++;
		}
	}
}

void redqueen_insert_hooks(redqueen_t* self){
  //QEMU_PT_PRINTF(REDQUEEN_PREFIX, "insert hooks");
  assert(!self->hooks_applied);
  switch(self->cpu->redqueen_instrumentation_mode){
    case(REDQUEEN_SE_INSTRUMENTATION):
    case(REDQUEEN_LIGHT_INSTRUMENTATION):
      insert_hooks_bitmap(self);
      break;
    case(REDQUEEN_WHITELIST_INSTRUMENTATION):
      insert_hooks_whitelist(self);
      break;
    case(REDQUEEN_NO_INSTRUMENTATION):
      break;
    default:
      assert(false);
  }
  self->hooks_applied = 1;
}

void redqueen_remove_hooks(redqueen_t* self){
  //QEMU_PT_PRINTF(REDQUEEN_PREFIX, "remove hooks");
  assert(self->hooks_applied);
	kvm_remove_all_breakpoints(self->cpu);
	memset(self->counter_bitmap, 0x00, (self->bitmap_size * sizeof(uint32_t)));
  self->hooks_applied = 0;
  return;
}
static uint64_t get_segment_register(redqueen_t* self, char* segmentor) {
  X86CPU *cpu = X86_CPU(self->cpu);
  CPUX86State *env = &cpu->env;
  assert(strlen(segmentor) == 2);
  assert(segmentor[1]=='s');
  switch(segmentor[0]){
    case('g'): return env->segs[R_GS].base;
    case('f'): return env->segs[R_FS].base;
    case('c'): return env->segs[R_CS].base;
    case('d'): return env->segs[R_DS].base;
    case('s'): return env->segs[R_SS].base;
  }
  assert(false);
}

static bool parse_reg(char* reg_str, uint8_t* index, uint8_t* type){
	uint8_t j;

	/* 64bit regs */
	if (reg_str[0] == 'r'){
		for(j = 0; j < REG64_NUM+1; j++){
			if (!strcmp(reg_str, regs64[j])){
				*type = VALUE64;
				*index = j; 
				return true;
			}
		}
	}

	/* 32bit regs */
	if (reg_str[0] == 'r' || reg_str[0] == 'e'){
		for(j = 0; j < REG32_NUM+1; j++){
			if (!strcmp(reg_str, regs32[j])){
				*type = VALUE32;
				*index = j; 
				return true;
			}
		}
	}

	/* 16bit regs */
	if (reg_str[0] == 'r' || strlen(reg_str) == 2){
		for(j = 0; j < REG16_NUM+1; j++){
			if (!strcmp(reg_str, regs16[j])){
				*type = VALUE16;
				*index = j; 
				return true;
			}
		}
	}

	/* 8bit regs high */
	for(j = 0; j < REG8H_NUM; j++){
		if (!strcmp(reg_str, regs8h[j])){
			*type = VALUE8H;
			*index = j; 
			return true;
		}
	}

	/* 8bit regs low */
	for(j = 0; j < REG8L_NUM; j++){
		if (!strcmp(reg_str, regs8l[j])){
			*type = VALUE8L;
			*index = j; 
			return true;
		}
	}	
	return false;
}

static inline uint64_t load64_qreg(redqueen_t* self, uint8_t index){
  CPUX86State *env = &(X86_CPU(self->cpu))->env;
	if (index == REG64_NUM){
		return env->eip;
	}
	if (index > REG64_NUM){
		return 0;
	}
	return env->regs[index];
}

static inline uint64_t sign_extend_from_size(uint64_t value, uint8_t size){
  switch(size){
    case 64: return value;
    case 32: return ((int32_t)(value)<0) ? 0xffffffff00000000 | value : value;
    case 16: return ((int16_t)(value)<0) ? 0xffffffffffff0000 | value : value;
    case 8: return  (( int8_t)(value)<0) ? 0xffffffffffffff00 | value : value;
  }
  assert(false);
}

static inline uint64_t limit_to_type(uint64_t value, uint8_t type){
	switch(type){
		case VALUE64:
			return value;
		case VALUE32:
			return value&0xffffffff;
		case VALUE16:
			return value &0xffff;
		case VALUE8H:
			return (value & 0xff00)>>8;
		case VALUE8L:
			return value &0xff;
	}
  assert(false);
}

static inline uint8_t type_to_bitsize(uint8_t type){
	switch(type){
		case VALUE64:
			return 64;
		case VALUE32:
			return 32;
		case VALUE16:
			return 16;
		case VALUE8H:
			return 8;
		case VALUE8L:
			return 8;
	}
  assert(false);
}

static inline uint64_t load_qreg(redqueen_t* self, uint8_t index, uint8_t type){
  return limit_to_type(load64_qreg(self, index), type);
}

static void parse_op_str2(char* op_str, asm_operand_t* op1, asm_operand_t* op2){

	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "parsing 2 ops on: %s\n",op_str);
  op1->was_present = false;
  op2->was_present = false;
  char* op_copy = strdup(op_str);
  char* arg2 = op_copy;
  char* arg1 = strsep(&arg2,",");
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "parsing arg1 on: %s\n",arg1);
  asm_decoder_parse_op(arg1, op1);
  if(arg2){
	  //QEMU_PT_PRINTF(REDQUEEN_PREFIX,  "parsing arg2 on: %s\n",arg2);
    while(*arg2 == ' ') arg2++;
    asm_decoder_parse_op(arg2, op2);
  } 
  free(op_copy);
}

static uint64_t eval_reg(redqueen_t* self, char* regstr, uint8_t *size){
    uint8_t index;
    uint8_t type;
    assert(parse_reg(regstr, &index, &type));
    if(size){
      *size = type_to_bitsize(type);
    }
    return load_qreg(self, index, type);
}

static uint64_t eval_addr(redqueen_t* self, asm_operand_t* op){

  uint8_t size=0;
  uint64_t base = 0; 
  uint64_t index = 0;
  uint64_t segment = 0;
  if(op->base){
    base = eval_reg(self, op->base, &size);
  }
  if(op->index){
    index = eval_reg(self, op->index, &size);
  }

  if(op->segment){
    segment = get_segment_register(self, op->segment);
  }

  uint64_t addr = segment + base + index*op->scale + op->offset;
  return addr;
}

static uint64_t eval_mem(redqueen_t* self, asm_operand_t* op){
  uint64_t val = 0;
	QEMU_PT_PRINTF(REDQUEEN_PREFIX, "EVAL MEM FOR OP:");
 //asm_decoder_print_op(op);
  assert(op->ptr_size == 1 || op->ptr_size == 2 || op->ptr_size == 4 || op->ptr_size == 8);
  read_virtual_memory(eval_addr(self, op), (uint8_t*) &val, op->ptr_size, self->cpu);
  return val;
}

static uint64_t eval(redqueen_t* self, asm_operand_t *op, uint8_t* size){
  switch(op->ptr_size){
    case 0: break;
    case 1: *size =8;  return eval_mem(self, op) &0xff;
    case 2: *size =16; return eval_mem(self, op)&0xffff;
    case 4: *size =32; return eval_mem(self, op)&0xffffffff;
    case 8: *size =64; return eval_mem(self, op);
    default: assert(false);
  }
  if(op->base){
    return eval_reg(self, op->base, size);
  }
  *size=0;
  return op->offset;
}

static void print_comp_result(uint64_t addr, const char* type, uint64_t val1, uint64_t val2, uint8_t size, bool is_imm){

	char result_buf[256]; 
  const char *format = NULL;
	uint8_t pos = 0;
			pos += snprintf(result_buf+pos, 256-pos, "%lx\t\t %s", addr, type);
	    //QEMU_PT_PRINTF(REDQUEEN_PREFIX, "got size: %ld", size);
      uint64_t mask = 0;
			switch(size){
				case 64: format = " 64\t%016lX-%016lX"; mask = 0xffffffffffffffff;  break;
				case 32: format = " 32\t%08X-%08X";     mask = 0xffffffff;          break;
				case 16: format = " 16\t%04X-%04X";     mask = 0xffff;              break;
				case 8:  format = " 8\t%02X-%02X";      mask = 0xff;                break;
        default:
          assert(false);
			}
			pos += snprintf(result_buf+pos, 256-pos, format, val1 & mask, val2 & mask);
			if(is_imm){
				pos += snprintf(result_buf+pos, 256-pos, " IMM");
			}
			pos += snprintf(result_buf+pos, 256-pos, "\n");
			write_re_result(result_buf);
}

bool redqueen_get_operands_at(redqueen_t* self, uint64_t addr, asm_operand_t *op1, asm_operand_t *op2){
  asm_decoder_clear(op1);
  asm_decoder_clear(op2);
	csh handle;
	cs_insn *insn;
	uint8_t* code = (self->code+(addr-self->address_range_start));
	uint64_t cs_address = addr;

	size_t code_size = self->address_range_end - addr;
	//assert(self->disassembler_word_width == 32 || self->disassembler_word_width == 64);
	if (cs_open(CS_ARCH_X86, get_capstone_mode(self->cpu->disassembler_word_width), &handle) == CS_ERR_OK){
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		insn = cs_malloc(handle);
		assert(cs_disasm_iter(handle, (const uint8_t **) &code, &code_size, &cs_address, insn)==1);

    parse_op_str2(insn->op_str, op1, op2);

    //asm_decoder_print_op(op1);
    //asm_decoder_print_op(op2);

		cs_free(insn, 1);
		cs_close(&handle);
    return true;
	}
  return false;
}

static void get_cmp_value(redqueen_t* self, uint64_t addr, const char* type){
  asm_operand_t op1 = {0};
  asm_operand_t op2 = {0};
  uint8_t size_1=0;
  uint8_t size_2=0;

  if( redqueen_get_operands_at(self, addr, &op1, &op2) ) {
    assert(op1.was_present && op2.was_present);

    uint64_t v1 = eval(self, &op1, &size_1);
    uint64_t v2 = eval(self, &op2, &size_2);

    if(self->cpu->redqueen_instrumentation_mode == REDQUEEN_WHITELIST_INSTRUMENTATION  ||  v1 != v2){
      print_comp_result(addr, type, v1, v2, (size_1 ? size_1 : size_2), asm_decoder_is_imm(&op2));
    }
    asm_decoder_clear(&op1);
    asm_decoder_clear(&op2);
  }
}

static void get_cmp_value_add(redqueen_t* self, uint64_t addr){
  asm_operand_t op1 = {0};
  asm_operand_t op2 = {0};
  uint8_t size_1=0;
  uint8_t size_2=0;

  if( redqueen_get_operands_at(self, addr, &op1, &op2) ) {
    assert(op1.was_present && op2.was_present);
    if(!asm_decoder_is_imm(&op2)){return;}

    uint64_t v1 = eval(self, &op1, &size_1);
    uint64_t v2 = -sign_extend_from_size(eval(self, &op2, &size_2), size_1);

    if(self->cpu->redqueen_instrumentation_mode == REDQUEEN_WHITELIST_INSTRUMENTATION  ||  v1 != v2){
      print_comp_result(addr, "SUB", v1, v2, size_1, asm_decoder_is_imm(&op2));
    }
    asm_decoder_clear(&op1);
    asm_decoder_clear(&op2);
  }
}

static void get_cmp_value_lea(redqueen_t* self, uint64_t addr){
  asm_operand_t op1 = {0};
  asm_operand_t op2 = {0};

  if( redqueen_get_operands_at(self, addr, &op1, &op2) ) {
    assert(op1.was_present && op2.was_present);
    assert(op2.ptr_size);
      uint8_t size=0;
      uint64_t index_val = eval_reg(self, op2.index, &size);
      if(self->cpu->redqueen_instrumentation_mode == REDQUEEN_WHITELIST_INSTRUMENTATION  ||  index_val != -op2.offset){
        print_comp_result(addr, "LEA", index_val, -op2.offset, op2.ptr_size*8, asm_decoder_is_imm(&op2));
      }
    asm_decoder_clear(&op1);
    asm_decoder_clear(&op2);
  }
}


static uint64_t limit_to_word_width(redqueen_t* self, uint64_t val){
	switch(self->cpu->disassembler_word_width){
	case 64:
		return val;
	case 32: 
		return val & 0xffffffff;
	default:
		assert(false);
	}
}

static uint64_t word_width_to_bytes(redqueen_t* self){
	switch(self->cpu->disassembler_word_width){
	case 64:
		return 8;
	case 32: 
		return 4;
	default:
		assert(false);
	}
}

static uint64_t read_stack(redqueen_t* self, uint64_t word_index){
	CPUX86State *env = &(X86_CPU(self->cpu))->env;
	uint64_t rsp = env->regs[4];
	rsp = limit_to_word_width(self, rsp);
	uint64_t res = 0;
	uint64_t stack_ptr = rsp + word_index * word_width_to_bytes(self);
	assert(read_virtual_memory(stack_ptr, (uint8_t*)(&res), 8, self->cpu));
	return limit_to_word_width(self, res);
}

static void format_strcmp(redqueen_t* self, uint8_t* buf1, uint8_t* buf2){
	char out_buf[REDQUEEN_MAX_STRCMP_LEN*4 + 2];
	char* tmp_hex_buf = &out_buf[0];
	for(int i = 0; i < REDQUEEN_MAX_STRCMP_LEN; i++){
		tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf1[i]);
	}
	*tmp_hex_buf++ = '-';
	for(int i = 0; i < REDQUEEN_MAX_STRCMP_LEN; i++){
		tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf2[i]);
	}
	char *res=0;
	CPUX86State *env = &(X86_CPU(self->cpu))->env;
	uint64_t rip = env->eip;
	assert(asprintf( &res, "%lx\t\tSTR %d\t%s\n", rip, REDQUEEN_MAX_STRCMP_LEN*8, out_buf ) != -1);
	write_re_result(res);
	free(res);
}

static bool test_strchr(redqueen_t* self, uint64_t arg1, uint64_t arg2){
	if(!is_addr_mapped(arg1, self->cpu) || arg2 & (~0xff)){
    return false;
  }
	uint8_t buf1[REDQUEEN_MAX_STRCMP_LEN];
	uint8_t buf2[REDQUEEN_MAX_STRCMP_LEN];
	assert(read_virtual_memory(arg1, &buf1[0], REDQUEEN_MAX_STRCMP_LEN, self->cpu));
  if(!memchr(buf1,'\0',REDQUEEN_MAX_STRCMP_LEN) ){return false;}
  memset(buf2,'\0',REDQUEEN_MAX_STRCMP_LEN);
  buf2[0]=  (uint8_t)(arg2);
  format_strcmp(self, buf1, buf2);
  return true;
}

static bool test_strcmp(redqueen_t* self, uint64_t arg1, uint64_t arg2){
	if(!is_addr_mapped(arg1, self->cpu) || ! is_addr_mapped(arg2, self->cpu)){
		return false;
	}
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX,"valid ptrs");
	uint8_t buf1[REDQUEEN_MAX_STRCMP_LEN];
	uint8_t buf2[REDQUEEN_MAX_STRCMP_LEN];
	assert(read_virtual_memory(arg1, &buf1[0], REDQUEEN_MAX_STRCMP_LEN, self->cpu));
	assert(read_virtual_memory(arg2, &buf2[0], REDQUEEN_MAX_STRCMP_LEN, self->cpu));
  format_strcmp(self, buf1,buf2);
	return true;
}

static bool test_strcmp_cdecl(redqueen_t* self){
	uint64_t arg1 = read_stack(self, 0);
	uint64_t arg2 = read_stack(self, 1);
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "extract call params cdecl %lx %lx", arg1, arg2);
  test_strchr(self, arg1, arg2);
	return test_strcmp(self, arg1, arg2) ;

}

static bool test_strcmp_fastcall(redqueen_t* self){
	CPUX86State *env = &(X86_CPU(self->cpu))->env;
	uint64_t arg1 = env->regs[1]; //rcx
	uint64_t arg2 = env->regs[2]; //rdx
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "extract call params fastcall %lx %lx", arg1, arg2);
  test_strchr(self, arg1, arg2);
	return test_strcmp(self, arg1, arg2);
}

static bool test_strcmp_sys_v(redqueen_t* self){
	if(self->cpu->disassembler_word_width != 64 ){return false;}
	CPUX86State *env = &(X86_CPU(self->cpu))->env;
	uint64_t arg1 = env->regs[7]; //rdx
	uint64_t arg2 = env->regs[6]; //rsi
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "extract call params sysv %lx %lx", arg1, arg2);
  test_strchr(self, arg1, arg2);
	return test_strcmp(self, arg1, arg2);
}

static void extract_call_params(redqueen_t* self, uint64_t ip){
	//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "extract call at %lx", ip);
	test_strcmp_cdecl(self);
	test_strcmp_fastcall(self);
	test_strcmp_sys_v(self);
}

static bool is_memory_access(redqueen_t* self, cs_insn* insn){
  return insn->id != X86_INS_LEA && strstr(insn->op_str,"[");
}

static bool is_trace_entry_point(redqueen_t* self, uint64_t addr){
	if(addr >= self->address_range_start && addr <= self->address_range_end){
    return self->bitmap[addr-self->address_range_start] & CMP_BITMAP_TRACE_ENABLED;
  }
  return false;
}

static void handle_hook_redqueen_light(redqueen_t* self, uint64_t ip, cs_insn *insn){
	if(insn->id == X86_INS_CMP || insn->id == X86_INS_XOR){ //handle original redqueen case
		get_cmp_value(self, ip, "CMP");
  } else if(insn->id == X86_INS_SUB){ //handle original redqueen case
		get_cmp_value(self, ip, "SUB");
  } else if(insn->id == X86_INS_LEA){ //handle original redqueen case
		get_cmp_value_lea(self, ip);
  } else if(insn->id == X86_INS_ADD){ //handle original redqueen case
		get_cmp_value_add(self, ip);
	} else if (insn->id == X86_INS_CALL || insn->id == X86_INS_LCALL){
		extract_call_params(self, ip);
	}
}

static void handle_hook_redqueen_se( redqueen_t* self, uint64_t ip, cs_insn *insn){
	int unused __attribute__((unused));
	CPUX86State *env = &(X86_CPU(self->cpu))->env;
    if( is_trace_entry_point(self, ip) ){
      char* res = NULL;
      unused = asprintf(&res, "{\"ep\": %"PRIu64", ", ip);
      write_se_result(res);
      dump_se_registers(self);
      write_se_result((char*)" }\n");
      write_se_result((char*)"{ ");
      dump_se_memory_access_at(self, env->eip, env->regs[RSP]+64);
      write_se_result((char*)" }\n");
      free(res);
    }
    if( is_memory_access(self, insn) ){
      write_se_result((char*)"{ ");
      dump_se_memory_access(self, insn);
      write_se_result((char*)" }\n");
    }
    if(insn->id == X86_INS_RET || insn->id == X86_INS_POP){
      write_se_result((char*)"{ ");
      dump_se_return_access(self, insn);
      write_se_result((char*)" }\n");
    }
}

static void handle_hook_breakpoint(redqueen_t* self){
    X86CPU *cpu = X86_CPU(self->cpu);
    CPUX86State *env = &cpu->env;
    csh handle;
    cs_insn *insn;
    uint64_t ip = env->eip;
    uint8_t* code = (self->code+(ip-self->address_range_start));
    //uint64_t cs_address = ip;
	  size_t code_size = self->address_range_end - ip;
    if (cs_open(CS_ARCH_X86, get_capstone_mode(self->cpu->disassembler_word_width), &handle) == CS_ERR_OK){
      cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
      size_t count = cs_disasm(handle, code, code_size, ip, 1, &insn);
	    QEMU_PT_PRINTF(REDQUEEN_PREFIX, " === HANDLE REDQUEEN HOOK %s %s ===", insn->mnemonic, insn->op_str);
      if(count > 0){
        int mode = self->cpu->redqueen_instrumentation_mode;
        if(mode == REDQUEEN_LIGHT_INSTRUMENTATION || mode == REDQUEEN_WHITELIST_INSTRUMENTATION || mode == REDQUEEN_SE_INSTRUMENTATION){
          handle_hook_redqueen_light(self, ip, insn);
        }
        if(mode == REDQUEEN_SE_INSTRUMENTATION){
          handle_hook_redqueen_se(self, ip, insn);
        }
      }
      cs_close(&handle);
      cs_free(insn, count);
    } else{
      printf("Oops!\n");
    }
}

/*
static void debug_print_disasm(char* desc, uint64_t ip, CPUState* cpu_state){
  //uint64_t cs_address = ip;
  uint8_t code[64];
  csh handle;
  cs_insn *insn;
  read_virtual_memory(ip, &code[0], 64, cpu_state);
  if (cs_open(CS_ARCH_X86, get_capstone_mode(cpu_state->disassembler_word_width), &handle) == CS_ERR_OK){
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t count = cs_disasm(handle, &code[0], 64, ip, 1, &insn);
    if(count > 0){
      QEMU_PT_PRINTF(REDQUEEN_PREFIX,"%s\t %lx: %s %s",desc, ip,  insn->mnemonic, insn->op_str);
    } else {
      QEMU_PT_PRINTF(REDQUEEN_PREFIX,"%s\t Failed to disassemble at: %lx",desc, ip);
    }
    cs_close(&handle);
    cs_free(insn, count);
  } else {
      QEMU_PT_PRINTF(REDQUEEN_PREFIX,"%s\t Failed to create capstone instance at: %lx",desc, ip);
  }
}
*/

/*
static void debug_print_state(char* desc, CPUState* cpu_state){
  X86CPU *cpu = X86_CPU(cpu_state);
  CPUX86State *env = &cpu->env;
  debug_print_disasm(desc, env->eip, cpu_state);
  QEMU_PT_PRINTF(REDQUEEN_PREFIX,"ECX: %lx", get_reg_cpu(cpu_state, (char*)"rcx"));
}
*/

int trace_debug = false;

void handle_hook(redqueen_t* self){
  X86CPU *cpu = X86_CPU(self->cpu);
  CPUX86State *env = &cpu->env;
  if(!self->cpu->singlestep_enabled){
    self->last_rip = env->eip;
    kvm_remove_breakpoint(self->cpu, env->eip, 1, 0);
    self->cpu->singlestep_enabled = true;
    self->singlestep_enabled = true;
    kvm_update_guest_debug(self->cpu, 0);
    if(self->cpu->pt_enabled && self->cpu->pt_c3_filter == env->cr[3]){
      handle_hook_breakpoint(self);
    }
  } else{
    self->cpu->singlestep_enabled = false;
    self->singlestep_enabled = false;
    kvm_update_guest_debug(self->cpu, 0);
    if(self->counter_bitmap[self->last_rip-self->address_range_start]++ < REDQUEEN_TRAP_LIMIT){
	  kvm_insert_breakpoint(self->cpu, self->last_rip, 1, 0);
    }
  }
}

void dump_se_return_access(redqueen_t* self, cs_insn* insn){
	int unused __attribute__((unused));
  X86CPU *cpu = X86_CPU(self->cpu);
  CPUX86State *env = &cpu->env;
  char* res = NULL;
  uint8_t buf[8];
  char hex_buf[16+1];
  uint64_t begin = env->regs[RSP];
  read_virtual_memory(begin, (uint8_t*)&buf, 8, self->cpu);
  char* tmp_hex_buf = hex_buf;
  for(int i = 0; i < 8; i++){
    tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf[i]);
  }
  unused = asprintf( &res, "\"access\":%"PRIu64", \"mem\":[%"PRIu64",\"%s\"]", env->eip, begin, hex_buf ) ;
  write_se_result(res);
  free(res);
}

#define REDQUEEN_SE_MEMORY_DUMP_SIZE 256
#define REDQUEEN_SE_MEMORY_DUMP_OFFSET 64

void dump_se_memory_access_at(redqueen_t* self, uint64_t instr_addr, uint64_t mem_addr){
      int unused __attribute__((unused));
      char* res = NULL;
      uint8_t buf[REDQUEEN_SE_MEMORY_DUMP_SIZE];
      char hex_buf[REDQUEEN_SE_MEMORY_DUMP_SIZE*2+1];
      memset(buf,'X',REDQUEEN_SE_MEMORY_DUMP_SIZE);
      if(mem_addr > 24+REDQUEEN_SE_MEMORY_DUMP_OFFSET){
        uint64_t begin = mem_addr - REDQUEEN_SE_MEMORY_DUMP_OFFSET;
        read_virtual_memory(begin, (uint8_t*)&buf, REDQUEEN_SE_MEMORY_DUMP_SIZE, self->cpu);
        char* tmp_hex_buf = hex_buf;
        for(int i = 0; i < REDQUEEN_SE_MEMORY_DUMP_SIZE; i++){
          tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf[i]);
        }
        unused = asprintf( &res, "\"access\":%"PRIu64", \"mem\":[%"PRIu64",\"%s\"]", instr_addr, begin, hex_buf ) ;
        write_se_result(res);
        free(res);
      }
}

static void dump_se_memory_for_op(redqueen_t* self, asm_operand_t *op){
    X86CPU *cpu = X86_CPU(self->cpu);
    CPUX86State *env = &cpu->env;
    if(op->was_present && op->ptr_size){
      uint64_t addr = eval_addr(self, op);
      dump_se_memory_access_at(self, env->eip, addr);
    }
}

void dump_se_memory_access(redqueen_t* self, cs_insn* insn){
  asm_operand_t op1 = {0};
  asm_operand_t op2 = {0};
  parse_op_str2(insn->op_str, &op1, &op2);
  dump_se_memory_for_op(self, &op1);
  dump_se_memory_for_op(self, &op2);
  asm_decoder_clear(&op1);
  asm_decoder_clear(&op2);
}


void dump_se_registers(redqueen_t* self){
	int unused __attribute__((unused));
  char* res = NULL;
  X86CPU *cpu = X86_CPU(self->cpu);
  CPUX86State *env = &cpu->env;
  uint64_t rip = env->eip;
  uint64_t rax = env->regs[RAX];
  uint64_t rbx = env->regs[RBX];
  uint64_t rcx = env->regs[RCX];
  uint64_t rdx = env->regs[RDX];
  uint64_t rsp = env->regs[RSP];
  uint64_t rbp = env->regs[RBP];
  uint64_t rsi = env->regs[RSI];
  uint64_t rdi = env->regs[RDI]; 
  uint64_t r8 =  env->regs[R8];
  uint64_t r9 =  env->regs[R9];
  uint64_t r10 = env->regs[R10];
  uint64_t r11 = env->regs[R11];
  uint64_t r12 = env->regs[R12];
  uint64_t r13 = env->regs[R13];
  uint64_t r14 = env->regs[R14];
  uint64_t r15 = env->regs[R15];
  uint64_t eflags = env->eflags;
  uint64_t gs = env->segs[R_GS].base;
  uint64_t fs = env->segs[R_FS].base;
  //printf(
  //    "\"regs\":[" "%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 ",%"PRIx64 "]\n",
  //              rip,   rax,   rbx,   rcx,   rdx,    r8,    r9,   r10,   r11,   r12,   r13,   r14,   r15,   rsp,   rbp,   rsi,   rdi,eflags,    gs) ;
  unused = asprintf(&res, 
      "\"regs\":[" "%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64 ",%"PRIu64",%"PRIu64 "]",
                rip,   rax,   rbx,   rcx,   rdx,    r8,    r9,   r10,   r11,   r12,   r13,   r14,   r15,   rsp,   rbp,   rsi,   rdi,eflags,    gs, fs) ;
  write_se_result(res);
  free(res);
}

void redqueen_register_transition(redqueen_t* self, uint64_t src, uint64_t target){
	int unused __attribute__((unused));
	if(self->trace_mode){
#ifdef RQ_DEBUG
		printf("{\"edge\": [%"PRIu64",%"PRIu64"] }\n", src, target);
#endif
		char* res = NULL;
		unused = asprintf(&res, "{\"edge\": [%"PRIu64",%"PRIu64"] }\n", src, target);
		write_trace_result(res);
		free(res);
	}
}

void redqueen_trace_enabled(redqueen_t* self, uint64_t ip){
	int unused __attribute__((unused));
  if(self->trace_mode){
    char* res = NULL;
    unused = asprintf(&res, "{\"trace_enable\": %"PRIu64" }\n", ip);
    write_trace_result(res);
    free(res);
    set_rq_trace_enabled_bp(self, ip);
  } 
}

void redqueen_trace_disabled(redqueen_t* self, uint64_t ip){
  //if(!self->intercept_mode){
  //  char* res = NULL;
  //  asprintf(&res, "{\"trace_disable\": %"PRIu64" }\n", ip);
  //  write_trace_result(res);
  //  free(res);
  //}
}

static void _redqueen_update_whitelist(redqueen_t* self){
  if(self->cpu->redqueen_instrumentation_mode == REDQUEEN_WHITELIST_INSTRUMENTATION){
    //size_t num_addrs = 0;
    //uint64_t *addrs;
    free(self->breakpoint_whitelist);
    parse_address_file(redqueen_workdir.breakpoint_white, &self->num_breakpoint_whitelist, &self->breakpoint_whitelist);
  }
}

static void _redqueen_update_blacklist(redqueen_t* self){
  if(self->cpu->redqueen_update_blacklist){
    size_t num_addrs = 0;
    uint64_t *addrs;
    parse_address_file(redqueen_workdir.breakpoint_black, &num_addrs, &addrs);
    for(size_t i = 0; i< num_addrs; i++){
      set_rq_blacklist(self, addrs[i]);
    }
    free(addrs);
  }
}

extern void* payload_buffer;

void enable_rq_intercept_mode(redqueen_t* self){
	if(!self->intercept_mode){
		delete_redqueen_files();
		//unlink("/tmp/redqueen_result.txt");
    _redqueen_update_whitelist(self);
    _redqueen_update_blacklist(self);
		redqueen_insert_hooks(self);
		self->intercept_mode = true;
		//((uint8_t*) payload_buffer)[PAYLOAD_SIZE-1] = 1;
	}
}

void disable_rq_intercept_mode(redqueen_t* self){
	if(self->intercept_mode){
		redqueen_remove_hooks(self);
		self->intercept_mode = false;
		//((uint8_t*) payload_buffer)[PAYLOAD_SIZE-1] = 0;
	}
}
