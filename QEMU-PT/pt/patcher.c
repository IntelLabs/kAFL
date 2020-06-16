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

#include "patcher.h"
#include "pt/memory_access.h"
#include "pt/disassembler.h"
#include "debug.h"

uint8_t cmp_patch_data[] = { 0x38, 0xC0, [2 ... MAX_INSTRUCTION_SIZE]=0x90 }; // CMP AL,AL; NOP, NOP ... 
const uint8_t *cmp_patch = &cmp_patch_data[0];

///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Declarations
///////////////////////////////////////////////////////////////////////////////////
//
static void _patcher_apply_patch(patcher_t *self, size_t index);

static void _patcher_restore_patch(patcher_t *self, size_t index);

static void _patcher_save_patch(patcher_t *self, size_t index, uint8_t* data, size_t instruction_size, uint64_t addr);

static size_t _patcher_disassemble_size(patcher_t *self, uint8_t* data,  uint64_t addr, x86_insn id);

static void _patcher_alloc_patch_infos(patcher_t *self, size_t num_patches);

static void _patcher_free_patch_infos(patcher_t *self);

static redqueen_t* _redq_ptr(patcher_t *self);


///////////////////////////////////////////////////////////////////////////////////
// Public Functions
///////////////////////////////////////////////////////////////////////////////////

patcher_t* patcher_new(CPUState *cpu){
    patcher_t *res = malloc(sizeof(patcher_t));
    res->cpu = cpu;
    res->num_patches = 0;
    res->patches = NULL;
    res->is_currently_applied = false;
    return res;
}

void patcher_free(patcher_t* self){
    assert(!self->is_currently_applied);
    _patcher_free_patch_infos(self);
    free(self);
}

void patcher_apply_all(patcher_t *self){
  assert(!self->is_currently_applied);
  if (_redq_ptr(self)) assert(!_redq_ptr(self)->hooks_applied);
  //assert(patcher_validate_patches(self));
  for(size_t i=0; i < self->num_patches; i++){
      _patcher_apply_patch(self, i);
  }
  self->is_currently_applied = true;
}

void patcher_restore_all(patcher_t *self){
  assert(self->is_currently_applied);
  if (_redq_ptr(self)) assert(!_redq_ptr(self)->hooks_applied);
  //assert(patcher_validate_patches(self));
  for(size_t i = 0; i < self->num_patches; i++){
    _patcher_restore_patch(self, i);
  }
  self->is_currently_applied = false;
}

void patcher_set_addrs(patcher_t *self, uint64_t* addrs, size_t num_addrs){
  _patcher_free_patch_infos(self);
  _patcher_alloc_patch_infos(self, num_addrs);
  uint8_t curr_instruction_code[MAX_INSTRUCTION_SIZE];
  memset(&curr_instruction_code[0], 0, MAX_INSTRUCTION_SIZE);

  for(size_t i=0; i < self->num_patches; i++){
    //QEMU_PT_PRINTF(REDQUEEN_PREFIX, "patching %lx", addrs[i]);
    if( read_virtual_memory(addrs[i], &curr_instruction_code[0], MAX_INSTRUCTION_SIZE, self->cpu) ) {
      size_t size =_patcher_disassemble_size(self, &curr_instruction_code[0], addrs[i], X86_INS_CMP);
      assert(size != 0); //csopen failed, shouldn't happen
      _patcher_save_patch(self, i, &curr_instruction_code[0], size, addrs[i]);
    }
  }
}

static void print_hexdump(const uint8_t* addr, size_t size){
  for(size_t i = 0; i < size; i++){
	  printf (" %02x", addr[i]);
  }
  printf("\n");
}

bool patcher_validate_patches(patcher_t *self){
  bool was_rq = _redq_ptr(self)->hooks_applied;
  if(was_rq)
    redqueen_remove_hooks(_redq_ptr(self));
  if(!self->patches){return true;}
  for(size_t i=0; i<self->num_patches; i++){
    uint8_t buf[MAX_INSTRUCTION_SIZE];
    read_virtual_memory(self->patches[i].addr, &buf[0], MAX_INSTRUCTION_SIZE, self->cpu);
    const uint8_t* should_value = NULL;
    if(self->is_currently_applied){
      should_value = cmp_patch;
    } else {
      should_value = &self->patches[i].orig_bytes[0];
    }

    QEMU_PT_PRINTF(REDQUEEN_PREFIX, "Validating, mem:");
    print_hexdump(&buf[0], self->patches[i].size);
    QEMU_PT_PRINTF(REDQUEEN_PREFIX, "should_be:");
    print_hexdump(should_value, self->patches[i].size);
    if(0 != memcmp(&buf[0], should_value, self->patches[i].size)){
      QEMU_PT_PRINTF(REDQUEEN_PREFIX, "validating patches failed self->is_currently_applied = %d",  self->is_currently_applied);
      return false;
    }
  }
  if(was_rq)
    redqueen_insert_hooks(_redq_ptr(self));
  return true;
}


///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Definitions
///////////////////////////////////////////////////////////////////////////////////


static void _patcher_apply_patch(patcher_t *self, size_t index) {
  patch_info_t *info = &self->patches[index];
	write_virtual_shadow_memory(info->addr, (uint8_t*)cmp_patch, info->size, self->cpu);
}

static void _patcher_restore_patch(patcher_t *self, size_t index){
  patch_info_t *info = &self->patches[index];
	write_virtual_shadow_memory(info->addr, (uint8_t*)&info->orig_bytes[0], info->size, self->cpu);
}

static void _patcher_save_patch(patcher_t *self, size_t index, uint8_t* data, size_t instruction_size, uint64_t addr) {
  assert(instruction_size >= 2);
  assert(instruction_size < MAX_INSTRUCTION_SIZE);
  patch_info_t *info = &self->patches[index];
  memset(&info->orig_bytes[0], 0, MAX_INSTRUCTION_SIZE);
  memcpy(&info->orig_bytes[0], data, instruction_size);
  info->addr = addr;
  info->size = instruction_size;
}

static size_t _patcher_disassemble_size(patcher_t *self, uint8_t* data, uint64_t addr, x86_insn type){

    csh handle;
    if (cs_open(CS_ARCH_X86, get_capstone_mode(self->cpu->disassembler_word_width), &handle) == CS_ERR_OK){
      cs_insn *insn = cs_malloc(handle);
      uint8_t* cur_offset = data;
      uint64_t cs_address = addr;
      uint64_t code_size = MAX_INSTRUCTION_SIZE;
      cs_disasm_iter(handle, (const uint8_t **) &cur_offset, &code_size, &cs_address, insn);
      size_t size = insn->size;
      if(type != X86_INS_INVALID){
        assert(insn->id == type);
      }
      cs_free(insn, 1);
      cs_close(&handle);
      return size;
    }
    return 0;
}

static void _patcher_alloc_patch_infos(patcher_t *self, size_t num_patches){
  assert(self->num_patches == 0);
  assert(self->patches == NULL);
  assert(num_patches < 10000);
  self->num_patches = num_patches;
  self->patches = malloc(sizeof(patch_info_t)*num_patches);
}

static void _patcher_free_patch_infos(patcher_t *self){
  assert(!self->is_currently_applied);
  free(self->patches);
  self->patches = NULL;
  self->num_patches = 0;
}

static redqueen_t* _redq_ptr(patcher_t *self){
  redqueen_t* res = self->cpu->redqueen_state[0];
  return res;
}
