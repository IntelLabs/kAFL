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

#include "filter.h"
#include <fcntl.h>

/* http://zimbry.blogspot.ch/2011/09/better-bit-mixing-improving-on.html */
static inline uint64_t mix_bits(uint64_t v) {
  v ^= (v >> 31);
  v *= 0x7fb5d329728ea185;
  v ^= (v >> 27);
  v *= 0x81dadef4bc2dd44d;
  v ^= (v >> 33);
  return v;
}

static inline uint64_t mix_tuple(uint64_t curent_addr, uint64_t prev_addr){
  return mix_bits((curent_addr<<32) + (prev_addr&0xFFFFFFFF));
}

static bool filter_get_bitmap(filter_t* self, uint8_t* bitmap, uint64_t offset){
  assert(offset <= self->size);
  return (bitmap[offset/8] & (1<< offset%8));
}

static void filter_set_bitmap(filter_t* self, uint8_t* bitmap, uint64_t offset){
  assert(offset <= self->size);
  bitmap[offset/8] |= (1<< offset%8);
}

static bool filter_get_bitmap_sync(filter_t* self, uint8_t* bitmap, uint64_t offset){
  assert(offset <= self->size);
  return bitmap[offset];
}

static void filter_set_bitmap_sync(filter_t* self, uint8_t* bitmap, uint64_t offset){
  assert(offset <= self->size);
  if(!bitmap[offset]){
    bitmap[offset] = 1;  
    self->blacklist_count++;
  }
}

/* default: 128MB */
filter_t* new_filter(uint64_t from, uint64_t to, uint8_t *filter_bitmap){
  filter_t* res = malloc(sizeof(filter_t));
  assert(from < to);
  res->size = to-from;
  res->execs = 0;
  res->counters = malloc(res->size*2);
  res->from_addr = from;
  res->to_addr = to;
  res->hit_bitmap = malloc(res->size/8);
  res->filter_bitmap = filter_bitmap;
  res->prev_addr = 0x0;
  res->blacklist_count = 0;
  return res;
}

void filter_init_determinism_run(filter_t* self){
  self->execs = 0;
  memset(self->counters, 0, self->size*2);
}

void filter_init_new_exec(filter_t* self){
  memset(self->hit_bitmap, 0, self->size/8);
}

void filter_add_address(filter_t* self, uint64_t addr){
  if(self->from_addr <= addr && addr <= self->to_addr){
    filter_set_bitmap(self,self->hit_bitmap,addr-self->from_addr);
  }
}

void filter_finalize_exec(filter_t* self){
  self->execs ++;
  for(uint64_t a = self->from_addr; a < self->to_addr; a++){
    if(filter_get_bitmap(self, self->hit_bitmap,a - self->from_addr)){
      self->counters[a - self->from_addr] += 1;
    }
  }
}


void filter_finalize_determinism_run(filter_t* self){
  for(uint64_t a = self->from_addr; a < self->to_addr; a++){
    uint64_t o = a-self->from_addr;
    if(self->counters[o] != self->execs && self->counters[o]){
      filter_set_bitmap_sync(self, self->filter_bitmap, o);
    }
  }
}

bool filter_is_address_nondeterministic(filter_t* self, uint64_t addr){
  if(self->from_addr <= addr && addr <= self->to_addr){
    return filter_get_bitmap_sync(self, self->filter_bitmap,addr-self->from_addr);
  }
  return false;
}

uint32_t filter_count_new_addresses(filter_t* self){
  return self->blacklist_count;
}
