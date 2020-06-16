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


#ifndef __FILTER__
#define __FILTER__

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

typedef struct filter_s {
  size_t size;
  uint16_t execs;
  uint16_t *counters;
  uint8_t *hit_bitmap;
  uint8_t *filter_bitmap;
  uint64_t prev_addr;
  uint64_t from_addr;
  uint64_t to_addr;
  uint32_t blacklist_count;
} filter_t;



filter_t* new_filter(uint64_t from, uint64_t to, uint8_t *filter_bitmap);

void filter_init_determinism_run(filter_t* self);

void filter_init_new_exec(filter_t* self);

void filter_add_address(filter_t* self, uint64_t addr);

void filter_finalize_exec(filter_t* self);

void filter_finalize_determinism_run(filter_t* self);

bool filter_is_address_nondeterministic(filter_t* self, uint64_t addr);

uint32_t filter_count_new_addresses(filter_t* self);

#endif
