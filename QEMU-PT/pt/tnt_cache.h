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

#ifndef TNT_CACHE_H
#define TNT_CACHE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define NOT_TAKEN			0
#define TAKEN				1
#define TNT_EMPTY			2

#define SHORT_TNT_OFFSET	1
#define SHORT_TNT_MAX_BITS	8-1-SHORT_TNT_OFFSET

#define LONG_TNT_OFFSET		16
#define LONG_TNT_MAX_BITS	64-1-LONG_TNT_OFFSET

#define BUF_SIZE 0x1000000      /* 16777216 slots */

typedef struct tnt_cache_s{
	uint8_t* tnt_memory;
	uint64_t pos;
	uint64_t max;
	uint64_t tnt;
} tnt_cache_t;

tnt_cache_t* tnt_cache_init(void);
void tnt_cache_destroy(tnt_cache_t* self);
void tnt_cache_flush(tnt_cache_t* self);


bool is_empty_tnt_cache(tnt_cache_t* self);
int count_tnt(tnt_cache_t* self);
uint8_t process_tnt_cache(tnt_cache_t* self);

void append_tnt_cache(tnt_cache_t* self, uint8_t data);
void append_tnt_cache_ltnt(tnt_cache_t* self, uint64_t data);

#endif 
