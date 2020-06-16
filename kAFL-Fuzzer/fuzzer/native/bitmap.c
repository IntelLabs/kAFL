/*
Copyright (C) 2019  Sergej Schumilo, Cornelius Aschermann, Tim Blazytko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

static const uint8_t bucket_lut[256] = {
  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128
};

static void con() __attribute__((constructor));
void init() {

}

/**
 * @brief Checks if two bitmaps differ.
 * @param bitmap The bucket bitmap.
 * A zero bit indicates that the specific bucket of the given byte is free.
 * @param new_bitmap A bitmap from a recent run.
 * Each byte value of this map is assigned to one of 9 buckets.
 * @param bitmap_size The length of both bitmaps.
 * @return true if the maps differ after "bucketing".
 */
uint64_t are_new_bits_present_do_apply_lut(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  uint64_t bit_count = 0;
  uint64_t byte_count = 0;
  for (uint64_t i = 0; i < bitmap_size; i++) {
		uint8_t a = bucket_lut[new_bitmap[i]];
		new_bitmap[i] = a; //THIS ONE is not availble below at no_apply_lut
		if( (a | bitmap[i]) != bitmap[i] )  {
			if (bitmap[i]==0){
				byte_count++;
			} else {
				bit_count++;
			}
		}
	}
  return (uint64_t)((byte_count << 32) + (bit_count));
}

uint64_t are_new_bits_present_no_apply_lut(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  uint64_t bit_count = 0;
  uint64_t byte_count = 0;

  for (uint64_t i = 0; i < bitmap_size; i++) {
		uint8_t a = new_bitmap[i];
		if( (a | bitmap[i]) != bitmap[i] )  {
			if (bitmap[i]==0){
				byte_count++;
			} else {
				bit_count++;
			}
		}
  }
  return (uint64_t)((byte_count << 32) + (bit_count));
}

void update_global_bitmap(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  for (uint64_t i = 0; i < bitmap_size; i++) {
        bitmap[i] |= new_bitmap[i];
  }
}

void apply_bucket_lut(uint8_t * bitmap, uint64_t bitmap_size) {
  for (uint64_t i = 0; i < bitmap_size; i++) {
		bitmap[i] = bucket_lut[bitmap[i]];
  }
}

/* AFL source code incoming... */
uint8_t could_be_bitflip(uint32_t xor_val) {

  uint32_t sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}

/* AFL source code incoming... */
#define SWAP16(_x) ({ \
    uint16_t _ret = (_x); \
    (uint16_t)((_ret << 8) | (_ret >> 8)); \
  })

/* AFL source code incoming... */
#define SWAP32(_x) ({ \
    uint32_t _ret = (_x); \
    (uint32_t)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

/* AFL source code incoming... */
uint8_t could_be_arith(uint32_t old_val, uint32_t new_val, uint8_t blen, uint8_t ARITH_MAX) {

  uint32_t i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {

    uint8_t a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((uint8_t)(ov - nv) <= ARITH_MAX ||
        (uint8_t)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    uint16_t a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((uint32_t)(old_val - new_val) <= ARITH_MAX ||
        (uint32_t)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((uint32_t)(old_val - new_val) <= ARITH_MAX ||
        (uint32_t)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */


static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };


uint8_t could_be_interest(uint32_t old_val, uint32_t new_val, uint8_t blen, uint8_t check_le) {

  uint32_t i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      uint32_t tval = (old_val & ~(0xff << (i * 8))) |
                 (((uint8_t)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      uint32_t tval = (old_val & ~(0xffff << (i * 8))) |
                 (((uint16_t)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (uint32_t)interesting_32[j]) return 1;

  }

  return 0;

}
