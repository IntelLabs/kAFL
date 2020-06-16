/*
 * Copyright 2020 Sergej Schumilo, Cornelius Aschermann
 * Copyright 2020 Intel Corporation
 * 
 * SPDX-License-Identifier: Apache-2.0
 */ 

/*
 * kAFL hypercall API, adapted from targets/kafl_user.h
 */

#ifndef KAFL_USER_H
#define KAFL_USER_H

#include <stdint.h>

#define HYPERCALL_KAFL_RAX_ID				0x01f
#define HYPERCALL_KAFL_ACQUIRE				0
#define HYPERCALL_KAFL_GET_PAYLOAD			1
#define HYPERCALL_KAFL_GET_PROGRAM			2
#define HYPERCALL_KAFL_GET_ARGV				3
#define HYPERCALL_KAFL_RELEASE				4
#define HYPERCALL_KAFL_SUBMIT_CR3			5
#define HYPERCALL_KAFL_SUBMIT_PANIC			6
#define HYPERCALL_KAFL_SUBMIT_KASAN			7
#define HYPERCALL_KAFL_PANIC				8
#define HYPERCALL_KAFL_KASAN				9
#define HYPERCALL_KAFL_LOCK					10
#define HYPERCALL_KAFL_INFO					11
#define HYPERCALL_KAFL_NEXT_PAYLOAD			12
#define HYPERCALL_KAFL_PRINTF				13
#define HYPERCALL_KAFL_PRINTK_ADDR			14
#define HYPERCALL_KAFL_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE	16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE		17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT			20
#define HYPERCALL_KAFL_TIMEOUT				21

#define PAYLOAD_SIZE						(128 << 10)				/* up to 128KB payloads */
#define PROGRAM_SIZE						(128 << 20)				/* kAFL supports 128MB programm data */
#define INFO_SIZE        					(128 << 10)				/* 128KB info string */

typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-sizeof(int32_t)-sizeof(uint8_t)];
	uint8_t redqueen_mode;
} kAFL_payload;

typedef struct{
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges;

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

//#define KAFL_SIM
#ifndef KAFL_SIM
static inline void kAFL_hypercall(uint32_t p1, void* p2)
{
	uint32_t nr = HYPERCALL_KAFL_RAX_ID;
	asm ("vmcall"
			: : "a"(nr), "b"(p1), "c"(p2));
}
#else
static kAFL_payload *sim_payload;
static char* sim_inputs[] = {
	"0",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"0123456789",
	"ABCDEFG",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"AAAAAAAAAAAAAAAAAA",
	"SERGEJAFLABCDEFG",
	"",
	"AAAAAAAAAAAAAAAAAA",
	"KASANABCDEFG0123",
	"",
	"AAAAAAAAAAAAAAAAAA",
	"",
	"KERNELAFLABCDEFG",
};
static int sim_idx = 0;
static inline void kAFL_hypercall(uint32_t p1, void* p2)
{
	switch(p1) {
		case HYPERCALL_KAFL_ACQUIRE:
			printk("hypercall: KAFL_AQUIRE()\n");
			break;
		case HYPERCALL_KAFL_GET_PAYLOAD:
			printk("hypercall: KAFL_GET_PAYLOAD(%p)\n", p2);
			sim_payload = (kAFL_payload*)p2;
			break;
		case HYPERCALL_KAFL_GET_PROGRAM:
			printk("hypercall: KAFL_GET_PROGRAM()\n");
			break;
		case HYPERCALL_KAFL_GET_ARGV:
			printk("hypercall: KAFL_GET_ARGV()\n");
			break;
		case HYPERCALL_KAFL_RELEASE:
			printk("hypercall: KAFL_RELEASE()\n");
			break;
		case HYPERCALL_KAFL_SUBMIT_CR3:
			printk("hypercall: KAFL_CR3(%p)\n", p2);
			break;
		case HYPERCALL_KAFL_SUBMIT_PANIC:
			printk("hypercall: KAFL_SUBMIT_PANIC(%p)\n", p2);
			break;
		case HYPERCALL_KAFL_SUBMIT_KASAN:
			printk("hypercall: KAFL_SUBMIT_KASAN(%p)\n", p2);
			break;
		case HYPERCALL_KAFL_PANIC:
			printk("hypercall: KAFL_isPANIC()\n");
			break;
		case HYPERCALL_KAFL_KASAN:
			printk("hypercall: KAFL_isKASAN()\n");
			break;
		case HYPERCALL_KAFL_LOCK:
			printk("hypercall: KAFL_LOCK()\n");
			break;
		case HYPERCALL_KAFL_INFO:
			printk("hypercall: KAFL_INFO()\n");
			printk("%s\n", (char*)p2);
			break;
		case HYPERCALL_KAFL_NEXT_PAYLOAD:
			printk("hypercall: KAFL_NEXT_PAYLOAD()\n");
			sim_idx = (sim_idx + 1) % sizeof(*sim_inputs);
			sim_payload->size = strlen(sim_inputs[sim_idx]);
			memcpy(sim_payload->data, sim_inputs[sim_idx], sim_payload->size);
			break;
		default:
			printk("Invalid hypercall!\n");
	}
}

#endif /* KAFL_SIM */
#endif /* KAFL_USER_H */
