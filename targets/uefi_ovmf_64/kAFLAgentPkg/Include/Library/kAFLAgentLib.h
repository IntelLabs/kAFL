/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 * Copyright 2020 Intel Corporation
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

/******************************************************************************
 * High-level Harness API
 *****************************************************************************/

/*
 * One-time initialization function
 *
 * Called once after fuzzing handshake to check/initialize any dependencies
 */
VOID
EFIAPI
InitTestHarness (VOID);

/*
 * Execute on a single fuzzing input
 *
 * In persistent fuzzing, this is called many thousand times.
 * Any side-effects/context must be reset on re-entry.
 */
EFI_STATUS
EFIAPI
RunTestHarness (
		IN VOID  *TestBuffer,
		IN UINTN TestBufferSize
		);

/******************************************************************************
 * Low-level kAFL API
 *****************************************************************************/
#include <stdarg.h>
#include <stdio.h>

#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef uint32_t
#define uint32_t UINT32
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#ifndef u_long
#define u_long UINT64
#endif

#ifndef uint_ptr
#if defined(__i386__)
#define uint_ptr uint32_t
#elif defined(__x86_64__)
#define uint_ptr uint64_t
#endif
#endif

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
#define INFO_SIZE							(128 << 10)				/* 128KB info string */

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

#if defined(__i386__)
void kAFL_hypercall(uint32_t rbx, uint32_t rcx);
#elif defined(__x86_64__)
void kAFL_hypercall(uint64_t rbx, uint64_t rcx);
#endif

#endif /* _KAFL_AGENT_LIB_H_ */
