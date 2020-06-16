/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>
#include <fatal.h>
#include <sys/check.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define _GNU_SOURCE
#include "kafl_user.h"
#include "target.h"

#ifdef DEBUG
static void test_panic(void)
{
	printk("kAFL test_panic()\n");

	/* panic hook captures all of the following */
	k_panic();
	//k_oops();
	//__ASSERT(0 == 1, "0 == 1");
	//target_entry("KERNELAFLAA", strlen("KERNELAFLAA"));
	//target_entry("SERGEJABC", strlen("SERGEJABC"));

	printk("Warning - this code should not be reached!\n");
}
#endif

static void agent_init(void *panic_handler, void *kasan_handler)
{
	printk("Initiate fuzzer handshake...\n");

	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* submit panic and optionally kasan handlers for qemu override */
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);

	if (kasan_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, kasan_handler);
	}
}

static void agent_run(void)
{
	/* 
	 * Heap allocation causes an interesting bug where agent crashes without proper
	 * detection/handling by the fuzzer..would be good to fix/report any such issues
	 * to make porting to new targets easier and don't waste cpu on broken threads..
	 */
#ifdef PAYLOAD_ON_HEAP
	kAFL_payload* payload_buffer = k_malloc(PAYLOAD_SIZE);
	if (!payload_buffer)
		return;
#else
	uint8_t buffer[PAYLOAD_SIZE];
	kAFL_payload* payload_buffer = (kAFL_payload*)buffer;
#endif

	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, payload_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	target_init();

	while (1) {
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
#ifdef DEBUG
		test_panic();
#endif
		target_entry(payload_buffer->data, payload_buffer->size);

		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
}

/*
 * That function is weak symbol on Zephyr, just override it with our
 * function to notify KVM through hypercall.
 */
void k_sys_fatal_error_handler(unsigned int reason, const z_arch_esf_t *esf)
{
	switch (reason) {
		case K_ERR_CPU_EXCEPTION:
		case K_ERR_KERNEL_OOPS:
		case K_ERR_KERNEL_PANIC:
			kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
			break;
		default:
			kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
			break;
	}

	k_fatal_halt(reason);
}

void main(void)
{
	printk("kAFL Hello World! %s\n\n", CONFIG_BOARD);
	
	// skip rewrite in favor of custom k_sys_fatal_error_handler()
	void* panic_handler = NULL;
	void* kasan_handler = NULL;

	printk("Kernel Panic Handler Address:\t%p\n", panic_handler);

	if (kasan_handler){
		printk("Kernel KASAN Handler Address:\t%p\n", kasan_handler);
	}

	agent_init(panic_handler, kasan_handler);
	agent_run();
}
