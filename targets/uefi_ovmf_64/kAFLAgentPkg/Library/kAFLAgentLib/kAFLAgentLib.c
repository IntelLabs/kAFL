/*
 * kAFL Agent Lib for UEFI OVMF
 *
 * Implements fuzzing harness based on kAFL hypercall API
 *
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <Uefi.h>
#include <Library/BaseLib.h>
#include  <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/kAFLAgentLib.h>

#if defined(__i386__)
void kAFL_hypercall(uint32_t rbx, uint32_t rcx)
{
	uint32_t rax = HYPERCALL_KAFL_RAX_ID;
	asm volatile("movl %0, %%ecx;"
			     "movl %1, %%ebx;"
			     "movl %2, %%eax;"
			     "vmcall"
			    :
			    : "r" (rcx), "r" (rbx), "r" (rax)
			    : "eax", "ecx", "ebx"
			);
}
#elif defined(__x86_64__)
void kAFL_hypercall(uint64_t rbx, uint64_t rcx)
{
	uint64_t rax = HYPERCALL_KAFL_RAX_ID;
	asm volatile("movq %0, %%rcx;"
			     "movq %1, %%rbx;"
			     "movq %2, %%rax;"
			     "vmcall"
			    :
			    : "r" (rcx), "r" (rbx), "r" (rax)
			    : "rax", "rcx", "rbx"
			);
}
#endif

void agent_init(void *panic_handler, void *kasan_handler)
{
	Print(L"Initiate fuzzer handshake...\n");
	
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* submit panic and optionally kasan handlers for qemu
	 * override */
	if (panic_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uint_ptr)panic_handler);
	}

	if (kasan_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uint_ptr)kasan_handler);
	}

	/* target-specific initialization, if any */
	InitTestHarness();
}

void agent_run()
{
    uint8_t buffer[PAYLOAD_SIZE];
    kAFL_payload* payload_buffer = (kAFL_payload*)buffer;

    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint_ptr)payload_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    while (1) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        RunTestHarness(payload_buffer->data, payload_buffer->size);

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    return;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
	/* 
	 * TODO find a function that kAFL can hook to detect protection faults / crashes.
	 * Hooking the exception handler or DumpCpuContext helper does not seem to work..
	 *
	 * As a workaround, we currently require a patch to EDK2 to inject these hypercalls.
	 */
	//agent_init(DumpCpuContext, 0);
	agent_init(NULL, NULL);
	agent_run();

	return EFI_SUCCESS;
}

