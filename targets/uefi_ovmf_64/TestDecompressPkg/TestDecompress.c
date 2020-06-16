/* @file TestDecompress.c
 *
 * Copyright 2020 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/BmpSupportLib.h>
#include <Protocol/ShellParameters.h>
#include  <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Shell.h>
#include <Guid/FileInfo.h>
#include <Library/CapsuleLib.h>
#include <Library/UefiDecompressLib.h>
#include <Library/SafeIntLib.h>

#include <Library/kAFLAgentLib.h>
#include <Library/CpuExceptionHandlerLib.h>

#define KAFL_VERBOSE
#ifndef KAFL_VERBOSE
#define KAFL_PRINT(...)
#else
#define KAFL_PRINT			Print
#endif

EFI_STATUS EFIAPI RunTestHarness(IN VOID *InputBuffer, IN UINTN InputLength)
{
	EFI_STATUS          Status;
	CHAR8               *Scratch = NULL;
	UINT32              ScratchSize;
	VOID                *Destination = NULL;
	UINT32              DestinationSize;

	KAFL_PRINT (L"Start->");
	Status = UefiDecompressGetInfo (
			(CHAR8*)InputBuffer,
			InputLength,
			&DestinationSize,
			&ScratchSize
			);

	if (EFI_ERROR (Status)) {
		KAFL_PRINT (L"Error G%d\n", Status);
		goto ERROR;
	}

	// Allocate scratch buffer
	Scratch = AllocateZeroPool (ScratchSize);
	if (Scratch == NULL) {
		KAFL_PRINT (L"Error A%d\n", Status);
		goto ERROR;
	}

	/* terribly complicated way of incrementing DestingationSize...who needs this?
	Status = SafeUint32Add(DestinationSize, 1, &DestinationSize);
	if (EFI_ERROR (Status)) {
		KAFL_PRINT (L"Error S%d\n", Status);
		goto ERROR;
	}
	*/

	// Allocate destination buffer, adding an extra page for security!
	// Surely this cannot overflow, can it..?!
	Destination = AllocateZeroPool (DestinationSize + 1);
	if (Destination == NULL) {
		KAFL_PRINT (L"Error A%d\n", Status);
		goto ERROR;
	}

	// Call decompress function
	Status = UefiDecompress (
			(CHAR8*)InputBuffer,
			Destination,
			Scratch
			);

	if (EFI_ERROR (Status)) {
		KAFL_PRINT (L"Error D%d\n", Status);
		goto ERROR;
	}

	KAFL_PRINT (L"Success! %d\n", Status);
ERROR:
	if (Scratch != NULL)
		FreePool(Scratch);
	if (Destination != NULL)
		FreePool(Destination);

	return Status;
}

VOID EFIAPI InitTestHarness(VOID)
{
	Print(L"Mapping info: UefiDecompressGetInfo is at %x\n", (void*)(UefiDecompressGetInfo));
	Print(L"Mapping info: DumpCpuContext is at %x\n", (void*)DumpCpuContext);
	//Print(L"Mapping info: DumpModuleImageInfo is at %x\n", (void*)DumpModuleImageInfo);

	/* Override target's word with autodetection
	 *
	 * Qemu log indicates the target is detected as 32bit even when OVMF+App are
	 * compiled for X64. This overrides the auto-detection and makes Redqueen
	 * actually find some bugs instead of just causing timeouts.
	 */
#if defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif
}

