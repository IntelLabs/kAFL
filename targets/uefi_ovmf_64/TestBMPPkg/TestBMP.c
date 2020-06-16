/* @file TestBMP.c
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
#include <Library/kAFLAgentLib.h>
#include <Library/CpuExceptionHandlerLib.h>


#define TOTAL_SIZE (512*1024)

UINTN
EFIAPI
GetMaxBufferSize ( VOID )
{
	return TOTAL_SIZE;
}

VOID
EFIAPI
InitTestHarness (VOID)
{
	/* kAFL debug info */
	Print(L"Mapping info: TranslateBmpToGopBlt is at %x\n", (void*)TranslateBmpToGopBlt);
	Print(L"Mapping info: DumpCpuContext is at %x\n", (void*)DumpCpuContext);
	//Print(L"Mapping info: DumpModuleImageInfo is at %x\n", (void*)DumpModuleImageInfo);
	//
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

EFI_STATUS
EFIAPI
RunTestHarness (
		IN VOID *input,
		IN UINTN inputSize
		)
{
	EFI_STATUS                                    Status;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL                 *Blt;
	UINTN                                         BltSize;
	UINTN                                         Height;
	UINTN                                         Width;
	VOID                                          *BmpBuffer;
	IN UINTN                                      FileSize;

	// input params
	BmpBuffer = input;
	FileSize = inputSize;
	// output params
	Blt = NULL;
	Width = 0;
	Height = 0;
	Status = TranslateBmpToGopBlt (
			BmpBuffer,
			FileSize,
			&Blt,
			&BltSize,
			&Height,
			&Width
			);

	if (Blt)
		FreePool(Blt);

	return Status;
}
