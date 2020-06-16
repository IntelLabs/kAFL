/*

Copyright (C) 2017 Robert Gawlik

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <windows.h>
#include <stdio.h>
#include "kafl_user.h"

#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

int main(int argc, char** argv){
    hprintf("[+] Starting... %s\n", argv[0]);

    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)\n", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = INVALID_HANDLE_VALUE;
    hprintf("[+] Attempting to open vulnerable device file (%s)\n", "\\\\.\\testKafl");
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\testKafl",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("[-] Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0);
    }

    /* submit the guest virtual address of the payload buffer */
    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */ 
    hprintf("[+] Submitting current CR3 value to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    while(1){
            kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
            /* request new payload (*blocking*) */
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 

            /* kernel fuzzing */
            hprintf("[+] Injecting data...\n");
            DeviceIoControl(kafl_vuln_handle,
                IOCTL_KAFL_INPUT,
                (LPVOID)(payload_buffer->data),
                (DWORD)payload_buffer->size,
                NULL,
                0,
                NULL,
                NULL
            );

            /* inform fuzzer about finished fuzzing iteration */
            hprintf("[+] Injection finished...\n");
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    return 0;
}

