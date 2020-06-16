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

int main(int argc, char** argv)
{
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    //LPVOID payload_buffer = (LPVOID)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    BOOL status = -1;
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\testKafl",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        printf("[-] KAFL test: Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0);
    }

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    while(1){
            kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
            /* request new payload (*blocking*) */
            kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 

            /* kernel fuzzing */
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
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    return 0;
}

