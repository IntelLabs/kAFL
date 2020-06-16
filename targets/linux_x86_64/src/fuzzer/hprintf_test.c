/*

Copyright (C) 2017 Sergej Schumilo

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

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "kafl_user.h"

int main(int argc, char** argv)
{
	int kafl_vuln_fd;
	hprintf("Starting... %s\n", argv[0]);
	hprintf("Allocating buffer for kAFL_payload struct\n");
	kAFL_payload* payload_buffer = mmap((void*)NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	hprintf("Memset kAFL_payload at address %lx (size %d)\n", (uint64_t) payload_buffer, PAYLOAD_SIZE);
	memset(payload_buffer, 0xff, PAYLOAD_SIZE);
	hprintf("Attempt to open vulnerable device file (%s)\n", "/proc/kafl_vuln");
	kafl_vuln_fd = open("/proc/kafl_vuln", O_WRONLY | O_SYNC, 0);
	hprintf("Submitting buffer address to hypervisor...\n");
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload_buffer);
	hprintf("Submitting current CR3 value to hypervisor...\n");
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	hprintf("Starting kAFL loop...\n");
	while(1){
			kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
			kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
			hprintf("Injecting data...\n");
			write(kafl_vuln_fd, payload_buffer->data, payload_buffer->size);
			hprintf("Injection finished...\n");
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
	return 0;
}
