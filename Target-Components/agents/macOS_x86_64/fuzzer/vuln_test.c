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
#include "../../kafl_user.h"

int main(int argc, char** argv)
{
	int kafl_vuln_fd;
	kAFL_payload* payload_buffer = mmap((void*)0xabcd0000, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(payload_buffer, 0xff, PAYLOAD_SIZE);
	kafl_vuln_fd = open("/dev/vuln", O_WRONLY, 0);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	while(1){
			kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
			kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
			write(kafl_vuln_fd, payload_buffer->data, payload_buffer->size);
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
	return 0;
}