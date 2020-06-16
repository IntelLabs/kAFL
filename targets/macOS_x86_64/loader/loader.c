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
#include <unistd.h>
#include "../../kafl_user.h"

static inline void execute_program(){
	char* newenviron[] = {NULL};
	char* newargv[] = {TARGET_FILE, NULL};
#ifndef AUTORELOAD
	pid_t cpid;
    int status;
    cpid = fork();
    while(1){
    	if (!cpid){
    		execve(TARGET_FILE, newargv, newenviron);
    	}
    	else{
    		waitpid(-1, &status, 0);
    		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    		cpid = fork();
    	}
    }
#else
	execve(TARGET_FILE, newargv, newenviron);
#endif
}

static inline void load_program(void* buf){
	int payload_file;
#ifdef DEBUG_MODE
	fflush(stdout);
#endif
	payload_file = open(TARGET_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	write(payload_file, buf, PROGRAM_SIZE);
	close(payload_file);

	execute_program();
}

#ifdef DEBUG_MODE
void readfile(void* buffer){
	FILE *fileptr;
	long filelen;

	fileptr = fopen("test", "rb");
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr); 
	rewind(fileptr);       

	fread(buffer, filelen, 1, fileptr);   
	fclose(fileptr);
}
#endif

static inline uint64_t get_kernel_symbol_addr(char* target){
	char cmd[256];
	FILE *fp = NULL;
	char addr[17];

	/* classy cmd-injection...hell yeah! */
	snprintf(cmd, 256, "nm /System/Library/Kernels/kernel | grep \"%s\"$", target);

	fp = popen(cmd, "r");
	fgets(addr, 17, fp);
  	pclose(fp);
  	return (uint64_t)strtoull(addr, NULL, 16);
}

int main(int argc, char** argv)
{
	uint64_t panic_handler = 0x0;
	uint64_t panic_handler64 = 0x0;
	void* program_buffer;

	printf("<< kAFL Usermode Loader for macOS x86-64 >>\n");

	panic_handler = get_kernel_symbol_addr("T _panic");
	panic_handler64 = get_kernel_symbol_addr("T _panic_64");

	printf("panic_handler\t%llx\n", panic_handler);
	printf("panic_handler64\t%llx\n", panic_handler64);

	/* allocate 4MB contiguous virtual memory to hold fuzzer program; data is provided by the fuzzer */
	program_buffer = mmap((void*)0xabcd0000, PROGRAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	/* ensure that the virtual memory is *really* present in physical memory... */

	memset(program_buffer, 0xff, PROGRAM_SIZE);

#ifdef DEBUG_MODE
	readfile(program_buffer);
	load_program(program_buffer);
	return 0;
#endif

	/* this hypercall will generate a VM snapshot for the fuzzer and subsequently terminate QEMU */
	kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);


	/***** Fuzzer Entrypoint *****/


	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* submit panic addresses */
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler64);

	/* submit virtual address of program buffer and wait for data (*blocking*) */
	kAFL_hypercall(HYPERCALL_KAFL_GET_PROGRAM, (uint64_t)program_buffer);
	/* execute fuzzer program */
	load_program(program_buffer);
	/* bye */ 
	return 0;
}
