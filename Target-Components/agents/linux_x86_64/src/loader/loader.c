/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

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

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "kafl_user.h"

static inline uint64_t get_address(char* identifier)
{
    FILE * fp;
    char * line = NULL;
    ssize_t read;
    ssize_t len;
    char *tmp;
    uint64_t address = 0x0;
    uint8_t identifier_len = strlen(identifier);

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL){
        return address;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if(strlen(line) > identifier_len && !strcmp(line + strlen(line) - identifier_len, identifier)){
                address = strtoull(strtok(line, " "), NULL, 16);
                break;
        }
    }

    fclose(fp);
    if (line){
        free(line);
    }
    return address;
}


static inline void load_programm(void* buf){
	int payload_file;
	char* newenviron[] = {NULL};
	char* newargv[] = {TARGET_FILE, NULL};

	payload_file = open(TARGET_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	write(payload_file, buf, PROGRAM_SIZE);
	close(payload_file);
	payload_file = open(TARGET_FILE, O_RDONLY);
	fexecve(payload_file, newargv, newenviron);
}

int main(int argc, char** argv)
{
	uint64_t panic_handler = 0x0;
	uint64_t kasan_handler = 0x0;
	void* program_buffer;

	if(geteuid()){
		printf("<< kAFL Usermode Load for Linux x86-64 >>\n");
        printf("Loader requires root privileges...\n");
        return 1;
    }

	panic_handler = get_address("T panic\n");
	printf("Kernel Panic Handler Address:\t%lx\n", panic_handler);

	kasan_handler = get_address("t kasan_report_error\n");
	if (kasan_handler){
		printf("Kernel KASAN Handler Address:\t%lx\n", kasan_handler);
	}

	/* allocate 4MB contiguous virtual memory to hold fuzzer program; data is provided by the fuzzer */
	program_buffer = mmap((void*)0xabcd0000, PROGRAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	/* ensure that the virtual memory is *really* present in physical memory... */
	memset(program_buffer, 0xff, PROGRAM_SIZE);

	/* this hypercall will generate a VM snapshot for the fuzzer and subsequently terminate QEMU */
	kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);


	/***** Fuzzer Entrypoint *****/


	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	/* submit panic address */
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
	/* submit KASan address */
	if (kasan_handler){
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, kasan_handler);
	}
	/* submit virtual address of program buffer and wait for data (*blocking*) */
	kAFL_hypercall(HYPERCALL_KAFL_GET_PROGRAM, (uint64_t)program_buffer);
	/* execute fuzzer program */
	load_programm(program_buffer);
	/* bye */ 
	return 0;
}