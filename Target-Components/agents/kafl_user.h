/* 
# This file is part of Redqueen.
#
# Copyright 
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef KAFL_USER_H
#define KAFL_USER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef __MINGW64__
#include <sys/mman.h>
#endif

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else 
#include <stdint.h>
#endif

#define HYPERCALL_KAFL_RAX_ID				0x01f
#define HYPERCALL_KAFL_ACQUIRE				0
#define HYPERCALL_KAFL_GET_PAYLOAD			1
#define HYPERCALL_KAFL_GET_PROGRAM			2
#define HYPERCALL_KAFL_GET_ARGV				3
#define HYPERCALL_KAFL_RELEASE				4
#define HYPERCALL_KAFL_SUBMIT_CR3			5
#define HYPERCALL_KAFL_SUBMIT_PANIC			6
#define HYPERCALL_KAFL_SUBMIT_KASAN			7
#define HYPERCALL_KAFL_PANIC				8
#define HYPERCALL_KAFL_KASAN				9
#define HYPERCALL_KAFL_LOCK					10
#define HYPERCALL_KAFL_INFO					11
#define HYPERCALL_KAFL_NEXT_PAYLOAD			12
#define HYPERCALL_KAFL_PRINTF				13
#define HYPERCALL_KAFL_PRINTK_ADDR			14
#define HYPERCALL_KAFL_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE	16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE		17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT			20
#define HYPERCALL_KAFL_TIMEOUT				21


#define PAYLOAD_SIZE						(128 << 10)				/* up to 128KB payloads */
#define PROGRAM_SIZE						(128 << 20)				/* kAFL supports 128MB programm data */
#define INFO_SIZE        					(128 << 10)				/* 128KB info string */
#define TARGET_FILE							"/tmp/fuzzing_engine"	/* default target for the userspace component */
#define TARGET_FILE_WIN						"fuzzing_engine.exe"	

#define HPRINTF_MAX_SIZE					0x1000					/* up to 4KB hprintf strings */


typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-sizeof(int32_t)-sizeof(uint8_t)];
	uint8_t redqueen_mode;
} kAFL_payload;

typedef struct{
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges; 

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

#if defined(__i386__)
static void kAFL_hypercall(uint32_t rbx, uint32_t rcx){
	printf("%s %x %x \n", __func__, rbx, rcx);
# ifndef __NOKAFL
	uint32_t rax = HYPERCALL_KAFL_RAX_ID;
    asm volatile("movl %0, %%ecx;"
				 "movl %1, %%ebx;"  
				 "movl %2, %%eax;"
				 "vmcall" 
				: 
				: "r" (rcx), "r" (rbx), "r" (rax) 
				: "eax", "ecx", "ebx"
				);


# endif
} 
#elif defined(__x86_64__)

static void kAFL_hypercall(uint64_t rbx, uint64_t rcx){
# ifndef __NOKAFL
	uint64_t rax = HYPERCALL_KAFL_RAX_ID;
    asm volatile("movq %0, %%rcx;"
				 "movq %1, %%rbx;"  
				 "movq %2, %%rax;"
				 "vmcall" 
				: 
				: "r" (rcx), "r" (rbx), "r" (rax) 
				: "rax", "rcx", "rbx"
				);
# endif
}
#endif

uint8_t* hprintf_buffer = NULL; 

static inline uint8_t alloc_hprintf_buffer(void){
	if(!hprintf_buffer){
#ifdef __MINGW64__
		hprintf_buffer = (uint8_t*)VirtualAlloc(0, HPRINTF_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else 
		hprintf_buffer = mmap((void*)NULL, HPRINTF_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
		if(!hprintf_buffer){
			return 0;
		}
	}
	return 1; 
}

#ifdef __NOKAFL
int (*hprintf)(const char * format, ...) = printf;
#else
static void hprintf(const char * format, ...)  __attribute__ ((unused));

static void hprintf(const char * format, ...){
	va_list args;
	va_start(args, format);
	if(alloc_hprintf_buffer()){
		vsnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
# if defined(__i386__)
		printf("%s", hprintf_buffer);
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uint32_t)hprintf_buffer);
# elif defined(__x86_64__)
		printf("%s", hprintf_buffer);
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uint64_t)hprintf_buffer);
# endif
	}
	//vprintf(format, args);
	va_end(args);
}
#endif

#endif
