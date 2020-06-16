/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "../../kafl_user.h"

int __libc_start_main(int (*main) (int,char **,char **),
		      int argc,char **ubp_av,
		      void (*init) (void),
		      void (*fini)(void),
		      void (*rtld_fini)(void),
		      void (*stack_end)) {

    hprintf("LD_PRELOAD hprintf :)\n");

    char filename[256];
    void* info_buffer = mmap((void*)NULL, INFO_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(info_buffer, 0xff, INFO_SIZE);

    hprintf("LD_PRELOAD hprintf :)\n");    
  	hprintf("Own pid is %d\n", getpid());

  	snprintf(filename, 256, "/proc/%d/maps", getpid());
  	hprintf("proc filename: %s\n", filename);

  	FILE* f = fopen(filename, "r");
  	uint16_t len = fread(info_buffer, 1, INFO_SIZE, f);
  	fclose(f);

  	((char*)info_buffer)[len] = '\0';

 	  hprintf("Transfer data to hypervisor\n");

    kAFL_hypercall(HYPERCALL_KAFL_INFO, (uintptr_t)info_buffer);

    return 0;
}
