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
