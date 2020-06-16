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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>

#include "kafl_user.h"

extern uint8_t _binary_target_start;
extern uint8_t _binary_target_end;
extern uint8_t _binary_target_size;

extern uint32_t modules;
extern uint8_t* module_address_start[];
extern uint8_t* module_address_end[];
extern char* module_name[];

static void copy_binary(char* name, char* path, void* start_address, void* end_address, bool load){
	char* load_cmd; 
	int payload_file;
	char* full_path;
	hprintf("<<%s>>\n", name);
	uint64_t size = end_address-start_address;
	hprintf("[!] binary (%s) is %d bytes in size...\n", name, size);
	asprintf(&full_path, "%s/%s", path, name);
	hprintf("[!] writing to \"%s\"\n", full_path);
	payload_file = open(full_path, O_RDWR | O_CREAT | O_SYNC, 0777);
	write(payload_file, (void*)start_address, size);
	hprintf("[*] write: %s\n", strerror(errno));
	close(payload_file);
	hprintf("[*] close: %s\n\n", strerror(errno));
	if(load){
		asprintf(&load_cmd, "insmod %s/%s", path, name);
		hprintf("[*] exec: %s => %d\n", load_cmd, system(load_cmd));
	}
}

static inline void load_programm(void* filepath){
	int payload_file;
	char* newenviron[] = {NULL};
	char* newargv[] = {filepath, NULL};

	payload_file = open(filepath, O_RDONLY);
	fexecve(payload_file, newargv, newenviron);
	hprintf("%s failed\n", __func__);
}

int main(int argc, char** argv){
	char va_space_result;
	int pid, fd;

	/* check if uid == 0 */
	if(getuid()){
	hprintf("Oops...no root creds?\n");
	return 1;
	}
	hprintf("[*] getuid() == 0\n");

	copy_binary("fuzzer", "/tmp", (void*)&_binary_target_start, (void*)&_binary_target_end, false);

	hprintf("Modules: %d\n", modules);
	for(uint32_t i = 0; i < modules; i++){
		hprintf("%s\n", module_name[i]);
		copy_binary(module_name[i], "/tmp", (void*)module_address_start[i], (void*)module_address_end[i], true);
	}

	hprintf("DONE\n");

	load_programm("/tmp/fuzzer");
	hprintf("ERROR\n");

	while(1){};
	return 0;
}
