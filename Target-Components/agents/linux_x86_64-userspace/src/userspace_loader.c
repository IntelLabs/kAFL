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

#include "../../kafl_user.h"

extern uint8_t extra_args;
extern char* args[];

extern uint8_t _binary_ld_preload_target_start;
extern uint8_t _binary_ld_preload_target_end;
extern uint8_t _binary_ld_preload_target_size;

extern uint8_t _binary_target_start;
extern uint8_t _binary_target_end;
extern uint8_t _binary_target_size;

extern uint32_t libraries;
extern uint8_t* library_address_start[];
extern uint8_t* library_address_end[];
extern char* library_name[];

extern uint8_t asan_enabled;
extern char* libasan_name;

#define TARGET_US_LD_FILE  "/tmp/kafl_user_loader.so"
#define TARGET_US_FILE "/tmp/target_executable"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

static inline void panic(void){
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
	while(1){}; /* halt */
}

static inline void load_programm(void){

  char* newenviron[5];
  if (asan_enabled) {
    newenviron[0] = "LD_LIBRARY_PATH=/tmp/";
    newenviron[1] = "LD_BIND_NOW=1";
    if (strlen(libasan_name) != 0){
    	asprintf(&(newenviron[2]), "LD_PRELOAD=/tmp/%s:/tmp/kafl_user_loader.so", libasan_name);
    	hprintf("newenviron[2]): %s\n", newenviron[2]);
    }
    else {
    	//newenviron[2] = "LD_PRELOAD=/tmp/libasan.so.2:/tmp/kafl_user_loader.so";	/* fix me */
    	hprintf("(strlen(libasan_name) == 0) <= FIX ME\n");
    	panic();
    }
    newenviron[3] = "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101"; /* forget about those memleaks :P ... */
  } else {
    newenviron[0] = "LD_LIBRARY_PATH=/tmp/";
    newenviron[1] = "LD_BIND_NOW=1";
    newenviron[2] = "LD_PRELOAD=/tmp/kafl_user_loader.so";
    newenviron[3] = "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101"; /* forget about those memleaks :P ... */

  }
  newenviron[4] = NULL;

  hprintf("ENV: %s\n", newenviron[0]);

  int payload_file = open("/tmp/target_executable", O_RDONLY);
  fexecve(payload_file, args, newenviron);
}

void child(void){
  load_programm();
  hprintf("Fail: %s\n", strerror(errno));
}

static void copy_binary(char* name, char* path, void* start_address, void* end_address){
  int payload_file;
  char* full_path;
  hprintf("<<%s>>\n", name);
  uint64_t size = end_address-start_address;
  hprintf("[!] binary (%s) is %d bytes in size...\n", name, size);
  asprintf(&full_path, "%s/%s", path, name);
  hprintf("[!] writing to \"%s\"\n", full_path);
  payload_file = open(full_path, O_RDWR | O_CREAT | O_SYNC, 0777);
  write(payload_file, (void*)start_address, size);
  //hprintf("[*] write: %s\n", strerror(errno));
  close(payload_file);
 // hprintf("[*] close: %s\n\n", strerror(errno));
}

void parent(int pid){
  int status=0;
  int waitoptions = 0;
  int res = 0;
  waitpid(pid, &status, waitoptions);

  printf("OOPS?!\n");

  /* something went wrong ... alert the hypervisor / fuzzer */
  panic();
}

int main(int argc, char** argv){
  char va_space_result;
  int pid, fd;

  system("rm /loader");
  system("rm /tmp/target");

  /* check if uid == 0 */
  if(getuid()){
    hprintf("Oops...no root creds?\n");
    return 1;
  }
  hprintf("[*] getuid() == 0\n");

    /* disable ASLR */
  hprintf("[!] disabling ASLR...\n");
  fd = open("/proc/sys/kernel/randomize_va_space", O_WRONLY);
  write(fd, "0", 1);
  close(fd);

  fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
  read(fd, &va_space_result, 1);
  close(fd);
  hprintf("[*] /proc/sys/kernel/randomize_va_space: %c\n\n", va_space_result);

  copy_binary("kafl_user_loader.so", "/tmp", (void*)&_binary_ld_preload_target_start, (void*)&_binary_ld_preload_target_end);
  copy_binary("target_executable", "/tmp", (void*)&_binary_target_start, (void*)&_binary_target_end);

  hprintf("Libraries: %d\n", libraries);
  for(uint32_t i = 0; i < libraries; i++){
  	hprintf("%s\n", library_name[i]);
  	copy_binary(library_name[i], "/tmp", (void*)library_address_start[i], (void*)library_address_end[i]);
  }

  printf("Done!\n");

  pid = fork();

  if(!pid){
    child();
  }
  else if(pid > 0){
    parent(pid);
  }
  else {
    hprintf("Oops...fork failed?!\n");
    return 1;
  }

  return 0;
}
