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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include "kafl_user.h"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

#define LINE_SIZE						(1024)
#define MOD_NAME_SIZE                   (256)

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

int main(int argc, char** argv){
  char line[LINE_SIZE];
  char module_name[MOD_NAME_SIZE];
  uint64_t start;
  uint64_t offset;
  char * pch;
  int counter;
  int pos = 0;
  int tokens = 1;
  int errno = 0;

  void* info_buffer = mmap((void*)NULL, INFO_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(info_buffer, 0xff, INFO_SIZE);


  pos += sprintf(info_buffer + pos, "kAFL Linux x86-64 Kernel Addresses (%d Modules)\n\n", counter);
  pos += sprintf(info_buffer + pos, "START-ADDRESS      END-ADDRESS\t\tDRIVER\n");

  FILE* f = fopen("/proc/modules", "r");

  while (fgets(line, LINE_SIZE, f)) {
	  tokens = sscanf(line, "%s %Lu %*u %*s %*s %Lx %*s", module_name, &offset, &start);
	  if (tokens==3)
          pos += sprintf(info_buffer + pos, "0x%016lx-0x%016lx\t%s\n", start, start+offset, module_name);
	  else
		  //printf("got %d tokens, error: %d\n", n, errno);
		  continue;
  }

  fclose(f);

  pos += sprintf(info_buffer + pos, "0x%016lx-0x%016lx\t%s\n\n",
		  get_address("T startup_64\n"),
		  get_address("r __param_str_debug\n"), "Kernel Core");

  //printf(">>>\n%s\n<<<\n", info_buffer);
  kAFL_hypercall(HYPERCALL_KAFL_INFO, (uint64_t)info_buffer);
  return 0;
}
