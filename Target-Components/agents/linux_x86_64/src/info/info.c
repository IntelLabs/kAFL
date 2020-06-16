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

#define TMP_SIZE                        (64<<10)
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
  char key[] = "(OE)";
  char key2[] = "(O)";
  char data[TMP_SIZE];
  char module_name[MOD_NAME_SIZE];
  uint64_t start;
  uint64_t offset;
  char * pch;
  int counter;
  int pos = 0;

	void* info_buffer = mmap((void*)NULL, INFO_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(info_buffer, 0xff, INFO_SIZE);

  FILE* f = fopen("/proc/modules", "r");
  fread(data, 1, TMP_SIZE, f);
  fclose(f);

  counter = 0;
  int i;
  for(i = 0; i < strlen(data); i++){
    if (data[i] == '\n'){
      counter++;
    }
  }

  pos += sprintf(info_buffer + pos, "kAFL Linux x86-64 Kernel Addresses (%d Modules)\n\n", counter);
  printf("kAFL Linux x86-64 Kernel Addresses (%d Modules)\n\n", counter);
  pos += sprintf(info_buffer + pos, "START-ADDRESS      END-ADDRESS\t\tDRIVER\n");
  printf("START-ADDRESS      END-ADDRESS\tDRIVER\n");
  
  pch = strtok(data, " \n");
  counter = 0;
  while (pch != NULL)
  {
    if(strcmp(key, pch) && strcmp(key2, pch)){
      switch((counter++) % 6){
        case 0:
          strncpy(module_name, pch, MOD_NAME_SIZE);
          break;
        case 1:
          offset = strtoull(pch, NULL, 10);
          break;
        case 5:
          start = strtoull(pch, NULL, 16);
          pos += sprintf(info_buffer + pos, "0x%016lx-0x%016lx\t%s\n", start, start+offset, module_name);
          printf("0x%016lx\t0x%016lx\t%s\n", start, start+offset, module_name);
          break;
      }
    }
    pch = strtok (NULL, " \n");
  }

  pos += sprintf(info_buffer + pos, "0x%016lx-0x%016lx\t%s\n\n", get_address("T startup_64\n"), get_address("r __param_str_debug\n"), "Kernel Core");

  kAFL_hypercall(HYPERCALL_KAFL_INFO, (uint64_t)info_buffer);
  return 0;
}
