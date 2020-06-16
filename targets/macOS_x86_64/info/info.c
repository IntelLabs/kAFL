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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include "../../kafl_user.h"

#define TMP_SIZE                        (64<<10)
#define MOD_NAME_SIZE                   (256)

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define DELIMITER "\n------------------------------------------------------------------"

void get_system_infos(char* buffer, uint32_t* pos, uint32_t max){
  char line1[0x1000];
  char line2[0x1000];
  char line3[0x1000];
  FILE *fp = NULL;
  size_t size = sizeof(line1);

  fp = popen("sw_vers -productVersion", "r");
  fgets(line3, 16, fp);
  pclose(fp);

  sysctlbyname("kern.osrelease", line1, &size, NULL, 0);
  sysctlbyname("kern.osversion", line2, &size, NULL, 0);
  (*pos) += sprintf(buffer + (*pos), "XNU System Infos:%s\nproductVersion\t\t%ssysctl kern.osrelease\t%s\nsysctl kern.osversion\t%s\n\n", DELIMITER, line3, line1, line2);
}

void get_xnu_core_addresses(char* buffer, uint32_t* pos, uint32_t max){
  FILE *fp = NULL;
  char addr1[17];
  char addr2[17];

  fp = popen("nm /System/Library/Kernels/kernel  | head -n1", "r");
  fgets(addr1, 17, fp);
  pclose(fp);

  fp = popen("nm /System/Library/Kernels/kernel  | tail -n1", "r");
  fgets(addr2, 17, fp);
  pclose(fp);

  (*pos) += sprintf(buffer + (*pos), "XNU Core Address Range:%s\n0x%s\t0x%s\n\n", DELIMITER, addr1, addr2);
}

void get_xnu_kext_addresses(char* buffer, uint32_t* pos, uint32_t max){
  FILE *fp = NULL;
  char line[0x1000];
  char * pch;
  uint8_t counter; 

  uint64_t start;
  uint64_t offset;

  (*pos) += sprintf(buffer + (*pos), "XNU Kext Address Ranges:%s\n", DELIMITER);

  fp = popen("/usr/sbin/kextstat", "r");

  /* skip first line */
  fgets(line, sizeof(line), fp);
  (*pos) += sprintf(buffer + (*pos), "%s", line);

  while (fgets(line, sizeof(line), fp) != NULL) {
    pch = strtok(line, " \n");
    counter = 0;
    while (pch != NULL){
      switch(counter++){
        case 2:
          start = strtoull(pch, NULL, 16);
          break;
        case 3:
          offset = strtoull(pch, NULL, 16);
          break;
        case 5:
          (*pos) += sprintf(buffer + (*pos), "0x%016llx\t0x%016llx\t%s\n", start, start+offset, pch);
          break;
      }
      pch = strtok (NULL, " \n");
    }
  }
  pclose(fp);
}

void check_sip(char* buffer, uint32_t* pos, uint32_t max){
  FILE *fp = NULL;
  char line[0x1000];

  (*pos) += sprintf(buffer + (*pos), "\nSystem Status:%s\n", DELIMITER);

  fp = popen("csrutil status", "r");

  while (fgets(line, sizeof(line), fp) != NULL) {    
    if (strstr(line, "enabled")){
      (*pos) += sprintf(buffer + (*pos), "System Integrity Protection:\t%sENABLED%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
    }
    
    else{
      if (strstr(line, "disabled")){
              (*pos) += sprintf(buffer + (*pos), "System Integrity Protection:\t%sDISABLED%s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET);
      }
      else{
        (*pos) += sprintf(buffer + (*pos), "System Integrity Protection:\t%sUNKNOWN%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
      }
    }
  }
  pclose(fp);
}

void check_cr3s(char* buffer, uint32_t* pos, uint32_t max){
  FILE *fp = NULL;
  char line[0x1000];
  bool boot_args_set = false;

  fp = popen("nvram -p | grep \"boot-args\"", "r");

  while (fgets(line, sizeof(line), fp) != NULL) {    
    if (strstr(line, "-no_shared_cr3")){
      (*pos) += sprintf(buffer + (*pos), "Non-Shared CR3 (boot-args):\t%sENABLED%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
    }
    else{
      (*pos) += sprintf(buffer + (*pos), "Non-Shared CR3 (boot-args):\t%sDISABLED%s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET);  
    }
    boot_args_set = true;
  }
  if(!boot_args_set){
    (*pos) += sprintf(buffer + (*pos), "Non-Shared CR3 (boot-args):\t%sDISABLED%s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET);    
  }
  pclose(fp);
}

void check_kaslr(char* buffer, uint32_t* pos, uint32_t max){
  FILE *fp = NULL;
  char line[0x1000];
  bool boot_args_set = false;

  fp = popen("nvram -p | grep \"boot-args\"", "r");

  while (fgets(line, sizeof(line), fp) != NULL) {    
    if (strstr(line, "slide=0")){
      (*pos) += sprintf(buffer + (*pos), "XNU KALSR (boot-args):\t\t%sDISABLED%s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET);
    }
    else{
      (*pos) += sprintf(buffer + (*pos), "XNU KALSR (slide=0):\t\t%sENABLED%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
    }
    boot_args_set = true;
  }
  if(!boot_args_set){
    (*pos) += sprintf(buffer + (*pos), "XNU KALSR (slide=0):\t\t%sENABLED%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
  }
  pclose(fp);
}

void check_root(char* buffer, uint32_t* pos, uint32_t max){
  if(!getuid()){
    (*pos) += sprintf(buffer + (*pos), "Root UID:\t\t\t%sTRUE%s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET);
  }
  else{
    (*pos) += sprintf(buffer + (*pos), "Root UID:\t\t\t%sFALSE%s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
  }
}

int main(int argc, char** argv){
  uint32_t pos = 0;
  void* info_buffer = mmap((void*)NULL, INFO_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(info_buffer, 0xff, INFO_SIZE);

  get_system_infos(info_buffer, &pos, INFO_SIZE);
  get_xnu_core_addresses(info_buffer, &pos, INFO_SIZE);
  get_xnu_kext_addresses(info_buffer, &pos, INFO_SIZE);
  check_sip(info_buffer, &pos, INFO_SIZE);
  check_cr3s(info_buffer, &pos, INFO_SIZE);
  check_kaslr(info_buffer, &pos, INFO_SIZE);
  check_root(info_buffer, &pos, INFO_SIZE);

  kAFL_hypercall(HYPERCALL_KAFL_INFO, (uint64_t)info_buffer);
  return 0;
}
