/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>


void test_panic(char* descr){
  char* str = NULL;
  printf("Panic at: %s", descr);
  assert(0);
}

void* test_malloc(size_t size) {
  return malloc(size);
}


void test_free(void* data){
  free(data);
}

#include "../tests.h"

int main(int argc, char *argv[])
{
  char buffer[256];
  int len = read(STDIN_FILENO, buffer, 256);
  if( len != -1){
    test(buffer,len);
  } else {
    printf("failed to read input\n");
  }

	return 0;
}
