/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char** argv){

#ifdef STDIN_INPUT
	char input[256];
	memset(input, 0x00, 256);
	size_t len = read(STDIN_FILENO, input, 256);
#elif FILE_INPUT
	if(argc != 2){
		return 0; 
	}

	int fd = open(argv[1], O_RDONLY);

	char input[256];
	memset(input, 0x00, 256);
	size_t len = read(fd, input, 256);
#endif

	char* array = malloc(128);

	if(len >= 256){
		return 0;
	}

	char* cmpval = "LOOPCHECK";
	if(len >= strlen(cmpval)){
		int counter = 0;
			for(int i = 0; i<strlen(cmpval); i++){
				if(input[i] == cmpval[i]){
					counter +=1;
				}
			}
		if(counter == strlen(cmpval)){
			free(array);
			free(array);
		}
	}

	return 0;
}	
