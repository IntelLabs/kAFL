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


	if(len >= 256){
		return 0;
	}

	char* array = malloc(128);


	if(input[0] == 'K')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'N')
					if(input[4] == 'E')
						if(input[5] == 'L')
							if(input[6] == 'A')
								if(input[7] == 'F')
									if(input[8] == 'L')
										assert(false);

	if(input[0] == 'S')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'G')
					if(input[4] == 'E')		
						if(input[5] == 'J')
							assert(false);

	if(input[0] == 'K'){
    	if(input[1] == 'A'){
        	if(input[2] == 'S'){
            	if(input[3] == 'A'){
                	if(input[4] == 'N'){
						free(array);
						array[0] = 234;
					}
				}
        	}
        }
	}
	free(array);
	return 0;
}	
