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
