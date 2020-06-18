/*
 * Zephyr TEST fuzzing sample target
 *
 * Based on kAFL kafl_vuln_test module
 *
 * Copyright 2017 Sergej Schumilo
 * Copyright 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>

#include <string.h>
#include <sys/types.h>

const size_t INPUT_LENGTH = 32;

void target_init() {};

ssize_t target_entry(const char *buf, size_t len)
{
	char input[INPUT_LENGTH];

	if (len >= INPUT_LENGTH) {
		return -EFAULT;
	}
	
	memcpy(input, buf, len);

	if(input[0] == 'K')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'N')
					if(input[4] == 'E')
						if(input[5] == 'L')
							if(input[6] == 'A')
								if(input[7] == 'F')
									if(input[8] == 'L') {
										printk("BUG: KERNELAFL\n");
										k_panic(); /* boom! bug incoming... */
									}

	if(input[0] == 'S')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'G')
					if(input[4] == 'E')		
						if(input[5] == 'J') {
							printk("BUG: SERGEJ\n");
							k_oops();
						}

	/* memory corruption */
	if(input[0] == 'K'){
    	if(input[1] == 'A'){
        	if(input[2] == 'S'){
            	if(input[3] == 'A'){
                	if(input[4] == 'N') {
						printk("BUG: KASAN\n");
						k_oops();
					}
				}
        	}
        }
	}

	if (0 == strncmp(input, "RedQueen", strlen("RedQueen"))) {
		printk("BUG: RedQueen\n");
		k_oops();
	}

	return len;
}

