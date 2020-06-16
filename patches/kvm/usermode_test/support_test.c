/* 
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define KVM_VMX_PT_SUPPORTED	_IO(KVMIO,	0xe4)

int main(){
	int kvm, ret;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1){
		printf("ERROR: KVM is not loaded!\n");
		exit(1);
	} 

	ret = ioctl(kvm, KVM_VMX_PT_SUPPORTED, NULL);
	if (ret == -1){
		printf("ERROR: KVM-PT is not loaded!\n");
		exit(2);
	}
	if (ret == -2){
		printf("ERROR: Intel PT is not supported on this CPU!\n");
		exit(3);
	}
	printf("KVM-PT is ready!\n");
	return 0;
}
