/* 
 * KVM-PT userspace support test program
 * (c) Sergej Schumilo, 2016 <sergej@schumilo.de> 
 *
 * SPDX-License-Info: MIT
 *
 * Customized from: https://github.com/nyx-fuzz/KVM-Nyx/blob/kvm-nyx-5.10.73/usermode_test/support_test.c
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

#define KVM_CAP_NYX_PT 512
#define KVM_CAP_NYX_FDL 513

int main(){
	int kvm, ret;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1){
		printf("ERROR: KVM is not loaded!\n");
		exit(1);
	} 

	ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NYX_PT);
	if (ret != 1){
		printf("ERROR: KVM does not support NYX_PT (%d)!\n", ret);
		exit(2);
	}

	ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NYX_FDL);
	if (ret != 1){
		printf("ERROR: KVM does not support NYX_PT (%d)!\n", ret);
		exit(2);
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
