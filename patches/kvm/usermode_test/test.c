/* 
 * vmx_pt userspace test program 
 *
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 * 
 * KVM Sample code for /dev/kvm API
 *
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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

#define KVM_VMX_PT_SETUP_FD					_IO(KVMIO,	0xd0)			/* apply vmx_pt fd (via vcpu fd ioctl)*/
#define KVM_VMX_PT_CONFIGURE_ADDR0			_IOW(KVMIO,	0xd1, __u64)	/* configure IP-filtering for addr0_a & addr0_b */
#define KVM_VMX_PT_CONFIGURE_ADDR1			_IOW(KVMIO,	0xd2, __u64)	/* configure IP-filtering for addr1_a & addr1_b */
#define KVM_VMX_PT_CONFIGURE_ADDR2			_IOW(KVMIO,	0xd3, __u64)	/* configure IP-filtering for addr2_a & addr2_b */
#define KVM_VMX_PT_CONFIGURE_ADDR3			_IOW(KVMIO,	0xd4, __u64)	/* configure IP-filtering for addr3_a & addr3_b */

#define KVM_VMX_PT_CONFIGURE_CR3			_IOW(KVMIO,	0xd5, __u64)	/* setup CR3 filtering value */
#define KVM_VMX_PT_ENABLE					_IO(KVMIO,	0xd6)			/* enable and lock configuration */ 
#define KVM_VMX_PT_GET_TOPA_SIZE			_IOR(KVMIO,	0xd7, __u32)	/* get defined ToPA size */
#define KVM_VMX_PT_DISABLE					_IO(KVMIO,	0xd8)			/* enable and lock configuration */ 
#define KVM_VMX_PT_CHECK_TOPA_OVERFLOW		_IO(KVMIO,	0xd9)			/* check for ToPA overflow */

#define KVM_VMX_PT_ENABLE_ADDR0				_IO(KVMIO,	0xaa)			/* enable IP-filtering for addr0 */
#define KVM_VMX_PT_ENABLE_ADDR1				_IO(KVMIO,	0xab)			/* enable IP-filtering for addr1 */
#define KVM_VMX_PT_ENABLE_ADDR2				_IO(KVMIO,	0xac)			/* enable IP-filtering for addr2 */
#define KVM_VMX_PT_ENABLE_ADDR3				_IO(KVMIO,	0xad)			/* enable IP-filtering for addr3 */

#define KVM_VMX_PT_DISABLE_ADDR0			_IO(KVMIO,	0xae)			/* disable IP-filtering for addr0 */
#define KVM_VMX_PT_DISABLE_ADDR1			_IO(KVMIO,	0xaf)			/* disable IP-filtering for addr1 */
#define KVM_VMX_PT_DISABLE_ADDR2			_IO(KVMIO,	0xe0)			/* disable IP-filtering for addr2 */
#define KVM_VMX_PT_DISABLE_ADDR3			_IO(KVMIO,	0xe1)			/* disable IP-filtering for addr3 */

#define KVM_VMX_PT_ENABLE_CR3				_IO(KVMIO,	0xe2)			/* enable CR3 filtering */
#define KVM_VMX_PT_DISABLE_CR3				_IO(KVMIO,	0xe3)			/* disable CR3 filtering */

#define KVM_VMX_PT_SUPPORTED				_IO(KVMIO,	0xe4)

#define KVM_VMX_PT_CONFIGURE_HYPERCALL_HOOK	_IOW(KVMIO,	0xe5, __u64)	/* set address for hypercall hooks */

struct vmx_pt_filter_iprs {
	__u64 a;
	__u64 b;
};

#define PAGE_SHIFT						12
#define TOPA_MAIN_ORDER					7
#define TOPA_FALLBACK_ORDER				0
#define TOPA_MAIN_SIZE					((1 << TOPA_MAIN_ORDER)*(1 << PAGE_SHIFT))
#define TOPA_FALLBACK_SIZE				((1 << TOPA_FALLBACK_ORDER)*(1 << PAGE_SHIFT))
#define TOPA_SIZE 						(TOPA_MAIN_SIZE + TOPA_FALLBACK_SIZE)

/* guest code sections */
#define ENTRY_ADDR 0x1000
#define SIZE (0x8 * 0x1000)

#define NPAGES 1

unsigned char *kadr;

void dump(int bytes){
	int i;
	printf("Trace-Data size: %d\n", bytes);
	fprintf(stdout, "\n%x\t", 0);
	/* ugly code incoming */
	for (int i= 0; i < bytes; i++){
		fprintf(stdout, "%02x", kadr[i+7]);
		fprintf(stdout, "%02x", kadr[i+6]); 
		fprintf(stdout, "%02x", kadr[i+5]);
		fprintf(stdout, "%02x", kadr[i+4]);
		fprintf(stdout, "%02x", kadr[i+3]);
		fprintf(stdout, "%02x", kadr[i+2]);
		fprintf(stdout, "%02x", kadr[i+1]);
		fprintf(stdout, "%02x", kadr[i]);
		fprintf(stdout, " ");
		i += 7;
	
		if (!((i+1)%16)){
			fprintf(stdout, "\n%x\t", i+1);
		}
	}
	fprintf(stdout, "\n");
	printf("---------------------------\n");
}

int trace(void)
{
	int i;
	int kvm, vmfd, vcpufd, vmx_pt_fd, ret;
	const uint8_t code[] = {
			0xba, 0xf8, 0x03,					/* <0x1000> mov $0x3f8, %dx.    */
			0x00, 0xd8,       					/* <0x1003> add %bl, %al 		*/
			0x04, '0',        					/* <0x1005> add $'0', %al		*/
			0xee,             					/* <0x1007> out %al, (%dx)		*/
			0xb0, '\n',       					/* <0x1008> mov $'\n', %al		*/
			0xee,             					/* <0x100a> out %al, (%dx)		*/
			0xea, 0x11, 0x10, 0x00, 0x00, 		/* <0x100b> far jmp to 0x1011	*/
			0xf4,             					/* <0x1010> hlt					*/
			0xb0, '*',        					/* <0x1011> mov $'\n', %al		*/
			0x73, 0x01,							/* <0x1013> jnc +1				*/
			0xee,             					/* <0x1015> out %al, (%dx)		*/
			0xee,             					/* <0x1016> out %al, (%dx)		*/
			0xee,             					/* <0x1017> out %al, (%dx)		*/
			0xea, 0x10, 0x10, 0x00, 0x00, 		/* <0x1018> far jmp to 0x1010	*/
	};
	
	uint8_t *mem;
	struct kvm_sregs sregs;
	size_t mmap_size;
	struct kvm_run *run;
	size_t bytes = 0;
	struct vmx_pt_filter_iprs filter_iprs;

	/* Create KVM fd */
	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1){
		err(1, "/dev/kvm");
	}


	ret = ioctl(kvm, KVM_VMX_PT_SUPPORTED, NULL);
	if (ret == -1){
		printf("ERROR: vmx_pt is not loaded!\n");
		exit(2);
	}
	if (ret == -2){
		printf("ERROR: Intel PT is not supported on this CPU!\n");
		exit(3);
	}

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
	if (ret == -1){
		err(1, "KVM_GET_API_VERSION");
	}
	if (ret != 12){
		errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);
	}

	vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
	if (vmfd == -1){
		err(1, "KVM_CREATE_VM");
	}

	/* Allocate one aligned page of guest memory to hold the code */
	mem = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!mem){
		err(1, "allocating guest memory");
	}
	memcpy(mem, code, sizeof(code));

	/* Map it to the second page frame (to avoid the real-mode IDT at 0) */
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.guest_phys_addr = ENTRY_ADDR,
		.memory_size = SIZE,
		.userspace_addr = (uint64_t)mem,
	};

	/* Setup executable memory region */
	ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1){
		err(1, "KVM_SET_USER_MEMORY_REGION");
	}

	/* Create VCPU fd */
	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if (vcpufd == -1){
		err(1, "KVM_CREATE_VCPU");
	}

	/* Map the shared kvm_run structure and following data. */
	ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1){
		err(1, "KVM_GET_VCPU_MMAP_SIZE");
	}
	mmap_size = ret;
	if (mmap_size < sizeof(*run)){
		errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
	}
	run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if (!run){
		err(1, "mmap vcpu");
	}

	/* Initialize CS to point at 0, via a read-modify-write of sregs. */
	ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1){
		err(1, "KVM_GET_SREGS");
	}
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1){
		err(1, "KVM_SET_SREGS");
	}

	/* Initialize registers: instruction pointer for our code, addends, and initial flags required by x86 architecture. */
	struct kvm_regs regs = {
		.rip = ENTRY_ADDR,
		.rax = 2,
		.rbx = 2,
		.rflags = 0x2,
	};
	ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1){
		err(1, "KVM_SET_REGS");
	}

	/* Get vmx_pt fd */
	vmx_pt_fd = ioctl(vcpufd, KVM_VMX_PT_SETUP_FD, (unsigned long)0);
	if (!(vmx_pt_fd == -1)){

		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, (unsigned long)0x0);
		if (ret == -1){
			err(1, "KVM_VMX_PT_GET_TOPA_SIZE");
		}
		printf("KVM_VMX_PT_GET_TOPA_SIZE: %d\n", ret);

		/* Set up ToPA Base + Fallback region mapping */
	   	kadr = mmap(0, ret, PROT_READ, MAP_SHARED, vmx_pt_fd, 0);
		if (kadr == MAP_FAILED) { 
			perror("mmap");
			exit(-1);
	   	}

	   	filter_iprs.a = 0x1000;
	   	filter_iprs.b = 0x100a;
		
		/* Set up ADDR0 IP filtering */
	    ret = ioctl(vmx_pt_fd, KVM_VMX_PT_CONFIGURE_ADDR0, &filter_iprs);
		if (ret == -1){
			err(1, "KVM_VMX_PT_CONFIGURE_ADDR0");
		}
		
		/* Enable ADDR0 IP filtering (trace only 0x1000 - 0x100a) */
		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_ENABLE_ADDR0, (unsigned long)0);
		if (ret == -1){
			err(1, "KVM_VMX_PT_ENABLE_ADDR0");
		}
			
		filter_iprs.a = 0x1017;
	   	filter_iprs.b = 0x200a;

		/* Set up ADDR1 IP filtering */
		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_CONFIGURE_ADDR1, &filter_iprs);
		if (ret == -1){
				err(1, "KVM_VMX_PT_CONFIGURE_ADDR1");
		}

		/* Enable ADDR1 IP filtering (also enable tracing for 0x1017 - 0x200a) */
		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_ENABLE_ADDR1, (unsigned long)0);
		if (ret == -1){
			err(1, "KVM_VMX_PT_ENABLE_ADDR1");
		}
		  
		/* Configuration is ready ... Let's enable vmx_pt tracing */
		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_ENABLE, (unsigned long)0);
		if (ret == -1){
				err(1, "KVM_VMX_PT_ENABLE");
		}
	}
	else{
	    printf("vmx_pt is not ready...\n");
	    return 1; 
	}

	/* Repeatedly run code and handle VM exits. */
	while (1) {

		/* Execute code in guest mode */
		ret = ioctl(vcpufd, KVM_RUN, NULL);
		if (ret == -1)
			err(1, "KVM_RUN");

		switch (run->exit_reason) {
			case KVM_EXIT_HLT:
				puts("KVM_EXIT_HLT");

		        /* Let's dump trace data for the last time */
				bytes = ioctl(vmx_pt_fd, KVM_VMX_PT_DISABLE, (unsigned long)0);
				if (bytes > 0){
					dump(bytes);
				}
				return 0;

			case KVM_EXIT_IO:
				if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1){
					printf("GUEST: ");
					putchar(*(((char *)run) + run->io.data_offset));
					printf("\n");
				}
				else{
					errx(1, "unhandled KVM_EXIT_IO");
				}
				break;

			case KVM_EXIT_FAIL_ENTRY:
				errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
					 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);

			case KVM_EXIT_INTERNAL_ERROR:
				errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);

			default:
				errx(1, "exit_reason = 0x%x", run->exit_reason);
		}
	
		/* If the ToPA base region is overflowed, this ioctl call will return the offset of the fallback region + ToPA base region size */
		ret = ioctl(vmx_pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);
		if (ret){
			printf("ToPA Overflow: %d", ret);
			dump(ret);
		}
	}

	return 0;
}

int main(){
	trace();
}
