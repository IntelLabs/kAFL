# 1 - Target analysis

## Objectives

The aim is to fuzz the [DVKM (Damned Vulnerable Kernel Module)](https://github.com/hardik05/Damn_Vulnerable_Kernel_Module), an example kernel module developed by [Hardik Shah](https://github.com/hardik05).

Designed for fuzzing training, DVKM contains deliberately vulnerable code that exposes to a range of security vulnerabilities, including:
- integer overflow / underflow
- use-after-free / double free
- stack / heap overflow
- and more...

It was originally built to be tested under [syzkaller](https://github.com/google/syzkaller), but in this tutorial, we will show you how to adapt it for kAFL fuzzing.

## Source code overview

DVKM is self-contained in a single `dvkm.c` C module file.

The `module_init()` function delegates its responsibilities to `dvkm_init()`, which in turn creates a `/proc/dvkm` entry.

The kernel module defines 12 IOCTLs, as outlines below:

```{code-block} c
---
caption: DVKM IOCTLs
---
// Macro to geneate unique IOCTL commands for DVKM driver
#define IOCTL(NUM) _IOWR(DVKM_IOCTL_MAGIC, NUM, struct dvkm_obj)
// Commands
#define DVKM_IOCTL_INTEGER_OVERFLOW IOCTL(0x0)
#define DVKM_IOCTL_INTEGER_UNDERFLOW IOCTL(0x1)
#define DVKM_IOCTL_STACK_BUFFER_OVERFLOW IOCTL(0x2)
#define DVKM_IOCTL_HEAP_BUFFER_OVERFLOW IOCTL(0x3)
#define DVKM_IOCTL_DIVIDE_BY_ZERO IOCTL(0x4)
#define DVKM_IOCTL_STACK_OOBR IOCTL(0x5)
#define DVKM_IOCTL_STACK_OOBW IOCTL(0x6)
#define DVKM_IOCTL_HEAP_OOBR IOCTL(0x7)
#define DVKM_IOCTL_HEAP_OOBW IOCTL(0x8)
#define DVKM_IOCTL_MEMORY_LEAK IOCTL(0x9)
#define DVKM_IOCTL_USE_AFTER_FREE IOCTL(0xA)
#define DVKM_IOCTL_USE_DOUBLE_FREE IOCTL(0xB)
#define DVKM_IOCTL_NULL_POINTER_DEREFRENCE IOCTL(0xC)
```

An associated `struct dvkm_obj` is defined as:

```{code-block} c
---
caption: struct dvkm_obj
---
struct dvkm_obj {
    int width;
    int height;
    int datasize;
    char *data;
} k_dvkm_obj;
```

A supplementary `test_dvkm.c` file is provided to test the module's IOCTLs.

Diagram representing the code flow between `test_dvkm.c` and the `dvkm.c` module:
```{mermaid}
graph
    subgraph test_dvkm.c - Userspace
        direction TB
        open["open('/proc/dvkm')"] --> ioctl["ioctl(fd, IOCTL(0x2), dvkm_obj)"]
    end
    subgraph dvkm.c - Kernel Module
        direction TB
        ioctl --> dispatcher["dvkm_ioctl()"]
        dispatcher -->|"DVKM_IOCTL_INTEGER_OVERFLOW"| int_over["Integer_Overflow_IOCTL_Handler()"]
        dispatcher -->|"DVKM_IOCTL_INTEGER_UNDERFLOW"| int_under["Integer_Underflow_IOCTL_Handler()"]
        dispatcher -. "etc..." .-> etc_handler["other_handler()"]
    end
```

## Integer Overflow

Each IOCTL handler addresses a specific type of code security flaw.

For example, let's dissect the Integer Overflow IOCTL handler to better understand how it can be triggered.

```{code-block} C
---
caption: Integer overflow IOCTL handler
linenos: yes
---
int Integer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	int width, height, datasize, size;
	char *kernel_buffer, *kernel_data_buffer;	
	size = 0xFFFFFFFF;

	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}	
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}
	width = k_dvkm_obj.width;
	height = k_dvkm_obj.height;	
	datasize = k_dvkm_obj.datasize;

	if (width == 0)
		return 0;
	if (height == 0)
		return 0;

	INFO("[+] width: %d\n", width);
	INFO("[+] Height: %d\n", height);
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	INFO("[+] data: %s\n", kernel_data_buffer);	

	size = size + width + height; //integer overflow here

	INFO("[+] calculated size: %d\n", size);

	kernel_buffer = (char *)kmalloc(size, GFP_KERNEL); //we allocate memory here.
	memcpy(kernel_buffer,kernel_data_buffer,k_dvkm_obj.datasize);
	kfree(kernel_buffer);
	kfree(kernel_data_buffer);
	return 0;
}
```

In summary:

1. Lines `7-10`: The handler copies the struct dvkm_obj *io IOCTL argument into the global variable k_dvkm_obj.
2. Lines `29-32`: It checks that both width and height are non-zero.
3. Line `39`: Performs an integer overflow operation.
4. Line `43`: Allocates a buffer based on the incorrect size resulting from the overflow.

Given these nuances, kAFL is likely to trigger and reproduce an integer overflow in the kernel.

Here's an example of how one might initialize the dvkm_obj struct to exploit this vulnerability:

```{code-block} c
struct dvkm_obj obj = {
    .width = 2399610,
    .height = -305747497,
    .datasize = 2399610
    .data = ...
};
```

With this comprehensive understanding of our target, let's move on to the next section to discuss setting up our fuzzing workflow with kAFL.
