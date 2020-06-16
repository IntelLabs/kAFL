/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <miscfs/devfs/devfs.h>
#include <i386/proc_reg.h>

#include <sys/uio.h>

#define BUFFERSIZE 255
#define PANIC *((char*)(0x0)) = '0'

static const char *device_name = "vuln";
static int device_major;
static void *device_handle;

kern_return_t vuln_start(kmod_info_t *ki, void *d);
kern_return_t vuln_stop(kmod_info_t *ki, void *d);
static int vuln_open(dev_t dev, int flags, int type, struct proc *p);
static int vuln_close(dev_t dev, int flags, int type, struct proc *p);
static int vuln_write(dev_t dev, uio_t uio, int flags);

static int vuln_open(dev_t dev, int flags, int type, struct proc *p)
{
	return KERN_SUCCESS;
}

static int vuln_close(dev_t dev, int flags, int type, struct proc *p)
{
	return KERN_SUCCESS;
}

static int vuln_write(dev_t dev, uio_t uio, int flags){

	char buffer[BUFFERSIZE+1];
	user_addr_t ioaddr = uio_curriovbase(uio);
        user_size_t iosize = uio_curriovlen(uio);
	
	//printf("KERNEL DRIVER!!!!!\n");

	if(iosize >= BUFFERSIZE){
		//printf("truncating input...\n");
		iosize = BUFFERSIZE;
	}

	if(copyin(ioaddr, buffer, iosize)){
		//printf("copyin failed!\n");
		return -1;
	}

	if(buffer[0] == 'K'){
	if(buffer[1] == 'E'){
	if(buffer[2] == 'R'){
	if(buffer[3] == 'N'){
	if(buffer[4] == 'E'){
	if(buffer[5] == 'L'){
	if(buffer[6] == 'A'){
	if(buffer[7] == 'F'){
	if(buffer[8] == 'L'){
		PANIC;
	}}}}}}}}}

	if(buffer[0] == 'm'){
	if(buffer[1] == 'a'){
	if(buffer[2] == 'c'){
	if(buffer[3] == 'O'){
	if(buffer[4] == 'S'){
	if(buffer[5] == '!'){
		PANIC;
	}}}}}}

	//printf("It works! \n");
	return 0;
}

static struct cdevsw device_fops = {
	.d_open  = vuln_open,
	.d_close = vuln_close,
	.d_write = vuln_write,
};

kern_return_t vuln_start(kmod_info_t *ki, void *d)
{
	device_major = cdevsw_add(-1, &device_fops);
	if (device_major < 0) {
		printf("cdevsw_add failed\n");
		return KERN_FAILURE;
	}
	device_handle = devfs_make_node(makedev(device_major, 0), DEVFS_CHAR, 0, 0, 0660, "%s", device_name);
	if (device_handle == NULL) {
		printf("devfs_make_node failed\n");
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

kern_return_t vuln_stop(kmod_info_t *ki, void *d)
{
	devfs_remove(device_handle);
	cdevsw_remove(device_major, &device_fops);
	return KERN_SUCCESS;
}
