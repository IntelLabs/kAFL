#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cornelius Aschermann");
MODULE_DESCRIPTION("kAFL Test Module");

#define NAME	    "kafl_vuln"

void test_panic(char* descr){
  panic(KERN_INFO" %s", descr);
}

void* test_malloc(size_t size) {
  return kmalloc(size, GFP_KERNEL);
}


void test_free(void* data){
  kfree(data);
}


#include "../tests.h"

ssize_t write_info(struct file *filp, const char __user *buff, size_t len, loff_t *data);

struct proc_dir_entry *proc_file_entry;

static const struct file_operations proc_file_fops = {
	 .owner = THIS_MODULE,
	 .write = write_info,
	};

int init_mod( void )
{
	proc_file_entry = proc_create(NAME, 0666, NULL, &proc_file_fops);
	if(proc_file_entry == NULL)
		return -ENOMEM;
	return 0;
}

void cleanup_mod( void )
{
	remove_proc_entry(NAME, NULL);
	printk(KERN_INFO "/proc/%s removed.\n", NAME);
}

module_init(init_mod);
module_exit(cleanup_mod);

ssize_t write_info(struct file *filp, const char __user *buff, size_t len, loff_t *data) {
	char input[256];
	
	if (len >= 256){
		return -EFAULT;
	}
	
	if (copy_from_user(input, buff, len)) {
		return -EFAULT;
	}
	test(input, len);
	return len;

}

