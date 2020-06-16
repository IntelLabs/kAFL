/*
 * Zephyr FS fuzzing sample
 *
 * This is not really working. Can you fix it?
 *
 * lsdir() function and other snippets taken from Zephyr RTOS project
 * samples/subsys/fs/fat_fs/src/main.c
 *
 * Copyright 2019-2020 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>
#include <fs/fs.h>
#include <ff.h>

#include <string.h>
#include <sys/types.h>

static FATFS fat_fs;
static struct fs_mount_t mp = {
	.type = FS_FATFS,
	.fs_data = &fat_fs,
};

static const char *disk_mount_pt = "/SD:";

void target_init() {};

static int lsdir(const char *path)
{
    int res;
    struct fs_dir_t dirp;
    static struct fs_dirent entry;

    /* Verify fs_opendir() */
    res = fs_opendir(&dirp, path);
    if (res) {
        printk("Error opening dir %s [%d]\n", path, res);
        return res;
    }

    printk("\nListing dir %s ...\n", path);
    for (;;) {
        /* Verify fs_readdir() */
        res = fs_readdir(&dirp, &entry);

        /* entry.name[0] == 0 means end-of-dir */
        if (res || entry.name[0] == 0) {
            break;
        }

        if (entry.type == FS_DIR_ENTRY_DIR) {
            printk("[DIR ] %s\n", entry.name);
        } else {
            printk("[FILE] %s (size = %zu)\n",
                entry.name, entry.size);
        }
    }

    /* Verify fs_closedir() */
    res = fs_closedir(&dirp);

    return res;
}

ssize_t target_entry(void *buf, size_t len)
{
	int rc = 0;

	mp.fs_data = buf;
	mp.mnt_point = disk_mount_pt;

	int res = fs_mount(&mp);

	if (res == FR_OK) {
		printk("Disk mounted.\n");
		lsdir(disk_mount_pt);
		fs_unmount(&mp);
	} else {
		printk("Error mounting disk.\n");
	}

	return rc;
}

