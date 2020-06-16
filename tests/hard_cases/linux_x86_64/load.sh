#!/bin/bash
if [[ $UID != 0 ]]; then
	echo "Please run this script as root!"
	exit 1
else
	make
	insmod kafl_guest_driver.ko
	insmod kafl_vuln_test.ko
	MN=$(dmesg | grep 'kAFL MN: ' | grep -Eo ' [0-9]{3}' | tail -n 1)
	mknod /dev/kafl c ${MN} 0
	echo "done"
	exit 0
fi
