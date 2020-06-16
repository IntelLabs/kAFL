#!/bin/bash
if [[ $UID != 0 ]]; then
	echo "Please run this script as root!"
	exit 1
else
	make
	insmod kafl_vuln_test.ko
	echo "done"
	exit 0
fi
