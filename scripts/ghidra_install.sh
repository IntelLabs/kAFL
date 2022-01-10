#!/bin/bash

set -e

URL='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.1_build/ghidra_10.1.1_PUBLIC_20211221.zip'

ZIPFILE="$(basename "$URL")"

pushd $HOME

wget -O "$ZIPFILE" "$URL"
unzip "$ZIPFILE"

sudo apt-get install openjdk-11-jdk openjdk-11-jre
