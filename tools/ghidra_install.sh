#!/bin/bash

set -e

URL='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.2_build/ghidra_10.0.2_PUBLIC_20210804.zip'

ZIPFILE="$(basename "$URL")"

pushd $HOME

wget -O "$ZIPFILE" "$URL"
unzip "$ZIPFILE"

sudo apt-get install openjdk-11-jdk openjdk-11-jre
