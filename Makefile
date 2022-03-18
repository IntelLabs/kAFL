# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Common helers for kAFL-Fuzzer Python project

all: deps install
.PHONY: clean tags

deps:
	pip install -r requirements.txt

install:
	pip install -e .

uninstall:
	pip uninstall kafl_fuzzer

clean:
	rm -rf build
	rm -rf kafl_fuzzer.egg-info
	rm -f kafl_fuzzer/native/bitmap*.so
	rm -f tags

tags:
	ctags -R kafl*.py kafl_fuzzer

test:
	pytest -v kafl_fuzzer

benchmark:
	python kafl_fuzzer/test.py
