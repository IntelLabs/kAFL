# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Makefile recipies for managing kAFL workspace

export PIPENV_VENV_IN_PROJECT := 1

all: env update install
.PHONY: clean tags

env: .env .west
ifeq ($(PIPENV_ACTIVE), 1)
	@echo "Already inside pipenv. Skipping."
else
	pipenv shell
endif

.env: .west .venv manifest/create_env.sh
	@# do not write .env on script failure
	pipenv run bash ./manifest/create_env.sh > .env.out
	mv .env.out .env

.west: | .venv
	pipenv run west init -l manifest
	@# minimum install for manifest import!
	pipenv run west update kafl

.venv:
	sudo apt install python3-pip
	pip install -U pipenv
	pipenv install

update:
	west update -k

install:
ifneq ($(PIPENV_ACTIVE), 1)
	@echo "Error: Need to run inside pipenv. Abort."
else
	./kafl/install.sh check
	./kafl/install.sh deps
	./kafl/install.sh perms
	./kafl/install.sh qemu
	./kafl/install.sh radamsa
	make -C $(KAFL_ROOT) install
endif
