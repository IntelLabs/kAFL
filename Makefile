# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Makefile recipies for managing kAFL workspace

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
# declare all targets in this variable
ALL_TARGETS:=deploy clean env update build docs open_docs
# declare all target as PHONY
.PHONY: $(ALL_TARGETS)

# This small chunk of code allows us to pass arbitrary arguments to our make targets
# see the solution on SO:
# https://stackoverflow.com/a/14061796/3017219
# If the first argument is contained in ALL_TARGETS
ifneq ($(filter $(firstword $(MAKECMDGOALS)), $(ALL_TARGETS)),)
  # use the rest as arguments to create a new variable ADD_ARGS
  EXTRA_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(EXTRA_ARGS):;@:)
endif

all: deploy

# User targets
#---------------
deploy:
	make -C deploy $@ -- $(EXTRA_ARGS)

clean:
	make -C deploy $@

env: SHELL:=bash
env: env.sh
	@echo "Entering environment in sub-shell. Exit with 'Ctrl-d'."
	@PROMPT_COMMAND='source env.sh; unset PROMPT_COMMAND' $(SHELL)

docs:
	make -C docs html

open_docs: docs
	xdg-open $(ROOT_DIR)/docs/build/html/index.html

# Developer targets
#------------------
# pull the latest changes from all components
update:
	make -C deploy $@ -- $(EXTRA_ARGS)

# rebuild all components
build:
	make -C deploy $@ -- $(EXTRA_ARGS)
