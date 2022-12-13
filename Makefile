# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Makefile recipies for managing kAFL workspace

# declare all targets in this variable
ALL_TARGETS:=deploy clean env update build
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

all: help

# User targets
#---------------
deploy:
	make -C deploy $@ -- $(EXTRA_ARGS)

clean:
	make -C deploy $@

env: SHELL:=bash
env: kafl/env.sh
	@echo "Entering environment in sub-shell. Exit with 'Ctrl-d'."
	@PROMPT_COMMAND='source kafl/env.sh; unset PROMPT_COMMAND' $(SHELL)

define HELP_TEXT
Manage kAFL installation.

  User actions:
    deploy:\tFull installation (download, build, install)
    env:\tActivate installation (shell env + python venv)
    clean:\tPurge ansible installation (to force re-deploy)

  Developer actions:
    update:\tUpdate cloned git repositories
    build:\tExecute component build steps only
endef
export HELP_TEXT

help:
	@echo "$$HELP_TEXT"


# Developer targets
#------------------
# pull the latest changes from all components
update:
	make -C deploy $@ -- $(EXTRA_ARGS)

# rebuild all components
build:
	make -C deploy $@ -- $(EXTRA_ARGS)
