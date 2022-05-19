# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Makefile recipies for managing kAFL workspace

# declare all targets in this variable
ALL_TARGETS:=deploy
# declare all target as PHONY
.PHONY: $(ALL_TARGETS)

# This small chunk of code allows us to pass arbitrary argument to our make targets
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

deploy: venv
	venv/bin/ansible-galaxy install -r requirements.yml
	venv/bin/ansible-playbook -i 'localhost,' -c local site.yml $(EXTRA_ARGS)

deploy_ci: venv
	venv/bin/ansible-galaxy install -r requirements.yml
	venv/bin/ansible-playbook -i 'localhost,' -c local site.yml \
		--skip-tags "hardware_check,kvm_device" \
		--extra-vars "git_clone_depth=1"

venv:
	python3 -m venv venv
	venv/bin/pip install wheel
	venv/bin/pip install -r requirements.txt
