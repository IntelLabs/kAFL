# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Makefile recipies for managing kAFL workspace

.PHONY: deploy

all: deploy

deploy: venv
	venv/bin/ansible-playbook -i 'localhost,' -c local site.yml

venv:
	python3 -m venv venv
	venv/bin/pip install -r requirements.txt
