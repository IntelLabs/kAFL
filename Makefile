# Common helers for kAFL-Fuzzer Python project
# Check install.sh for general kAFL/Nyx install

all: env update install
.PHONY: clean tags

env: .env .west
ifeq ($(PIPENV_ACTIVE), 1)
	@echo "Already inside pipenv. Skipping."
else
	pipenv shell
endif

.env: .west .pipenv scripts/create_env.sh
	pipenv run bash ./scripts/create_env.sh > .env

.west: | .pipenv
	pipenv run west init -l manifest

.pipenv:
	sudo apt install python3 pip
	pip install -U pipenv
	pipenv install west
	@touch .pipenv

install:
ifneq ($(PIPENV_ACTIVE), 1)
	@echo "Error: Need to run inside pipenv. Abort."
else
	./install.sh all
	pip install -r requirements.txt
	pip install -e .
endif

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
