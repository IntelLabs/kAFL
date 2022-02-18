# Common helers for kAFL-Fuzzer Python project
# Check install.sh for general kAFL/Nyx install


all: deps install
.PHONY: clean tags

deps:
	pip install -r requirements.txt

install:
	pip install .

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
