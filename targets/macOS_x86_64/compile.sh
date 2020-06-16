if [[ "$OSTYPE" == "darwin"* ]]; then
	printf "\tCompiling info executable...\n"
	gcc -o info/info info/info.c
	printf "\tCompiling loader...\n"
	gcc -o loader/loader loader/loader.c # -D DEBUG_MODE
	printf "\tCompiling loader (autoreload)...\n"
	gcc -o loader/loader_autoreload loader/loader.c -D AUTORELOAD
	printf "\tCompiling vuln_driver fuzzer...\n"
	gcc -o fuzzer/vuln_test fuzzer/vuln_test.c # -D DEBUG_MODE
else
	printf "\tError: Need to run MacOS to compile these components! Skipping..!\n"
fi
