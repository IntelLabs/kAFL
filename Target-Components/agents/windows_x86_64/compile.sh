if [[ "$OSTYPE" == "linux-gnu" ]]; then

	mkdir bin/ 2> /dev/null
	mkdir bin/loader/ 2> /dev/null
	mkdir bin/fuzzer/ 2> /dev/null
	mkdir bin/info/ 2> /dev/null

	if x86_64-w64-mingw32-gcc -v 2> /dev/null && x86_64-w64-mingw32-g++ -v 2> /dev/null; then
		printf "\tCompiling loader...\n"
		x86_64-w64-mingw32-g++ src/info/info.cpp -I ../ -o bin/info/info.exe -lntdll -lpsapi
		printf "\tCompiling info executable...\n"
		x86_64-w64-mingw32-gcc src/loader/loader.c -I ../ -o bin/loader/loader.exe -Wall -lpsapi
		printf "\tCompiling vuln_driver fuzzer...\n"
		x86_64-w64-mingw32-gcc src/fuzzer/vuln_test.c -I ../ -o bin/fuzzer/vuln_test.exe
        printf "\tCompiling hprintf test...\n"
        x86_64-w64-mingw32-gcc src/fuzzer/hprintf_test.c -I ../ -o bin/fuzzer/hprintf_test.exe -mwindows -Wall

	else
		printf "\tError: x86_64-w64-mingw32-gcc/g++ not found. Please install x86_64-w64-mingw32-gcc/g++ (sudo apt install gcc-mingw-w64-x86-64  g++-mingw-w64-x86-64)!\n"
	fi 
else
	printf "\tError: Cannot compile windows userspace components on this platform!\n\tPlease use Linux instead!\n"
fi


# sudo apt install gcc-mingw-w64-x86-64
# sudo apt install gcc-mingw-w64-x86-64
# linux_x86-64-2$ x86_64-w64-mingw32-gcc -v
