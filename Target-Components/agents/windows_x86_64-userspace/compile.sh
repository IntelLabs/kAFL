if [[ "$OSTYPE" == "linux-gnu" ]]; then

    mkdir bin/ 2> /dev/null

    if x86_64-w64-mingw32-gcc -v 2> /dev/null && x86_64-w64-mingw32-g++ -v 2> /dev/null; then
        printf "\tCompiling usermode fuzzer test...\n"
        x86_64-w64-mingw32-gcc src/selffuzz_test.c -I ../ -o bin/selffuzz_test.exe -mwindows -Wall
        printf "\tCompiling gdiplus fuzzer ...\n"
        x86_64-w64-mingw32-gcc src/gdiplus.cpp -I ../ -o bin/gdiplus.exe -lpsapi -lgdiplus -Wall -fno-exceptions -fno-rtti
        printf "\tCompiling gdiplus font fuzzer ...\n"
        x86_64-w64-mingw32-g++ src/gdiplus_loadfont.cpp -I ../ -o bin/gdiplus_loadfont.exe -lpsapi -lgdiplus -fno-exceptions -fno-rtti -Wall -static-libstdc++ -static-libgcc -static 

    else
        printf "\tError: x86_64-w64-mingw32-gcc/g++ not found. Please install x86_64-w64-mingw32-gcc/g++ (sudo apt install gcc-mingw-w64-x86-64  g++-mingw-w64-x86-64)!\n"
    fi 
else
    printf "\tError: Cannot compile windows userspace components on this platform!\n\tPlease use Linux instead!\n"
fi


# sudo apt install gcc-mingw-w64-x86-64
# sudo apt install gcc-mingw-w64-x86-64
# linux_x86-64-2$ x86_64-w64-mingw32-gcc -v
