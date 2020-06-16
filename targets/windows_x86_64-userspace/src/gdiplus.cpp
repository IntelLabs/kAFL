#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>
#include <psapi.h>
#include "kafl_user.h"

#define PAYLOAD_FILENAME "payload.emf"

/*
 *
 https://msdn.microsoft.com/en-us/library/windows/desktop/ms533814(v=vs.85).aspx

 -- compile for kAFL 
 $ x86_64-w64-mingw32-gcc gdiplus.cpp -o gdiplus.exe -lpsapi -lgdiplus -Wall -fno-exceptions -fno-rtti 

 -- no SetProcessWorkingSetSize and VirtualLock 
 $ x86_64-w64-mingw32-gcc gdiplus.cpp -o gdiplus.exe -lpsapi -lgdiplus -Wall -fno-exceptions -fno-rtti -D__NOLOCK

 -- more verbose
 $ x86_64-w64-mingw32-gcc gdiplus.cpp -o gdiplus.exe -lpsapi -lgdiplus -Wall -fno-exceptions -fno-rtti -D__DBG

 -- standalone run to use without kAFL: 
 $ x86_64-w64-mingw32-gcc gdiplus.cpp -o gdiplus.exe -lpsapi -lgdiplus -Wall -fno-exceptions -fno-rtti -D__NOKAFL -D__DBG

*/


char payload_file[MAX_PATH] = { 0 };
DWORD dwWritten;

static void panic(void){
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while(1){}; /* halt */
}


//https://www.codeproject.com/Questions/172037/Convert-char-to-wchar
WCHAR* char2wchar(const PCHAR p){
  // required size
  int nChars = MultiByteToWideChar(CP_ACP, 0, p, -1, NULL, 0);
  // allocate it
  WCHAR* pwcsName = (WCHAR*)VirtualAlloc(0, nChars*sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
  MultiByteToWideChar(CP_ACP, 0, p, -1, (LPWSTR)pwcsName, nChars);
  return pwcsName;
}


void drop_VA(){
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO sys_info;
    LPVOID curr_addr;
    TCHAR filename[MAX_PATH] = { 0 };
    MODULEINFO module_info;

    GetSystemInfo(&sys_info); 
    curr_addr = sys_info.lpMinimumApplicationAddress;

    while (curr_addr < sys_info.lpMaximumApplicationAddress)
    {
        memset(&mbi, 0, sizeof(mbi));
        if (VirtualQuery((LPCVOID)curr_addr, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
            {
                GetModuleInformation((HANDLE)-1, (HMODULE)curr_addr, &module_info, sizeof(module_info));
                GetModuleFileNameA((HMODULE)curr_addr, filename, MAX_PATH);
                if (curr_addr == module_info.lpBaseOfDll)
                {
                    hprintf("[+] 0x%p-0x%p \"%s\"\n", curr_addr, (void*)((DWORD64)curr_addr + (DWORD64)module_info.SizeOfImage), filename);
                }
                else
                {
                    hprintf("    0x%p-0x%p \033[1A", curr_addr, (void*)((DWORD64)curr_addr + (DWORD64)mbi.RegionSize));
                    switch(mbi.Protect)
                    {
                        case PAGE_EXECUTE:
                            hprintf("\033[42C--X\n");
                            break;
                        case PAGE_EXECUTE_READ:
                            hprintf("\033[42CR-X\n");
                            break;
                       case PAGE_EXECUTE_READWRITE:
                            hprintf("\033[42CRWX\n");
                            break;
                       case PAGE_READONLY:
                            hprintf("\033[42CR--\n");
                            break;
                       case PAGE_READWRITE:
                            hprintf("\033[42CRW-\n");
                            break;
                       case PAGE_WRITECOPY:
                            hprintf("\033[42CRW- (cow)\n");
                            break;

                    }
                }
            }
        }

        curr_addr = (PCHAR)curr_addr + mbi.RegionSize;
    }
}


/* forward exceptions to panic handler */
LONG CALLBACK exc_handle(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;

#if __DBG
    hprintf("Exception caught: %x\n", exception_code);
#endif

    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       //(exception_code == STATUS_HEAP_CORRUPTION) ||
       (exception_code == 0xc0000374) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT))
    {
        panic();
    }

    return TRUE;
}


void write_payload_file(const PCHAR target_file, kAFL_payload* kafl_payload)
{
    HANDLE payload_file_handle = CreateFileA((LPCSTR)target_file,
        GENERIC_READ | GENERIC_WRITE,
        /* FILE_SHARE_READ | FILE_SHARE_WRITE */ 0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, 
        NULL
    );
    //LockFile(payload_file_handle, 0, 0, kafl_payload->size, 0);

    if (payload_file_handle == INVALID_HANDLE_VALUE){
#ifdef __DBG
        hprintf("[-] Cannot CreateFile: %u\n", (DWORD) GetLastError());
#endif
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

#ifdef __DBG
    hprintf("[-] %lx %d\n", *(PDWORD64)kafl_payload->data, kafl_payload->size);
    BOOL r = WriteFile(payload_file_handle,
#else
    WriteFile(payload_file_handle,
#endif
        kafl_payload->data,
        kafl_payload->size,
        &dwWritten,
        NULL
    );

#ifdef __DBG
    if (r == FALSE){
        hprintf("[-] Error when writing payload file: %u\n", (DWORD) GetLastError());
    }

    hprintf("[+] Size: %d written: %d\n",kafl_payload->size, dwWritten);
#endif

#ifdef __DBG
    BOOL s = CloseHandle(payload_file_handle);
    if (s == FALSE){
        hprintf("[-] Error when closing payload file: %u\n", (DWORD) GetLastError());
    }

#else
    CloseHandle(payload_file_handle);
    payload_file_handle = NULL;
#endif
}


void set_payload(char* path, kAFL_payload* payload_buffer)
{
    printf("[+] reading payload file %s\n", path);
    DWORD dwRead = 0;
    HANDLE hFile = CreateFile((LPCSTR)path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Err: Cannot open testcase: 0x%X\n", (UINT)GetLastError());
        ExitProcess(0);
    }

    payload_buffer->size = GetFileSize(hFile, NULL);

    // FIXME: length check on data
    if (!ReadFile(hFile, payload_buffer->data, payload_buffer->size, &dwRead, NULL)){
        printf("[-] Cannot read testcase: 0x%X\n", (UINT)GetLastError());
        ExitProcess(0);
    }
    printf("[+] Payload size: %d; read: %lu\n", payload_buffer->size, dwRead);

    CloseHandle(hFile);
}



int main(int argc, char** argv)
{
    memset(payload_file, 0x00, MAX_PATH);   
    DWORD tmp_path_len = GetTempPathA(MAX_PATH, payload_file);
    memcpy(payload_file + tmp_path_len, "\x5c", 1);
    memcpy(payload_file + tmp_path_len + 1, PAYLOAD_FILENAME, strlen(PAYLOAD_FILENAME));

    Gdiplus::Image* image = NULL;
    Gdiplus::Status status;

#ifndef __NOLOCK
    VirtualLock(image, sizeof(image));
    VirtualLock(&status, sizeof(&status));
#endif

    /* load dll to fuzz (gdiplus.dll) */
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    /* dump module names, addresses and sizes */
    drop_VA();

    hprintf("[+] payload location %s\n", payload_file);
	WCHAR* payload_fileW = char2wchar(payload_file);
    wprintf(L"[+] payload location %s\n", payload_fileW);

#ifndef __NOKAFL
    /* install exception handler */
    if (AddVectoredExceptionHandler(1, exc_handle) == 0)
    {
        hprintf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }
#endif

#ifndef __NOLOCK
    if(!VirtualLock(payload_file, strlen(payload_file)) || !VirtualLock(payload_fileW, wcslen(payload_fileW)))
    {
        hprintf("[+] WARNING: Virtuallock failed on payload names: %u", GetLastError());
    }
#endif

    /* kafl loop logic */

    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

#ifndef __NOLOCK
    if (!VirtualLock(payload_buffer, PAYLOAD_SIZE))
    {
        hprintf("[+] WARNING: Virtuallock failed on payload buffer %lp...\n", payload_buffer);
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }
#endif

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)\n", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

#ifdef __NOKAFL
    if (argc != 2)
    {
        printf("[-] Need a payload file as first parameter\n");
        exit(1);
    }

    set_payload(argv[1], payload_buffer);
#endif

    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] Range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);
 
#ifndef __NOLOCK
    hprintf("[+] Locking fuzzing ranges...\n");
    if (!SetProcessWorkingSetSize((HANDLE)-1, 1 << 25 /* min: 64MB */, 1 << 31 /* max: 2GB */))
    {
        hprintf("[-] Err increasing min and max working sizes: %u\n", (UINT32)GetLastError());
    }

# ifndef __NOKAFL
    for(int i = 0; i < 4; i++){
        hprintf("[+] Range %d enabled: %x\t(%p-%p)\n", i, (uint8_t)range_buffer->enabled[i], range_buffer->ip[i], range_buffer->size[i]);
        if (range_buffer->ip[i] != 0)
        {
            if (!VirtualLock((LPVOID)range_buffer->ip[i], range_buffer->size[i]))
            {
                hprintf("[-] WARNING: VirtualLock failed on range %d (%u)\n", (uint8_t)range_buffer->enabled[i], (UINT32)GetLastError());
                kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
            }
            else
            {
                hprintf("[+] Range %d locked\n", (uint8_t)range_buffer->enabled[i]);
            }
        }
    }
# endif
#endif

    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

#ifdef __NOKAFL
    int c = 0;
    while(c < 5)
    {
        c++;
        hprintf("[+] Iter: %d\n", c);
#else
    while(1)
    {
#endif
        kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

        write_payload_file(payload_file, payload_buffer);
#ifdef __DBG
        hprintf("[+] Payload size:%d\n", payload_buffer->size);
#endif
        image = Gdiplus::Image::FromFile(payload_fileW, FALSE);
        status = image->GetLastStatus();

        if (image && status == Gdiplus::Ok)
        {
#ifdef __DBG
            hprintf("[+] Image (%p) ok: %d\n", image, status);
#endif
            HDC hdc = GetDC(NULL);
            Gdiplus::Graphics graphics(hdc);
            graphics.DrawImage(image,0,0);
        }
        else{
#ifdef __DBG
            hprintf("[-] Image (%p) error: %d\n", image, status);
#endif
        }

        delete image;

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

}


/*
 * kAFL issues:
 * non reload mode:
 * SetProcessWorkingSetSize produces hangs
 *
 * reload mode
 * new Gdiplus::Image(L"filename") causes hangs
 *
 */
