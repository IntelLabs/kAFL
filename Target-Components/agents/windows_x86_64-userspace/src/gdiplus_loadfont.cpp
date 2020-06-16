#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>
#include <psapi.h>
#include "kafl_user.h"


/*
 * x86_64-w64-mingw32-g++ gdiplus_loadfont.cpp  -o gdiplus_loadfont.exe -lpsapi -lgdiplus -fno-exceptions -fno-rtti -Wall -static-libstdc++ -static-libgcc -static 
*/



static void panic(void){
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while(1){}; /* halt */
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
    /* load dll to fuzz (gdiplus.dll) */
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    /* dump module names, addresses and sizes */
    drop_VA();

#ifndef __NOKAFL
    /* install exception handler */
    if (AddVectoredExceptionHandler(1, exc_handle) == 0)
    {
        hprintf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
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

#ifdef __DBG
        hprintf("[+] Payload size:%d\n", payload_buffer->size);
#endif
        Gdiplus::PrivateFontCollection* fonts = new Gdiplus::PrivateFontCollection();
        Gdiplus::Status status = fonts->AddMemoryFont(payload_buffer->data, payload_buffer->size);

        if (fonts && status == Gdiplus::Ok)
        {
#ifdef __DBG
            hprintf("[+] Font collection ok: %d\n", status);
#endif
            INT count = fonts->GetFamilyCount();
            if (count == 1)
            {
#ifdef __DBG
                hprintf("[+] Loading font...\n");
#endif
                INT found = 0;
                Gdiplus::FontFamily* font_families = new Gdiplus::FontFamily[count];
                fonts->GetFamilies(count, font_families, &found);
                WCHAR family_name[LF_FACESIZE];
                INT style = -1;
                if(font_families[0].IsStyleAvailable(0))
                {
                    //style = FontStyleRegular;
                    style = 0;
                }
                else if(font_families[0].IsStyleAvailable(1))
                {
                    //style = FontStyleBold;
                    style = 1;
                }
                else if(font_families[0].IsStyleAvailable(2))
                {
                    //style = FontStyleItalic;
                    style = 2;
                }
#ifdef __DBG
                else
                {
                    hprintf("[+] No font style\n");
                }
#endif

                if (style != -1)
                {
                    font_families[0].GetFamilyName(family_name);
                    Gdiplus::Font* font = new Gdiplus::Font(family_name, 24, style, Gdiplus::UnitPixel, fonts);
                    if (font->GetLastStatus() == Gdiplus::Ok){
#ifdef __DBG
                        hprintf("[+] Font ok\n");
#endif
                        Gdiplus::PointF* pointF = new Gdiplus::PointF(10.0f, 0.0f);
                        Gdiplus::SolidBrush* solidBrush = new Gdiplus::SolidBrush(Gdiplus::Color(255, 0, 0, 0));
                        HDC hdc = GetDC(NULL);
                        Gdiplus::Graphics* graphics = new Gdiplus::Graphics(hdc);
                        graphics->DrawString(family_name, -1, font, *pointF, solidBrush);
                        delete graphics;
                    }
#ifdef __DBG
                    else
                    {
                        hprintf("[+] Font loading error\n");
                    }
#endif
                    delete font;
                }
            }
        }
#ifdef __DBG
        else
        {
            hprintf("[-] Font error: %d\n", status);
        }

#endif

        delete fonts;

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

}

