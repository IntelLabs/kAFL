#include <windows.h>
#include "kafl_user.h"

void fuzzme(uint8_t*, int);
void end();


static inline void panic(void){
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while(1){}; /* halt */
}


int main(int argc, char** argv){
    hprintf("[+] Starting... %s\n", argv[0]);

    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    if (!VirtualLock(payload_buffer, PAYLOAD_SIZE)){
        hprintf("[+] WARNING: Virtuallock failed on payload buffer %lp...\n", payload_buffer);
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

    hprintf("[+] Memset kAFL_payload at address %lx (size %d)\n", (uint64_t) payload_buffer, PAYLOAD_SIZE);
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);
 
    hprintf("[+] Locking fuzzing ranges...\n");
    for(int i = 0; i < 4; i++){
        hprintf("[+] Range %d enabled: %x\t(%p-%p)\n", i, (uint8_t)range_buffer->enabled[i], range_buffer->ip[i], range_buffer->size[i]);
        if (range_buffer->ip[i] != 0){
            if (!VirtualLock((LPVOID)range_buffer->ip[i], range_buffer->size[i])){
                hprintf("[+] WARNING: VirtualLock failed on range %d...\n", (uint8_t)range_buffer->enabled[i]);
                kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
            }
            else{
                hprintf("[+] Range %d locked\n", (uint8_t)range_buffer->enabled[i]);
            }
        }
    }

    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    hprintf("[+] Range: 0x%p-0x%p\n", fuzzme, end);

    while(1){
            kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);
            fuzzme(payload_buffer->data, payload_buffer->size);
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    return 0;
}


void fuzzme(uint8_t* input, int size){
    if (size > 0x11){
        if(input[0] == 'K')
            if(input[1] == '3')
                if(input[2] == 'r')
                    if(input[3] == 'N')
                        if(input[4] == '3')
                            if(input[5] == 'l')
                                if(input[6] == 'A')
                                    if(input[7] == 'F')
                                        if(input[8] == 'L')
                                            if(input[9] == '#')
                                                panic();

        if(input[0] == 'P')
            if(input[1] == 'w')
                if(input[2] == 'n')
                    if(input[3] == 'T')
                        if(input[4] == '0')     
                            if(input[5] == 'w')     
                                if(input[6] == 'n')
                                    if(input[7] == '!')
                                        panic();

    }
};

void end(){}

