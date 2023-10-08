# Target analysis

## Objectives

The objective of this tutorial is to fuzz a Windows program, built for educational purposes.

Like the [driver](../driver/index.md) that we've previously covered, this program doesn't interact with anything, except issuing kAFL hypercalls, and calling it's own function.

## Source code

The source code is located at [`kafl.targets/windows_x86_64/src/userspace/selffuzz_test.c`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/userspace/selffuzz_test.c)

The code is deliberatly kept straightforward to enhance understanding and learning experience.

1. Initialization of kAFL agent
2. Allocation of kAFL payload buffer
3. Ensure fuzzing ranges are locked
4. `fuzzme()` function is called with kAFL payload buffer

## Vulnerability

Two [`PANIC`](../../../reference/hypercall_api.md#panic--kasan) kAFL Hypercalls have been inserted into the `fuzzme()` function:

```c
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
```

We can recognize 2 paths leading to a crash:

```{mermaid}
graph TD
    classDef red fill:#ff7d7d
    subgraph Userspace
        crashme -->|"K3rN3lAFL#"| panic["panic()"]:::red
        crashme -->|"PwnT0wn!"| panic
    end
```

## kAFL Agent Implementation

The Agent is initialized following the usual hypercall sequence and the harness is implemented around `fuzzme()` function.

You can check the [driver](../driver/target.md#agent-initialization) for a similar implementation.
