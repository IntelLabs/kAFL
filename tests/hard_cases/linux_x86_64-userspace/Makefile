SRCS := main.c
DEPS := ../tests.h
BINS := test_vuln_32 test_vuln_64

CFLAGS := -static -std=c99

all: $(BINS)

clean:
	$(RM) $(BINS)

test_vuln_32: $(DEPS) $(SRCS)
	$(CC) $(CFLAGS) -m32 -o $@ $(SRCS)

test_vuln_64: $(SRC)
	$(CC) $(CFLAGS) -m64 -o $@ $(SRCS)


.PHONY: $(BINS)
