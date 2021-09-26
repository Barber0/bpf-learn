CC ?= gcc

CFLAGS := -g -Wall

LIBBPF_MAIN_DIR := ../libbpf
LIBBPF_BUILD_DIR := $(LIBBPF_MAIN_DIR)/src/

CFLAGS += -I$(LIBBPF_BUILD_DIR)/build/usr/include/ 

all: cmd_args.o xdp_helper.o

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o