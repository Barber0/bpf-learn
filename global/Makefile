CC ?= gcc

CFLAGS := -g -Wall

LIBBPF_DIR := ../libbpf/src/

CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/

all: cmd_args.o xdp_helper.o

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o