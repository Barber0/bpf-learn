CC ?= gcc

CFLAGS := -g -Wall

LIBBPF_DIR := ../libbpf/src/

CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o