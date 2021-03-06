CLANG ?= clang
LLC ?= llc
CC ?= gcc

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

USER_C := ${USER_TARGET:=.c}
USER_OBJ := ${USER_C:.c=.o}
USER_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
LDFLAGS ?= -L$(LIBBPF_DIR)

XDP_C = ${XDP_TARGET:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/

LIBS = -l:libbpf.a -lelf -lz $(USER_LIBS)

OUTPUT_DIR ?= ./

all: llvm-check $(USER_TARGET) $(XDP_OBJ)
	@echo "alpha"

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(XDP_OBJ) $(USER_TARGET)
	rm -f *.ll
	rm -f *~

COMMON_MK = $(COMMON_DIR)/common.mk

COMMON_OBJS += $(COMMON_DIR)/cmd_args.o $(COMMON_DIR)/xdp_helper.o
$(COMMON_OBJS):
	make -C $(COMMON_DIR)

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

$(USER_TARGET): %: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS)
	mkdir -p $(OUTPUT_DIR)
	$(CC) -Wall $(USER_CFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$@ $(COMMON_OBJS) $< $(LIBS)

$(XDP_OBJ): %.o: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_MK)
	mkdir -p $(OUTPUT_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o $(OUTPUT_DIR)/${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $(OUTPUT_DIR)/$@ $(OUTPUT_DIR)/${@:.o=.ll}