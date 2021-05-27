#!/usr/bin/env make

SHELL:=bash

CSAL_BASE:=CSAL
CSAL_ARCH:=arm64
CSAL_BUILD:=rel
CSAL_INC:=$(CSAL_BASE)/include
CSAL_LIB:=$(CSAL_BASE)/lib/$(CSAL_ARCH)/$(CSAL_BUILD)
CSAL_DEMO:=$(CSAL_BASE)/demos
LIBCSACCESS:=$(CSAL_LIB)/libcsaccess.a
LIBCSACCUTIL:=$(CSAL_LIB)/libcsacc_util.a
CSKNOWNBOARDS:=$(CSAL_DEMO)/$(CSAL_BUILD)-$(CSAL_ARCH)/cs_demo_known_boards.o

CSD_BASE:=OpenCSD
CSD_PLAT:=linux-arm64
CSD_BUILD:=rel
CSD_DECODER:=$(CSD_BASE)/decoder/tests/bin/$(CSD_PLAT)/$(CSD_BUILD)/trc_pkt_lister_s

CFLAGS:=-I$(CSAL_INC) -I$(CSAL_DEMO)

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)
TARGET:=proc-trace

TESTS:= \
  tests/fib \
  tests/loop \

DIR?=trace/$(shell date +%Y-%m-%d-%H-%M-%S)
TRACEE?=tests/fib

all: $(TARGET) $(TESTS)

trace: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(TARGET)) $(realpath $(TRACEE))

$(TARGET): $(OBJS) $(CSKNOWNBOARDS) $(LIBCSACCESS) $(LIBCSACCUTIL)
	$(CC) -o $@ $^

$(CSD_DECODER):
	$(MAKE) -C $(CSD_BASE)/decoder/build/linux -f makefile.dev

libcsal:
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) NO_DIAG=1

$(CSKNOWNBOARDS): libcsal
$(LIBCSACCESS): libcsal
$(LIBCSACCUTIL): libcsal

clean:
	$(MAKE) -C $(CSAL_BASE) clean ARCH=$(CSAL_ARCH) NO_DIAG=1 && \
	rm -f *.o $(TARGET) $(TESTS)

.PHONY: all trace libcsal clean
