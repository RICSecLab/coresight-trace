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

CSDEC_BASE:=coresight-decoder
CSDEC:=$(CSDEC_BASE)/processor

CFLAGS:= \
  -Wall \
  -I$(CSAL_INC) \
  -I$(CSAL_DEMO) \

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)
TARGET:=proc-trace

TESTS:= \
  tests/fib \
  tests/loop \
  tests/bf \

DATE:=$(shell date +%Y-%m-%d-%H-%M-%S)
DIR?=trace/$(DATE)
TRACEE?=tests/fib

BF_HELLO:="+[-->-[>>+>-----<<]<--<---]>-.>>>+.>>..+++[.>]<<<<.+++.------.<<-.>>>>+."
BF_INC:="[->+<]"
BF_CODE?=$(BF_HELLO)

all: $(TARGET) $(TESTS)

trace-bf: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(TARGET)) $(realpath $(TRACEE)) $(BF_CODE)

trace: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(TARGET)) $(realpath $(TRACEE))

decode: $(CSDEC) trace
	$(realpath $(CSDEC)) $(shell cat $(DIR)/decoderargs.txt)

$(CSDEC):
	$(MAKE) -C $(CSDEC_BASE)

$(TARGET): $(OBJS) $(CSKNOWNBOARDS) $(LIBCSACCESS) $(LIBCSACCUTIL)
	$(CC) -o $@ $^

libcsal:
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) NO_DIAG=1

$(CSKNOWNBOARDS): libcsal
$(LIBCSACCESS): libcsal
$(LIBCSACCUTIL): libcsal

clean:
	rm -f *.o $(TARGET) $(TESTS)

dist-clean: clean
	$(MAKE) -C $(CSAL_BASE) clean ARCH=$(CSAL_ARCH) NO_DIAG=1

.PHONY: all trace decode libcsal clean dist-clean
