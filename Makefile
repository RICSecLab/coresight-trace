#!/usr/bin/env make

SHELL:=bash

CSAL_BASE:=CSAL
CSAL_ARCH:=arm64
CSAL_BUILD:=rel
CSAL_INC:=$(CSAL_BASE)/include
CSAL_LIB:=$(CSAL_BASE)/lib/$(CSAL_ARCH)/$(CSAL_BUILD)
CSAL_DEMO:=$(CSAL_BASE)/demos
CSAL_FLAGS:=ARCH=$(CSAL_ARCH) NO_DIAG=1 NO_CHECK=1
LIBCSACCESS:=$(CSAL_LIB)/libcsaccess.a
LIBCSACCUTIL:=$(CSAL_LIB)/libcsacc_util.a

CSDEC_BASE:=coresight-decoder
CSDEC:=$(CSDEC_BASE)/processor

INC:=include

HDRS:= \
  $(INC)/config.h \
  $(INC)/utils.h \

OBJS:= \
  src/config.o \
  src/known_boards.o \
  src/main.o \
  src/utils.o \

CFLAGS:= \
  -Wall \
  -I$(INC) \
  -I$(CSAL_INC) \
  -I$(CSAL_DEMO) \
  -lpthread \

ifneq ($(strip $(DEBUG)),)
  CFLAGS+=-g -O0
endif

TARGET:=proc-trace
TARGET_FLAGS?=

ifneq ($(strip $(DEBUG)),)
  TARGET_FLAGS+=--export-config=1 --verbose=2
endif

ifneq ($(strip $(NOTRACE)),)
  TARGET_FLAGS+=--tracing=0
endif

ifneq ($(strip $(NOPOLLING)),)
  TARGET_FLAGS+=--tracing=1 --polling=0
endif

TESTS:= \
  tests/fib \
  tests/fib-large \
  tests/fib-num \
  tests/loop \
  tests/bf \

DATE:=$(shell date +%Y-%m-%d-%H-%M-%S)
DIR?=trace/$(DATE)
TRACEE?=tests/fib

BF_HELLO:="+[-->-[>>+>-----<<]<--<---]>-.>>>+.>>..+++[.>]<<<<.+++.------.<<-.>>>>+."
BF_INC:="[->+<]"
BF_CODE?=$(BF_HELLO)

all: $(TARGET) $(TESTS)

decode: $(CSDEC) trace
	$(realpath $(CSDEC)) $(shell cat $(DIR)/decoderargs.txt)

trace-bf: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(TARGET)) $(realpath $(TRACEE)) $(BF_CODE)

trace: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(TARGET)) $(TARGET_FLAGS) -- $(realpath $(TRACEE))

debug: $(TARGET) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo gdb --args $(realpath $(TARGET)) $(TARGET_FLAGS) -- $(realpath $(TRACEE))

$(CSDEC):
	$(MAKE) -C $(CSDEC_BASE)

$(TARGET): $(OBJS) $(LIBCSACCESS) $(LIBCSACCUTIL)
	$(CC) -o $@ $^ $(CFLAGS)

libcsal:
	$(MAKE) -C $(CSAL_BASE) $(CSAL_FLAGS)

$(LIBCSACCESS): libcsal
$(LIBCSACCUTIL): libcsal

clean:
	rm -f $(OBJS) $(TARGET) $(TESTS)

dist-clean: clean
	$(MAKE) -C $(CSAL_BASE) clean $(CSAL_FLAGS)

.PHONY: all trace-bf trace debug decode libcsal clean dist-clean
