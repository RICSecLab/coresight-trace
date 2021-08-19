#!/usr/bin/env make

SHELL:=bash

CSAL_BASE:=CSAL
CSAL_ARCH:=arm64
ifneq ($(strip $(DEBUG)),)
  CSAL_BUILD:=dbg
else
  CSAL_BUILD:=rel
endif
CSAL_INC:=$(CSAL_BASE)/include
CSAL_LIB:=$(CSAL_BASE)/lib/$(CSAL_ARCH)/$(CSAL_BUILD)
CSAL_DEMO:=$(CSAL_BASE)/demos
CSAL_FLAGS:=ARCH=$(CSAL_ARCH) NO_DIAG=1 NO_CHECK=1
LIBCSACCESS:=$(CSAL_LIB)/libcsaccess.a
LIBCSACCUTIL:=$(CSAL_LIB)/libcsacc_util.a

CSDEC_BASE:=coresight-decoder
CSDEC:=$(CSDEC_BASE)/processor
CSDEC_INC:=$(CSDEC_BASE)/include
LIBCSDEC:=$(CSDEC_BASE)/libcsdec.a

INC:=include

HDRS:= \
  $(INC)/common.h \
  $(INC)/config.h \
  $(INC)/known-boards.h \
  $(INC)/utils.h \

COMMON_OBJS:= \
  src/common.o \
  src/config.o \
  src/utils.o \

CFLAGS:= \
  -std=c11 \
  -Wall \
  -I$(INC) \
  -I$(CSAL_INC) \
  -I$(CSAL_DEMO) \
  -I$(CSDEC_INC) \
  -lpthread \
  -lcapstone \

ifneq ($(strip $(DEBUG)),)
  CFLAGS+=-g -O0
else
  CFLAGS+=-O2
endif

CS_PROXY_OBJS:= \
  $(COMMON_OBJS) \
  src/cs-proxy.o \

CS_PROXY:=cs-proxy

PROC_TRACE_OBJS:= \
  $(COMMON_OBJS) \
  src/proc-trace.o \

PROC_TRACE:=proc-trace
PROC_TRACE_FLAGS?=

ifneq ($(strip $(DEBUG)),)
  PROC_TRACE_FLAGS+=--export-config=1 --verbose=2
endif

ifneq ($(strip $(NOTRACE)),)
  PROC_TRACE_FLAGS+=--tracing=0
endif

ifneq ($(strip $(NOPOLLING)),)
  PROC_TRACE_FLAGS+=--tracing=1 --polling=0
endif

TESTS:= \
  tests/fib \
  tests/fib-large \
  tests/fib-num \
  tests/loop \
  tests/bf \
  tests/toy \

DATE:=$(shell date +%Y-%m-%d-%H-%M-%S)
DIR?=trace/$(DATE)
TRACEE?=tests/fib
TRACEE_ARGS?=

all: $(CS_PROXY) $(PROC_TRACE) $(TESTS)

decode: $(CSDEC) trace
	$(realpath $(CSDEC)) $(shell cat $(DIR)/decoderargs.txt)

trace: $(PROC_TRACE) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(PROC_TRACE)) $(PROC_TRACE_FLAGS) -- $(realpath $(TRACEE)) $(TRACEE_ARGS)

debug: $(PROC_TRACE) $(TESTS)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo gdb --args $(realpath $(PROC_TRACE)) $(PROC_TRACE_FLAGS) -- $(realpath $(TRACEE)) $(TRACEE_ARGS)

$(LIBCSDEC):
	$(MAKE) -C $(CSDEC_BASE)

$(CSDEC): $(LIBCSDEC)

$(CS_PROXY): $(CS_PROXY_OBJS) $(LIBCSACCESS) $(LIBCSACCUTIL) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(CFLAGS)

$(PROC_TRACE): $(PROC_TRACE_OBJS) $(LIBCSACCESS) $(LIBCSACCUTIL) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(CFLAGS)

libcsal:
	$(MAKE) -C $(CSAL_BASE) $(CSAL_FLAGS)

$(LIBCSACCESS): libcsal
$(LIBCSACCUTIL): libcsal

clean:
	rm -f $(CS_PROXY_OBJS) $(CS_PROXY) $(PROC_TRACE_OBJS) $(PROC_TRACE) $(TESTS)

dist-clean: clean
	$(MAKE) -C $(CSAL_BASE) clean $(CSAL_FLAGS)
	$(MAKE) -C $(CSDEC_BASE) clean

.PHONY: all trace debug decode libcsal clean dist-clean
