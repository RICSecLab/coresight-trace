#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

SHELL:=bash

DEFAULT_BOARD?="Marvell ThunderX2"

CSAL_BASE:=CSAL
CSAL_ARCH:=arm64
ifneq ($(strip $(DEBUG)),)
  CSAL_BUILD:=dbg
else
  CSAL_BUILD:=rel
endif
CSAL_INC:=$(CSAL_BASE)/include
CSAL_LIB:=$(CSAL_BASE)/lib/$(CSAL_ARCH)/$(CSAL_BUILD)
CSAL_FLAGS:=ARCH=$(CSAL_ARCH) NO_DIAG=1 NO_CHECK=1
LIBCSACCESS:=$(CSAL_LIB)/libcsaccess.a
LIBCSACCUTIL:=$(CSAL_LIB)/libcsacc_util.a

CSDEC_BASE:=coresight-decoder
CSDEC:=$(CSDEC_BASE)/processor
CSDEC_INC:=$(CSDEC_BASE)/include
LIBCSDEC:=$(CSDEC_BASE)/libcsdec.a

UDMABUF_BASE:=udmabuf
UDMABUF_KMOD:=$(UDMABUF_BASE)/u-dma-buf.ko
UDMABUF_BUF_PATH:=/dev/udmabuf0
UDMABUF_BUF_SIZE:=0x80000

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
  -DDEFAULT_BOARD_NAME=\"$(DEFAULT_BOARD)\" \
  -I$(INC) \
  -I$(CSAL_INC) \
  -I$(CSDEC_INC) \
  -lpthread \
  -lcapstone \

ifneq ($(strip $(DEBUG)),)
  CFLAGS+=-g -O0
else
  CFLAGS+=-Ofast
endif

CS_PROXY_OBJS:= \
  $(COMMON_OBJS) \
  src/cs-proxy.o \

CS_PROXY:=cs-proxy

CS_TRACE_OBJS:= \
  $(COMMON_OBJS) \
  src/cs-trace.o \

CS_TRACE:=cs-trace
CS_TRACE_FLAGS?=

ifneq ($(strip $(DEBUG)),)
  CS_TRACE_FLAGS+=--export --verbose=0
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

all: $(CS_TRACE) $(TESTS)
ifeq ($(shell test -d $(INC)/afl/; echo $$?),0)
all: $(CS_PROXY)
endif

decode: $(CSDEC) trace
	$(realpath $(CSDEC)) $(shell cat $(DIR)/decoderargs.txt)

trace: $(CS_TRACE) $(TESTS) | $(UDMABUF_BUF_PATH)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo $(realpath $(CS_TRACE)) $(CS_TRACE_FLAGS) -- $(realpath $(TRACEE)) $(TRACEE_ARGS)

debug: $(CS_TRACE) $(TESTS) | $(UDMABUF_BUF_PATH)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo gdb --args $(realpath $(CS_TRACE)) $(CS_TRACE_FLAGS) -- $(realpath $(TRACEE)) $(TRACEE_ARGS)

$(LIBCSDEC):
	$(MAKE) -C $(CSDEC_BASE)

$(CSDEC): $(LIBCSDEC)

$(CS_PROXY): $(CS_PROXY_OBJS) $(LIBCSACCESS) $(LIBCSACCUTIL) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(CFLAGS)

$(CS_TRACE): $(CS_TRACE_OBJS) $(LIBCSACCESS) $(LIBCSACCUTIL) $(LIBCSDEC)
	$(CXX) -o $@ $^ $(CFLAGS)

libcsal:
	$(MAKE) -C $(CSAL_BASE) $(CSAL_FLAGS)

$(LIBCSACCESS): libcsal
$(LIBCSACCUTIL): libcsal

$(UDMABUF_KMOD):
	$(MAKE) -C $(UDMABUF_BASE)

$(UDMABUF_BUF_PATH): | $(UDMABUF_KMOD)
	sudo insmod $^ $(notdir $@)=$(UDMABUF_BUF_SIZE)

clean:
	rm -f $(CS_PROXY_OBJS) $(CS_PROXY) $(CS_TRACE_OBJS) $(CS_TRACE) $(TESTS)

dist-clean: clean
	$(MAKE) -C $(CSAL_BASE) clean $(CSAL_FLAGS)
	$(MAKE) -C $(CSDEC_BASE) clean
	$(MAKE) -C $(UDMABUF_BASE) clean

.PHONY: all trace debug decode libcsal clean dist-clean
