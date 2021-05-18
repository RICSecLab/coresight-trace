#!/usr/bin/env make

SHELL:=bash

CSAL_BASE:=CSAL
CSAL_ARCH:=arm64
CSAL_BUILD:=dbg
CSAL_INC:=$(CSAL_BASE)/include
CSAL_LIB:=$(CSAL_BASE)/lib/$(CSAL_ARCH)/$(CSAL_BUILD)
CSAL_DEMO:=$(CSAL_BASE)/demos
LIBCSACCESS:=$(CSAL_LIB)/libcsaccess.a
LIBCSACCUTIL:=$(CSAL_LIB)/libcsacc_util.a
CSKNOWNBOARDS:=$(CSAL_DEMO)/$(CSAL_BUILD)-$(CSAL_ARCH)/cs_demo_known_boards.o

CFLAGS:=-I$(CSAL_INC) -I$(CSAL_DEMO)

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)
TARGET:=proc-trace

all: $(TARGET)

run: $(TARGET)
	./$(TARGET) /bin/ls /

$(TARGET): $(OBJS) $(CSKNOWNBOARDS) $(LIBCSACCESS) $(LIBCSACCUTIL)
	$(CC) -o $@ $^

$(LIBCSACCESS):
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) DEBUG=1 # TODO

$(LIBCSACCUTIL):
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) DEBUG=1 # TODO

clean:
	rm -f *.o $(TARGET)

.PHONY: all run clean
