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

CSD_BASE:=OpenCSD
CSD_PLAT:=linux-arm64
CSD_BUILD:=rel
CSD_DECODER:=$(CSD_BASE)/decoder/tests/bin/$(CSD_PLAT)/$(CSD_BUILD)/trc_pkt_lister_s

CFLAGS:=-I$(CSAL_INC) -I$(CSAL_DEMO)

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)
TARGET:=proc-trace

TEST=/bin/ls
TEST_ARG="/"

all: $(TARGET)

trace: $(TARGET) $(CSD_DECODER)
	mkdir -p $(DIR) && \
	cd $(DIR) && \
	sudo ../$(TARGET) $(TEST) $(TEST_ARG) && \
	../$(CSD_DECODER) -ss_dir .

run: $(TARGET)
	sudo ./$(TARGET) $(TEST) $(TEST_ARG)

$(TARGET): $(OBJS) $(CSKNOWNBOARDS) $(LIBCSACCESS) $(LIBCSACCUTIL)
	$(CC) -o $@ $^

$(CSD_DECODER):
	$(MAKE) -C $(CSD_BASE)/decoder/build/linux -f makefile.dev

$(CSKNOWNBOARDS):
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) DEBUG=1 # TODO

$(LIBCSACCESS):
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) DEBUG=1 # TODO

$(LIBCSACCUTIL):
	$(MAKE) -C $(CSAL_BASE) ARCH=$(CSAL_ARCH) DEBUG=1 # TODO

clean:
	rm -f *.o $(TARGET)

.PHONY: all run clean
