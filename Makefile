#!/usr/bin/env make

SHELL := bash

TARGET = proc-trace

all: $(TARGET)

run: $(TARGET)
	./$(TARGET) /bin/ls /

$(TARGET): main.c
	$(CC) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all run clean
