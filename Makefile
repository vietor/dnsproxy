# Makefile for dnsproxy

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC = gcc
CFLAGS = -O2 -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS =

TARGET = dnsproxy
INCLUDES = $(wildcard *.h embed/*.h)
SOURCES = $(wildcard *.c embed/*.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

ifneq (,$(findstring MINGW,$(uname_S)))
	CFLAGS +=
	LDFLAGS += -lws2_32 -lmswsock
	TARGET := $(TARGET).exe
endif

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(SOURCES) $(INCLUDES)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(LDFLAGS)

clean:
	$(RM) *.o embed/*.o *~ $(TARGET)
