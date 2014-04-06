# Makefile for AE-TEST

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC = gcc
CFLAGS = -O2 -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS =

TARGET = dnsproxy
INCLUDES = $(wildcard *.h)
SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

ifeq ($(uname_S),Linux)
	CFLAGS +=
	LDFLAGS +=
else
ifeq ($(uname_S),FreeBSD)
	CFLAGS +=
	LDFLAGS +=
else
ifneq (,$(findstring MINGW,$(uname_S)))
	CFLAGS +=
	LDFLAGS += -lws2_32 -lmswsock
	TARGET := $(TARGET).exe
else
	$(error Unsupport platform for compile)
endif
endif
endif

all: build

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(SOURCES) $(INCLUDES)

build: $(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(LDFLAGS)

clean:
	$(RM) *.o *~ $(TARGET)
