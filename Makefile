CC      ?= cc
CFLAGS  = -Wall -Wextra -std=gnu11 -O2 -g
TARGET  = mytraceroute

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=build/%.o)
HDRS = $(wildcard src/*.h)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

build/%.o: src/%.c $(HDRS) | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

LIB_OBJS = $(filter-out build/traceroute.o,$(OBJS))

build/test_packets: tests/test_packets.c $(LIB_OBJS) $(HDRS) | build
	$(CC) $(CFLAGS) -o $@ tests/test_packets.c $(LIB_OBJS)

test: build/test_packets
	./build/test_packets

clean:
	rm -rf build $(TARGET)

.PHONY: all clean test
