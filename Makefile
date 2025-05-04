.PHONY: all clean debug

CC=gcc
CFLAGS=-Wall -Wextra
DEBUG_FLAGS=-g -O0

all: mytar

mytar: mytar.c
	$(CC) $(CFLAGS) mytar.c -o mytar

debug: mytar.c
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) mytar.c -o mytar

clean:
	rm -f mytar
