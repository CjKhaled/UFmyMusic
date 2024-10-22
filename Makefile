#################################################################
##
## FILE:	Makefile
## PROJECT:	CNT 4007 Project 1 - Professor Traynor
## DESCRIPTION: Compile Project 1
##
#################################################################

CC=gcc

OS := $(shell uname -s)

# Extra LDFLAGS if Solaris
ifeq ($(OS), SunOS)
	LDFLAGS=-lsocket -lnsl
    endif

all: client server 

# for some reason, client won't build unless forced to
.PHONY: client server clean

client: ./client/client-f.c
	$(CC) ./client/client-f.c -o requestor -lcrypto

server: ./server/server-f.c
	$(CC) ./server/server-f.c -o resolver -lcrypto

clean:
	rm -f requestor resolver *.o


