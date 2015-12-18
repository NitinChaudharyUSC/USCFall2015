# Makefile for EE450 fall2015 project
# author: nchaudha@usc.edu

# the compiler: gcc for C program
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall

#includes commonly needed dependencies
DEPS = -lnsl -lsocket -lresolv -lpthread

all: server client

#the server executable
server: server.c server.h client.h
	$(CC) -o server server.c $(DEPS)

#the client executable
client: client.c client.h server.h
	$(CC) -o client client.c $(DEPS)
