CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
LIBS    = -lsodium -lpthread

SHARED_SRC = src/logger.c src/net.c src/crypto.c
SHARED_OBJ = $(SHARED_SRC:.c=.o)

RENDEZVOUS_SRC = $(SHARED_SRC) src/rendezvous.c src/protocol.c src/room.c
RENDEZVOUS_OBJ = $(RENDEZVOUS_SRC:.c=.o)

PEER_SRC = $(SHARED_SRC) src/peer.c src/identity.c
PEER_OBJ = $(PEER_SRC:.c=.o)

.PHONY: all clean

all: rendezvous peer test/echo_client

rendezvous: $(RENDEZVOUS_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

peer: $(PEER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test/echo_client: test/echo_client.o $(SHARED_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $

# Header dependencies
src/rendezvous.o:    src/rendezvous.c    include/logger.h include/net.h \
                                          include/crypto.h include/protocol.h \
                                          include/room.h
src/protocol.o:      src/protocol.c      include/protocol.h include/msgtype.h \
                                          include/logger.h include/crypto.h \
                                          include/room.h
src/room.o:          src/room.c          include/room.h include/logger.h \
                                          include/crypto.h
src/peer.o:          src/peer.c          include/logger.h include/net.h \
                                          include/crypto.h include/msgtype.h \
                                          include/identity.h include/room.h
src/identity.o:      src/identity.c      include/identity.h include/logger.h
src/crypto.o:        src/crypto.c        include/crypto.h include/net.h \
                                          include/logger.h
src/net.o:           src/net.c           include/net.h include/logger.h
src/logger.o:        src/logger.c        include/logger.h
test/echo_client.o:  test/echo_client.c  include/logger.h include/net.h \
                                          include/crypto.h include/msgtype.h

clean:
	rm -f rendezvous peer test/echo_client src/*.o test/*.o
