# OpenP2P -- Makefile
#
# Targets:
#   make          build optimized binaries (default)
#   make debug    -O0 -g, no sanitizers, for gdb
#   make asan     -O0 -g + AddressSanitizer + stack protector
#   make clean    remove all build artifacts
#
# Layout:
#   src/*.c      sources (one main per binary)
#   include/*.h  headers
#   build/       all .o files land here, mirroring src/ layout

CC      := gcc
CSTD    := -std=gnu11
WARN    := -Wall -Wextra -Wpedantic
INC     := -Iinclude
LIBS    := -lsodium -lpthread

CFLAGS  ?= -O2

# ── source layout ─────────────────────────────────────────────────────

# Files shared by both binaries.
SHARED_SRC := \
	src/logger.c \
	src/net.c \
	src/crypto.c

# Rendezvous-only sources.
RENDEZVOUS_SRC := \
	src/rendezvous.c \
	src/protocol.c \
	src/room.c

# Peer-only sources.
PEER_SRC := \
	src/peer.c \
	src/identity.c \
	src/holepunch.c \
	src/chat.c \
	src/file_offer.c \
	src/file_stream.c \
	src/progress.c \
	src/proxy.c

# ── object file paths ─────────────────────────────────────────────────
# Mirror source layout under build/. e.g. src/crypto.c -> build/src/crypto.o

SHARED_OBJ     := $(SHARED_SRC:%.c=build/%.o)
RENDEZVOUS_OBJ := $(RENDEZVOUS_SRC:%.c=build/%.o)
PEER_OBJ       := $(PEER_SRC:%.c=build/%.o)

ALL_OBJ := $(SHARED_OBJ) $(RENDEZVOUS_OBJ) $(PEER_OBJ)

# ── top-level targets ─────────────────────────────────────────────────

.PHONY: all clean debug asan
.DEFAULT_GOAL := all

all: rendezvous peer

debug: CFLAGS := -O0 -g
debug: clean all

asan: CFLAGS := -O0 -g -fsanitize=address -fstack-protector-all
asan: LIBS   += -fsanitize=address
asan: clean all

# ── linking ───────────────────────────────────────────────────────────

rendezvous: $(SHARED_OBJ) $(RENDEZVOUS_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

peer: $(SHARED_OBJ) $(PEER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# ── compilation ───────────────────────────────────────────────────────

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(INC) $(CFLAGS) -c -o $@ $<

# ── header dependencies ───────────────────────────────────────────────

build/src/logger.o:     include/logger.h
build/src/net.o:        include/logger.h    include/typedefs.h                   include/net.h
build/src/proxy.o: 	include/logger.h    include/typedefs.h  include/proxy.h
build/src/crypto.o:     include/logger.h    include/typedefs.h  include/crypto.h include/net.h
build/src/room.o:       include/logger.h    include/typedefs.h  include/crypto.h include/room.h
build/src/protocol.o:   include/logger.h    include/typedefs.h  include/crypto.h include/room.h   include/protocol.h  include/msgtype.h
build/src/rendezvous.o: include/logger.h    include/typedefs.h  include/crypto.h include/room.h   include/protocol.h  include/net.h
build/src/identity.o:   include/logger.h    include/typedefs.h  include/identity.h
build/src/holepunch.o:  include/logger.h    include/typedefs.h  include/holepunch.h include/net.h
build/src/chat.o: 	include/logger.h    include/typedefs.h  include/crypto.h include/chat.h   include/msgtype.h include/file_offer.h include/file_stream.h
build/src/file_offer.o: include/logger.h    include/typedefs.h  include/file_offer.h
build/src/file_stream.o:include/logger.h    include/typedefs.h  include/crypto.h include/file_stream.h include/file_offer.h include/msgtype.h
build/src/progress.o:   include/progress.h  include/typedefs.h
build/src/peer.o:       include/logger.h    include/typedefs.h  include/crypto.h \
                        include/msgtype.h   include/identity.h  include/room.h \
                        include/holepunch.h include/net.h

# ── cleanup ───────────────────────────────────────────────────────────

clean:
	rm -rf build rendezvous peer
