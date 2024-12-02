#
# Makefile for the linux userspace wireguard daemon implemented with C
#
# Copyright (c) 2024 Chunghan Yi <chunghan.yi@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#

#CROSS   = aarch64-openwrt-linux-musl-
CROSS   =
CC      = $(CROSS)gcc
STRIP	= strip
MAKE	= make
CP		= cp
RM		= rm
LIBS	= -lpthread

CFLAGS	= -W -Wall -D_GNU_SOURCE -g
OFLAGS  = -W -Wall -D_GNU_SOURCE -g

TARGET	= wireguard

.SUFFIXES: .c .cpp .o .O .h

.c.o:
	$(CC) $(OFLAGS) -c $< -o $@

all	:	$(TARGET)

$(TARGET):	wg_main.o \
			wg_comm.o \
			wg_config.o \
			wg_tun.o \
			wireguard_vpn.o \
			wireguardif.o \
			wireguard.o \
			wireguard-platform.o \
			wg_timer.o \
			crypto.o \
			crypto/blake2s.o \
			crypto/chacha20.o \
			crypto/chacha20poly1305.o \
			crypto/poly1305-donna.o \
			crypto/x25519.o \
			lib/log.o \
			lib/strlib.o
	$(CC) $(CFLAGS)	-o $@ $^ $(LIBS)

strip:
	$(STRIP) $(TARGET)

clean:
	$(RM) -rf *.o crypto/*.o lib/*.o $(TARGET)

install:
	$(STRIP) $(TARGET)
