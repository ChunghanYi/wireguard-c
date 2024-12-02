/*
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WG_COMM_H_
#define _WG_COMM_H_

#include <errno.h>
#include "wireguard.h"
#include "lwip_h/ip_addr.h"

/*
 * duration of the timeout used with the select calls*/
#define SELECT_DELAY_SEC 2
#define SELECT_DELAY_USEC 0

#define TUN_MTU_DEFAULT 1420
#define MESSAGE_MAX_LENGTH 1500

#define MAC_ADDR_LEN 6
#define SERIAL_NUMBER_LEN 128
#define ALLOWED_IPS_LEN 512

struct wgallowedip {
	uint16_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint8_t cidr;
	struct wgallowedip *next_allowedip;
};

/* arguments for the comm_tun and comm_socket threads */
struct comm_args {
    int sockfd;
    int tunfd;
    struct wireguard_device *device;
};

int start_vpn();
int create_socket(void);

#endif /*_WG_COMM_H_*/
