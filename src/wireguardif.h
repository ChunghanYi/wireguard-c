/*
 * Porting for Linux userspace
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 */
/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */


#ifndef _WIREGUARDIF_H_
#define _WIREGUARDIF_H_

#include <stddef.h>
#include "lwip_h/arch.h"
#include "lwip_h/ip_addr.h"
#include "wg_config.h"

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)
#define WIREGUARDIF_KEEPALIVE_DEFAULT	(0xFFFF)

typedef struct netif {
	int sockfd;
	int tunfd;
	void *state;
	timer_t *timer;
} netif_t;

struct pbuf {
	/** next pbuf in singly linked pbuf chain */
	//struct pbuf *next;

	/** pointer to the actual data in the buffer */
	void *payload;

	/**
	 * total length of this buffer and all next buffers in chain
	 * belonging to the same packet.
	 *
	 * For non-queue packet chains this is the invariant:
	 * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
	 */
	u16_t tot_len;

	/** length of this buffer */
	u16_t len;
};

struct wireguardif_init_data {
	// Required: the private key of this WireGuard network interface
	const char *private_key;
	// Required: What UDP port to listen on
	u16_t listen_port;
};

struct wireguardif_peer {
#if 0
	const char *public_key;
#else
	char public_key[WG_KEY_LEN_BASE64];
#endif
	// Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
	const uint8_t *preshared_key;
	// tai64n of largest timestamp we have seen during handshake to avoid replays
	uint8_t greatest_timestamp[12];

	// Allowed ip/netmask (can add additional later but at least one is required)
	ip_addr_t allowed_ip;
	ip_addr_t allowed_mask;

	// End-point details (may be blank)
	ip_addr_t endpoint_ip;
	u16_t endport_port;
	u16_t keep_alive;
};

#define WIREGUARDIF_INVALID_INDEX (0xFF)

// Initialise a new WireGuard network interface (netif)
err_t wireguardif_init(struct netif *netif);

// rx(eth0 -> tun0)
void wireguardif_network_rx(void *arg, struct pbuf *p, const ip_addr_t *addr, u16_t port);

// tx(-> eth0)
err_t wireguardif_output(struct netif *netif, struct pbuf *q, const ip_addr_t *ipaddr);

// Helper to initialise the peer struct with defaults
void wireguardif_peer_init(struct wireguardif_peer *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardif_add_peer(struct netif *netif, struct wireguardif_peer *peer, u8_t *peer_index);

// Remove the given peer from the network interface
err_t wireguardif_remove_peer(struct netif *netif, u8_t peer_index);

// Update the "connect" IP of the given peer
err_t wireguardif_update_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port);

// Try and connect to the given peer
err_t wireguardif_connect(struct netif *netif, u8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardif_disconnect(struct netif *netif, u8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);

#endif /* _WIREGUARDIF_H_ */
