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

#include <stdio.h>
#include <string.h>

#include "wireguardif.h"
#include "wireguard.h"

#include "wireguard_vpn.h"
#include "wg_main.h"
#include "wg_timer.h"

#if !defined(WG_CLIENT_PRIVATE_KEY) || !defined(WG_PEER_PUBLIC_KEY)
#error "Please update configuratiuon with your VPN-specific keys!"
#endif

extern struct netif *wg_netif;
static uint8_t wireguard_peer_index_local = WIREGUARDIF_INVALID_INDEX;

int wireguard_setup(void) {
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	union {
		uint32_t ip32;
		uint8_t ip8[4];
	} u;

	u.ip32 = config.epIP.s_addr; /* endpoint ip address */
	const ip_addr_t peer_address = IPADDR4_INIT_BYTES(u.ip8[0], u.ip8[1], u.ip8[2], u.ip8[3]);

	// Setup the WireGuard device structure
	wg.private_key = (const char *)config.private_key;

	wg.listen_port = config.localport;

	// Register the new WireGuard network interface
	wg_netif = (struct netif *)malloc(sizeof(struct netif));
	if (wg_netif == NULL)
		return -1;
	wg_netif->state = &wg;

	wireguardif_init(wg_netif);

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(&peer);
	memset(peer.public_key, 0, WG_KEY_LEN_BASE64);
	memcpy(peer.public_key, config.public_key, WG_KEY_LEN_BASE64-1);
	peer.preshared_key = NULL;

	// Allow all IPs through tunnel
	//peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
	IP_ADDR4(&peer.allowed_ip, 0, 0, 0, 0);
	IP_ADDR4(&peer.allowed_mask, 0, 0, 0, 0);

	// If we know the endpoint's address can add here
	ip_addr_set(&peer.endpoint_ip, &peer_address);
	peer.endport_port = config.peerport;

	// Register the new WireGuard peer with the netwok interface
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index_local);

	if ((wireguard_peer_index_local != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
		// Start outbound connection to peer
		wireguardif_connect(wg_netif, wireguard_peer_index_local);
	}

	return 0;
}
