/*
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WG_CONFIG_H_
#define _WG_CONFIG_H_

#define WG_KEY_LEN 32
#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)   // from encoding.h

struct configuration {
    int verbose;                                // verbose
    int debug;                                  // more verbose
    int daemonize;                              // daemonize the client

    uint16_t localport;                         // local UDP port(VPN port)
    uint16_t peerport;                          // peer UDP port(VPN port)

    struct in_addr localIP;                     // local IP address
    struct in_addr vpnIP;                       // my VPN IP address
    struct in_addr vpnNetmask;                  // my VPN Netmask
	int vpnNetmask_CIDR;                        // CCTV VPN Netmask CIDR
    char *network;                              // my VPN subnetwork as a string

	struct in_addr peer_vpnIP;                  // peer VPN IP address
	struct in_addr epIP;                        // endpoint IP address (IPv4)
	uint8_t allowed_ips[128];                   // peer allowed ips(networks)

	uint8_t private_key[WG_KEY_LEN_BASE64];     // my vpn private key
	uint8_t public_key[WG_KEY_LEN_BASE64];      // peer vpn public key

    int tun_mtu;                                // MTU of the tun device
    char *iface;                                // bind to a specific network interface
    char *tun_device;                           // The name of the TUN interface

    int timeout;                                // wait timeout secs before closing a session for inactivity
    unsigned int keepalive;                     // seconds between keepalive messages;
    char ** exec_up;                            // UP commands
    char ** exec_down;                          // DOWN commands

    char *pidfile;                              // PID file in daemon mode

#ifdef HAVE_LINUX
    int txqueue;                                // TX queue length for the TUN device (0 means default)
    int tun_one_queue;                          // Single queue mode
#endif
};

extern void initConfig(void);
extern int parse_conf_file(const char *file);
extern void freeConfig(void);

#endif /*_WG_CONFIG_H_*/
