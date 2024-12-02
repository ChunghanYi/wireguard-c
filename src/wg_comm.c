/*
 * Proxy routines between UDP socket and TUN device
 *
 * Copyright (c) 2024 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wg_main.h"

#include <time.h>
#include <pthread.h>

#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

#include "wg_comm.h"
#include "wg_tun.h"
#include "wireguardif.h"
#include "lwip_h/ip4.h"
#include "lib/pthread_wrap.h"
#include "lib/log.h"

extern struct netif *wg_netif;

/* Initialise a timeval structure to use with select */
static inline void init_timeout(struct timeval *timeout) {
	timeout->tv_sec = SELECT_DELAY_SEC;
	timeout->tv_usec = SELECT_DELAY_USEC;
}

/* Create the UDP socket
 * Bind it to config.localIP
 *            config.localport (localport > 0)
 *            config.iface (iface != NULL)
 */
int create_socket(void) {
	int sockfd;
	struct sockaddr_in localaddr, tmp_addr;
	socklen_t tmp_addr_len;

	/* Socket creation */
	log_message_level(2, "Creating the UDP socket...");
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_error(errno, "Could not create the socket");
		return -1;
	}

#ifdef HAVE_LINUX
	if (config.iface != NULL) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		if (strlen(config.iface) + 1 > IFNAMSIZ) {
			log_message("The interface name '%s' is too long", config.iface);
			return -1;
		}
		strcpy(ifr.ifr_name, config.iface);
		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
			log_error(errno, "Could not bind the socket to the interface (%s)", config.iface);
			return -1;
		}
	}
#endif

	memset(&localaddr, 0, sizeof(localaddr));
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = config.localIP.s_addr;
	if (config.localport != 0) localaddr.sin_port = htons(config.localport);
	if (bind(sockfd, (struct sockaddr *)&localaddr, sizeof(localaddr)) < 0) {
		log_error(errno,
				"Could not bind the socket to the local IP address (%s port %u)",
				inet_ntoa(config.localIP), config.localport);
		return -1;
	}
	log_message_level(2, "Socket opened");

	/* Get the local port */
	if (config.localport == 0) {
		tmp_addr_len = sizeof(tmp_addr);
		getsockname(sockfd, (struct sockaddr *) &tmp_addr, &tmp_addr_len);
		config.localport = ntohs(tmp_addr.sin_port);
	}

	return sockfd;
}

/*
 * Manage the incoming messages(VPN packets) from the UDP socket
 * argument: struct comm_args *
 */
static void *comm_socket(void *argument) {
	struct comm_args * args = argument;
	struct wireguard_device *device = args->device;
	int sockfd = args->sockfd;

	int r;
	int r_select;
	fd_set fd_select;                           // for the select call
	struct timeval timeout;                     // timeout used with select
	struct pbuf u;
	struct sockaddr_in unknownaddr;             // address of the sender
	socklen_t len = sizeof(struct sockaddr_in);
	ip_addr_t addr;

	size_t u_len = 1<<13;  // 8192
	u.payload = CHECK_ALLOC_FATAL(malloc(u_len));

	while (!end_wireguard) {
		/* select call initialisation */
		FD_ZERO(&fd_select);
		FD_SET(sockfd, &fd_select);

		init_timeout(&timeout);
		r_select = select(sockfd+1, &fd_select, NULL, NULL, &timeout);

		/* MESSAGE READ FROM THE SOCKET */
		if (r_select > 0) {
			while ((r = (int) recvfrom(sockfd, u.payload, u_len,
							0, (struct sockaddr *)&unknownaddr, &len)) != -1) {
				/* Message from another peer */
				if (config.debug)
					log_message("<<  Received a UDP packet: size %d from %s:%d",
							r, inet_ntoa(unknownaddr.sin_addr), ntohs(unknownaddr.sin_port));

				u.len = u.tot_len = r;
				addr.u_addr.ip4.addr = unknownaddr.sin_addr.s_addr;
				wireguardif_network_rx(device, &u, &addr, ntohs(unknownaddr.sin_port));
			}
		}
	}

	if (u.payload)
		free(u.payload);
	return NULL;
}

/*
 * Manage the incoming messages from the TUN device
 * argument: struct comm_args *
 */
static void *comm_tun(void *argument) {
	struct comm_args *args = argument;
	int tunfd = args->tunfd;
	int r;
	int r_select;
	fd_set fd_select;            // for the select call
	struct timeval timeout;      // timeout used with select
	struct pbuf u;
	ip_addr_t addr;
	struct ip_hdr *ip;

	u.payload = CHECK_ALLOC_FATAL(malloc(MESSAGE_MAX_LENGTH));

	while (!end_wireguard) {
		/* select call initialisation */
		init_timeout(&timeout);
		FD_ZERO(&fd_select);
		FD_SET(tunfd, &fd_select);
		r_select = select(tunfd+1, &fd_select, NULL, NULL, &timeout);

		/* MESSAGE READ FROM TUN DEVICE */
		if (r_select > 0) {
			r = (int) read_tun(tunfd, u.payload, MESSAGE_MAX_LENGTH);

			ip = (struct ip_hdr *)u.payload;
			if (config.debug) {
				log_message("<< Sending a VPN message: size %d from SRC = %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32" to DST = %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"",
						r,
						(ntohl(ip->src.addr)  >> 24) & 0xFF,
						(ntohl(ip->src.addr)  >> 16) & 0xFF,
						(ntohl(ip->src.addr)  >>  8) & 0xFF,
						(ntohl(ip->src.addr)  >>  0) & 0xFF,
						(ntohl(ip->dest.addr) >> 24) & 0xFF,
						(ntohl(ip->dest.addr) >> 16) & 0xFF,
						(ntohl(ip->dest.addr) >>  8) & 0xFF,
						(ntohl(ip->dest.addr) >>  0) & 0xFF);
			}

			u.len = u.tot_len = r;
			addr.u_addr.ip4.addr = ip->dest.addr;
			wireguardif_output(wg_netif, &u, &addr);
		}
	}

	if (u.payload)
		free(u.payload);
	return NULL;
}

/*
 * Start the VPN:
 * start a thread running comm_tun and another one running comm_socket
 *
 * set end_wireguard to 1 in order to stop both threads
 */
int start_vpn(struct netif *netif) {
	struct comm_args args;
	pthread_t th_socket;
	pthread_t th_tun;

	args.sockfd = netif->sockfd;
	args.tunfd = netif->tunfd;
	args.device = (struct wireguard_device *)(netif->state);

	/* peer vpn -> eth0 -> wg_decrypt -> tun0 -> host application */
	th_socket = createThread(comm_socket, &args);
	log_message_level(2, "thread id for comm_socket thread is (%ld)", th_socket);

	/* host application -> tun0 -> wg_encrypt -> eth0 -> peer vpn */
	th_tun = createThread(comm_tun, &args);
	log_message_level(2, "thread id for comm_tun thread is (%ld)", th_tun);

	joinThread(th_socket, NULL);
	joinThread(th_tun, NULL);

	return 0;
}
