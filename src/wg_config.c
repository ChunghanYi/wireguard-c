/*
 * Create the "config" structure containing all the configuration variables
 *
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wg_main.h"
#include "wg_config.h"
#include "wg_comm.h"
#include "wireguard_vpn.h"
#include "lib/log.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

struct configuration config;

/* set default values in config */
void initConfig() {
	config.verbose = 0;
	config.daemonize = 0;
	config.debug = 0;

	memset(&config.localIP, 0, sizeof(config.localIP));

	config.localport = WG_CLIENT_PORT;
	config.peerport = WG_PEER_PORT;

	memset(&config.vpnIP, 0, sizeof(config.vpnIP));
	const ip_addr_t ipaddr = WG_LOCAL_ADDRESS;
	config.vpnIP.s_addr = ipaddr.u_addr.ip4.addr;

	memset(&config.vpnNetmask, 0, sizeof(config.vpnNetmask));
	const ip_addr_t netmask = WG_LOCAL_NETMASK;
	config.vpnNetmask.s_addr = netmask.u_addr.ip4.addr;
	config.vpnNetmask_CIDR = 24;

	config.network = CHECK_ALLOC_FATAL("10.1.1.0/24");

	memset(&config.peer_vpnIP, 0, sizeof(config.peer_vpnIP));
	memset(config.allowed_ips, 0, sizeof(config.allowed_ips));

	config.tun_mtu = TUN_MTU_DEFAULT;
	config.iface = NULL;
	config.tun_device = CHECK_ALLOC_FATAL("tun0");

	config.exec_up = NULL;
	config.exec_down = NULL;

	config.pidfile = NULL;

#ifdef HAVE_LINUX
	config.txqueue = 0;
	config.tun_one_queue = 0;
#endif
}

#ifdef HAVE_IFADDRS_H
/*
 * Search the local IP address to use. Copy it into "ip" and set "localIPset".
 * If iface != NULL, get the IP associated with the given interface
 * Otherwise search the IP of the first non loopback interface
 */
static int get_local_IP(struct in_addr * ip, int *localIPset, char *iface) {
	struct ifaddrs *ifap = NULL, *ifap_first = NULL;
	if (getifaddrs(&ifap) != 0) {
		log_error(errno, "getifaddrs");
		return -1;
	}

	ifap_first = ifap;
	while (ifap != NULL) {
		if (iface == NULL && ((ifap->ifa_flags & IFF_LOOPBACK)
					|| !(ifap->ifa_flags & IFF_RUNNING)
					|| !(ifap->ifa_flags & IFF_UP))) {
			ifap = ifap->ifa_next;
			continue; // local or not running interface, skip it
		}
		if (iface == NULL || strcmp(ifap->ifa_name, iface) == 0) {
			/* If the interface has no link level address (like a TUN device),
			 * then ifap->ifa_addr is NULL.
			 * Only look for AF_INET addresses
			 */
			if (ifap->ifa_addr != NULL && ifap->ifa_addr->sa_family == AF_INET) {
				*ip = (((struct sockaddr_in *) ifap->ifa_addr)->sin_addr);
				*localIPset = 1;
				break;
			}
		}
		ifap = ifap->ifa_next;
	}
	freeifaddrs(ifap_first);
	return 0;
}
#endif

int parse_conf_file(const char *file) {
	FILE *fp = NULL;
	char xbuf[1024];
	char *s = NULL;
	char *saveptr; // Initialize our save pointers to save the context of tokens
	int ret = -1;

	fp = fopen(file, "r");
	if (fp) {
		memset(xbuf, 0, sizeof(xbuf));
		while (fgets(xbuf, sizeof(xbuf), fp)) {
			xbuf[strlen(xbuf)-1] = '\0';
			if (xbuf[0] == '#' || xbuf[0] == '\0') {
				memset(xbuf, 0, sizeof(xbuf));
				continue;
			}
			s = strtok_r(xbuf, "=", &saveptr);
			if (s) {
				if (!strcmp(s, "debug")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					config.debug = atoi(s);

				} else if (!strcmp(s, "my_vpn_ip_address")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					inet_pton(AF_INET, s, &(config.vpnIP));

				} else if (!strcmp(s, "my_vpn_netmask")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					inet_pton(AF_INET, s, &(config.vpnNetmask));

				} else if (!strcmp(s, "my_vpn_netmask_CIDR")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					config.vpnNetmask_CIDR = atoi(s);

				} else if (!strcmp(s, "peer_vpn_ip_address")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					inet_pton(AF_INET, s, &(config.peer_vpnIP));

				} else if (!strcmp(s, "endpoint_ip_address")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					inet_pton(AF_INET, s, &(config.epIP));

				} else if (!strcmp(s, "local_wg_port")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					config.localport = atoi(s);

				} else if (!strcmp(s, "peer_wg_port")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					config.peerport = atoi(s);

				} else if (!strcmp(s, "local_wg_private_key")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					memset(config.private_key, '\0', WG_KEY_LEN_BASE64);
					sprintf((char *)config.private_key, "%s=", &s[1]);

				} else if (!strcmp(s, "peer_wg_public_key")) {
					s = strtok_r(NULL, "=", &saveptr);
					if (s == NULL) continue;
					memset(config.public_key, '\0', WG_KEY_LEN_BASE64);
					sprintf((char *)config.public_key, "%s=", &s[1]);
				}
			}

			memset(xbuf, 0, sizeof(xbuf));
		}
		fclose(fp);
		ret = 0;
	}

	return ret;
}

void freeConfig() {
}
