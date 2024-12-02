/*
 * Create and configure a TUN device
 *
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wg_main.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include "wg_config.h"
#include "wg_comm.h"
#include "wg_tun.h"
#include "lib/log.h"
#include "lib/strlib.h"

static char *device;

const char *tun_default_up[] = {
	"ifconfig %D %V mtu %M up",
	"ip route replace %N via %V || route add -net %N gw %V",
	NULL
};
const char *tun_default_down[] = {NULL};

/* Replace the special variables %D %V ... in s and write the result in sb */
static void replace_args(strlib_buf_t *sb, const char *s, const char *device) {
	const char *src;

	strlib_reset(sb);
	src = s;

	while (*src) {
		switch (*src) {
			case '%':
				switch (*(src + 1)) {
					case '%':
						strlib_push(sb, '%');
						break;
					case 'D': // device
						strlib_appendf(sb, "'%s'", device);
						break;
					case 'V': // VPN IP
						strlib_appendf(sb, "%s", inet_ntoa(config.vpnIP));
						break;
					case 'M': // MTU
						strlib_appendf(sb, "%d", config.tun_mtu);
						break;
					case 'N': // netmask as a string
						strlib_appendf(sb, "'%s'", config.network);
						break;
					case 'n': // netmask
						strlib_appendf(sb, "%s", inet_ntoa(config.vpnNetmask));
						break;
					case 'P': // local UDP port
						strlib_appendf(sb, "%d", config.localport);
						break;
					case 'I': // local IP
						strlib_appendf(sb, "%s", inet_ntoa(config.localIP));
						break;
					default:
						strlib_push(sb, '%');
						strlib_push(sb, *(src + 1));
						break;
				}
				src += 2;
				break;
			default:
				strlib_push(sb, *src);
				src++;
				break;
		}
	}
}

/* execute the commands in programs */
static void exec_internal(const char * const * programs, const char *device) {
	int r;
	strlib_buf_t sb;
	strlib_init(&sb);
	if (programs != NULL) {
		while (*programs) {
			replace_args(&sb, *programs, device);
			log_message_level(2, "|wg| Running: %s", sb.s);
			r = system(sb.s);
			log_message_level(2, "|wg| Exited with status %d", WEXITSTATUS(r));
			programs++;
		}
	}
	strlib_free(&sb);
}

void exec_up(const char *device) {
	char xbuf[256];
	char my_vpnip[32] = {0,}, peer_vpnip[32] = {0,}, vpn_subnet[32] = {0,};
	struct in_addr subnet;
	char *s = NULL;
	char *saveptr; // Initialize our save pointers to save the context of tokens

	if (config.exec_up != NULL) {
		exec_internal((const char * const *) config.exec_up, device);
	} else {
		snprintf(my_vpnip, sizeof(my_vpnip)-1, "%s", inet_ntoa(config.vpnIP));
		snprintf(peer_vpnip, sizeof(peer_vpnip)-1, "%s", inet_ntoa(config.peer_vpnIP));

		subnet.s_addr = config.vpnIP.s_addr & config.vpnNetmask.s_addr;
		snprintf(vpn_subnet, sizeof(vpn_subnet)-1, "%s", inet_ntoa(subnet));

		snprintf(xbuf, sizeof(xbuf)-1, "ifconfig tun0 %s netmask %s up > /dev/null 2>&1",
				my_vpnip, inet_ntoa(config.vpnNetmask));
		system(xbuf);

		snprintf(xbuf, sizeof(xbuf)-1, "route add -net %s/%d gw %s > /dev/null 2>&1",
				vpn_subnet, config.vpnNetmask_CIDR, peer_vpnip);
		system(xbuf);

		s = strtok_r((char *)config.allowed_ips, ",", &saveptr);
		while (s) {
			snprintf(xbuf, sizeof(xbuf)-1, "route add -net %s gw %s > /dev/null 2>&1", s, peer_vpnip);
			system(xbuf);
			s = strtok_r(NULL, ",", &saveptr);
		}

		snprintf(xbuf, sizeof(xbuf)-1, "ip link set dev %s mtu %d up > /dev/null 2>&1", config.tun_device, config.tun_mtu);
		system(xbuf);
	}
}

void exec_down(const char *device) {
	if (config.exec_down != NULL) {
		exec_internal((const char * const *) config.exec_down, device);
	} else {
		char xbuf[256];
		snprintf(xbuf, sizeof(xbuf)-1, "ip addr del %s/%d dev tun0 > /dev/null 2>&1",
				inet_ntoa(config.vpnIP), config.vpnNetmask_CIDR);
		system(xbuf);
	}
}

/*
 * Open a new TUN virtual interface
 * Bind it to config.vpnIP
 */
int init_tun() {
	int tunfd;
	struct ifreq ifr;           // interface request used to open the TUN device

	/* Open TUN interface */
	log_message_level(1, "TUN interface initialization");
	if( (tunfd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		log_error(errno, "Could not open /dev/net/tun");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	/* IFF_TUN       - TUN device (no Ethernet headers)
	   IFF_NO_PI     - Do not provide packet information
	   IFF_ONE_QUEUE - One-queue mode (workaround for old kernels). The driver
	   will only use its internal queue.
	 */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (config.tun_device != NULL) {
		strncpy(ifr.ifr_name, config.tun_device, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	}
	else {
		strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
	}

	if ((ioctl(tunfd, TUNSETIFF, (void *) &ifr)) < 0) {
		log_error(errno, "Error ioctl TUNSETIFF");
		close(tunfd);
		return -1;
	}
	if ((ioctl(tunfd, TUNSETNOCSUM, 1)) < 0) {
		log_error(errno, "Error ioctl TUNSETNOCSUM");
		close(tunfd);
		return -1;
	}

#if 0
	if (config.txqueue != 0 && config.txqueue != TUN_READQ_SIZE) {
		/* The default queue length is 500 frames (TUN_READQ_SIZE) */
		struct ifreq ifr_queue;
		int ctl_sock;

		if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
			memset(&ifr_queue, 0, sizeof(ifr_queue));
			strncpy(ifr_queue.ifr_name, ifr.ifr_name, IFNAMSIZ);
			ifr_queue.ifr_qlen = config.txqueue;
			if (ioctl(ctl_sock, SIOCSIFTXQLEN, (void *) &ifr_queue) < 0) {
				log_error(errno, "ioctl SIOCGIFTXQLEN");
			}
			close(ctl_sock);
		} else {
			log_error(errno, "open socket");
		}
	}
#endif

	/* Inteface configuration */
	device = CHECK_ALLOC_FATAL(strdup(ifr.ifr_name));
	log_message_level(1, "TUN interface configuration (%s MTU %d)", device,
			config.tun_mtu);
	exec_up(device);

	return tunfd;
}

int close_tun(int fd) {
	exec_down(device);
	free(device);
	return close(fd); // the close call destroys the device
}
