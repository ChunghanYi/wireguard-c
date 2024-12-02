/*
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WG_MAIN_H_
#define _WG_MAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

/*
 * provide a dummy definition for ASSERT
 * log.h redefines ASSERT to use it with syslog
 */
#define ASSERT(expr)       assert(expr)

#include "wg_config.h"

#define DEFAULT_CONF_FILE "/etc/wireguard.conf"
#define DEFAULT_PID_FILE "/var/run/wireguard.pid"

extern volatile sig_atomic_t end_wireguard;
extern struct configuration config;

#endif /*_WG_MAIN_H_*/
