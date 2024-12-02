/*
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WG_TUN_H_
#define _WG_TUN_H_

#include <errno.h>
#include "wg_main.h"
#include "lib/log.h"

extern int init_tun(void);
extern int close_tun(int fd);

extern void exec_up(const char *device);
extern void exec_down(const char *device);
extern const char *tun_default_up[];
extern const char *tun_default_down[];

static inline ssize_t read_tun(int fd, void *buf, size_t count) {
    ssize_t r;
    r = read(fd, buf, count);
    if (r == -1) {
        log_error(errno, "Error while reading the tun device");
        abort();
    }
    return r;
}

static inline ssize_t write_tun(int fd, const void *buf, size_t count) {
    ssize_t r;
    r = write(fd, buf, count);
    if (r == -1) {
        log_error(errno, "Error while writting to the tun device");
        abort();
    }
    return r;
}

#endif /*_WG_TUN_H_*/
