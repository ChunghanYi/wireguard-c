/*
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WG_TIMER_H_
#define _WG_TIMER_H_

#include <signal.h>
#include <time.h>

typedef void (*time_handler)(union sigval data);

timer_t *start_timer(unsigned int interval, time_handler handler, void *user_data);
void stop_timer(timer_t *timer_id);

#endif /*_WG_TIMER_H*/
