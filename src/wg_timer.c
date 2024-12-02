/*
 * Timer functions
 *
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "wg_timer.h"
#include "lib/log.h"

timer_t *start_timer(unsigned int interval, time_handler handler, void *user_data) {
	int res = 0;

	/* sigevent specifies behaviour on expiration */
	struct sigevent sev = { 0 };
	struct itimerspec its = {
		.it_value.tv_sec  = interval/1000,
		.it_value.tv_nsec = 0,
		.it_interval.tv_sec  = interval/1000,
		.it_interval.tv_nsec = 0
	};

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = handler;
	sev.sigev_value.sival_ptr = user_data;

	timer_t *timer_id = malloc(sizeof(timer_t));
	if (timer_id == NULL) {
		log_error(errno, "|wg| Error malloc: %s\n", strerror(errno));
		return NULL;
	}

	/* create timer */
	res = timer_create(CLOCK_REALTIME, &sev, timer_id);
	if (res != 0) {
		log_error(errno, "|wg| Error timer_create: %s\n", strerror(errno));
		free(timer_id);
		return NULL;
	}

	/* start timer */
	res = timer_settime(*timer_id, 0, &its, NULL);
	if (res != 0) {
		log_error(errno, "|wg| Error timer_settime: %s\n", strerror(errno));
		free(timer_id);
		return NULL;
	}

	return timer_id;
}

void stop_timer(timer_t *timer_id) {
	timer_delete(*timer_id);
	if (timer_id)
		free(timer_id);
}
