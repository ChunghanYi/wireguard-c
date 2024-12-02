/*
 * Wireguard VPN Client for Linux userspace
 * startup code
 *
 * Copyright (C) 2024 Chunghan.Yi(chunghan.yi@gmail.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wg_main.h"

#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>

#include "wg_tun.h"
#include "wg_comm.h"
#include "wg_config.h"
#include "wg_timer.h"
#include "wireguard_vpn.h"
#include "wireguardif.h"
#include "lib/log.h"
#include "lib/pthread_wrap.h"

#define VERSION "0.9.90"

volatile sig_atomic_t end_wireguard = 0;
static char *pidfile = NULL;
struct netif *wg_netif = NULL;


static void usage(void) {
	fprintf(stderr, "Usage: wireguard [OPTION]... [configuration_file]\n\n");
	fprintf(stderr, "Options\n");
	fprintf(stderr, " -d, --debug             debug mode\n");
	fprintf(stderr, " -D, --daemon            fork in background\n");
	fprintf(stderr, " -h, --help              this help message\n");
	fprintf(stderr, " -m, --mlock             lock the memory into RAM\n");
	fprintf(stderr, " -p, --pidfile=FILE      write the pid into this file when running in background\n");
	fprintf(stderr, " -v, --verbose           verbose mode\n");
	fprintf(stderr, " -V, --version           show version information and exit\n\n");
	fprintf(stderr, "If no configuration file is given, the default is " DEFAULT_CONF_FILE "\n");
	exit(EXIT_FAILURE);
}

static void version(void) {
	fprintf(stderr, "Wireguard VPN | Version %s\n", VERSION);
	fprintf(stderr, "Copyright (c) 2024 Chunghan Yi <chunghan.yi@gmail.com>\n");
	exit(EXIT_SUCCESS);
}

static int parse_args(int argc, char **argv, const char **configFile) {
	int opt;

	struct option long_options[] = {
		{"verbose", 0, NULL, 'v'},
		{"daemon", 0, NULL, 'D'},
		{"debug", 0, NULL, 'd'},
		{"version", 0, NULL, 'V'},
		{"help", 0, NULL, 'h'},
		{"mlock", 0, NULL, 'm'},
		{"pidfile", 1, NULL, 'p'},
		{0, 0, 0, 0}
	};
	while ((opt = getopt_long(argc, argv, "vVdDhmp:", long_options, NULL)) >= 0) {
		switch(opt) {
			case 'v':
				config.verbose = 1;
				break;
			case 'D' :
				config.daemonize = 1;
				break;
			case 'd' :
				config.debug = 1;
				config.verbose = 1;
				break;
			case 'm' :
#ifdef HAVE_MLOCKALL
				if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
					log_error(errno, "Unable to lock the memory");
					exit(EXIT_FAILURE);
				}
#else
				log_message("This platform doesn't support mlockall.");
#endif
				break;
			case 'p' :
				if (config.pidfile)
					free(config.pidfile);
				config.pidfile = CHECK_ALLOC_FATAL(strdup(optarg));
				break;
			case 'V' :
				return 2;
			case 'h' :
				return 1;
			default : return 1;
		}
	}

	argv += optind;
	argc -= optind;

	/* the configuration file */
	if (argc == 1) {
		*configFile = argv[0];
	} else if (argc == 0) {
		*configFile = DEFAULT_CONF_FILE;
	} else {
		return 1;
	}

	return 0;
}

static void remove_pidfile(void) {
	unlink(pidfile);
	free(pidfile);
}

static void create_pidfile(void) {
	int fd;
	FILE *file;

	if (strlen(pidfile) == 0) {
		return;
	}

	if (unlink(pidfile) != 0 && errno != ENOENT) {
		return;
	}

	fd = open(pidfile, O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW, (mode_t) 00644);
	if (fd == -1) {
		return;
	}

	file = fdopen(fd, "w");
	if (file == NULL) {
		return;
	}

	fprintf(file, "%d\n", getpid());

	fclose(file);

	atexit(remove_pidfile);
}

static void daemonize(void) {
    int r;

    printf("Going in background...\n");
    r = daemon(1, 0);
    if (r != 0) {
        log_error(errno, "Unable to daemonize");
        exit(EXIT_FAILURE);
    }

    config.verbose = 0;
    config.debug = 0;
}

/* thread used to cath and handle signals */
static void *sig_handler(void *arg __attribute__((unused))) {
	sigset_t mask;
	int sig;

	while (1) {
		sigfillset(&mask);
		sigwait(&mask, &sig);

		switch (sig) {
			case SIGTERM:
			case SIGINT:
			case SIGQUIT:
				end_wireguard = 1;
				// terminate timer
				stop_timer(wg_netif->timer);
				log_message("Received signal %d, exiting...", sig);
				return NULL;
			case SIGALRM:
				break;
			default:
				break;
		}
	}
}

int main (int argc, char **argv) {
	const char *configFile = NULL;
	int pa;
	int exit_status = EXIT_SUCCESS;
	int log_level = 0;

	initConfig();

	pa = parse_args(argc, argv, &configFile);
	if (pa == 1)
		usage();
	else if (pa == 2)
		version();

	if (parse_conf_file(configFile) != 0) {
		goto clean_end;
	}

	log_level = config.debug;

	if (config.daemonize) daemonize();
	log_init(config.daemonize, log_level, "wireguard");

	if (config.daemonize) {
		const char *pidtmp = (config.pidfile != NULL) ? config.pidfile : DEFAULT_PID_FILE;
		pidfile = CHECK_ALLOC_FATAL(strdup(pidtmp));
		create_pidfile();
	}

	/* mask all signals in this thread and child threads */
	sigset_t mask;
	sigfillset(&mask);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	/* start the signal handler */
	createDetachedThread(sig_handler, NULL);

	/* Start wireguard setup ... */
	if (wireguard_setup() == -1) {
		log_error(errno, "Could not setup wireguard.");
		exit_status = EXIT_FAILURE;
		goto clean_end;
	}

	if (wg_netif == NULL) {
		log_error(errno, "wg_netif is NULL.");
		exit_status = EXIT_FAILURE;
		goto clean_end;
	}

	wg_netif->sockfd = create_socket();
	if (wg_netif->sockfd < 0) {
		log_error(errno, "Could not create udp socket.");
		exit_status = EXIT_FAILURE;
		goto clean_end;
	}

	if (fcntl(wg_netif->sockfd, F_SETFL, O_NONBLOCK) == -1) {
		log_error(errno, "Could not set non-blocking mode on the socket");
		exit_status = EXIT_FAILURE;
		goto clean_end;
	}

	wg_netif->tunfd = init_tun();
	if (wg_netif->tunfd < 0) {
		log_error(errno, "Could not create tun device file.");
		exit_status = EXIT_FAILURE;
		goto clean_end;
	}

	do {
		log_message("Starting Wireguard VPN");

		if (start_vpn(wg_netif) == -1) {
			log_error(errno, "Could not start vpn.");
			exit_status = EXIT_FAILURE;
		}
	} while (0);

clean_end:
	if (wg_netif) {
		stop_timer(wg_netif->timer);
		close_tun(wg_netif->tunfd);
		close(wg_netif->sockfd);
		if (wg_netif->state)
			free(wg_netif->state); //device
		free(wg_netif);
	}

	log_close();
	freeConfig();
	exit(exit_status);
}
