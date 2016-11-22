/**
 * Copyright © 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

#include "console-server.h"

int console_tty_fd;
struct console {
	const char	*tty_kname;
	char		*tty_sysfs_devnode;
	char		*tty_dev;
	int		tty_sirq;
	int		tty_lpc_addr;
	int		tty_fd;

	struct handler	**handlers;
	int		n_handlers;

	struct poller	**pollers;
	int		n_pollers;

	struct pollfd	*pollfds;
};

struct tty_handler {
	struct handler	handler;
	struct console	*console;
	struct poller	*poller;
	int		fd;
};

static struct tty_handler *to_tty_handler(struct handler *handler)
{
	return container_of(handler, struct tty_handler, handler);
}

static enum poller_ret tty_poll(struct handler *handler,
		int events, void __attribute__((unused)) *data)
{
	struct tty_handler *th = to_tty_handler(handler);
	uint8_t buf[4096];
	ssize_t len;

	if (!(events & POLLIN))
		return POLLER_OK;

	len = read(th->fd, buf, sizeof(buf));
	if (len <= 0) {
		th->poller = NULL;
		close(th->fd);
		return POLLER_REMOVE;
	}

	console_data_out(th->console, buf, len);

	return POLLER_OK;
}

static int tty_init(struct handler *handler, struct console *console,
		struct config *config __attribute__((unused)))
{
	struct tty_handler *th = to_tty_handler(handler);
	const char *tty_name;
	char *tty_path;
	int rc, flags;

	console_tty_fd = console->tty_fd;
	tty_name = config_get_value(config, "local-tty");
	if (!tty_name)
		return -1;

	rc = asprintf(&tty_path, "/dev/%s", tty_name);
	if (!rc)
		return -1;

	th->fd = open(tty_path, O_RDWR);
	if (th->fd < 0) {
		warn("Can't open %s; disabling local tty", tty_name);
		free(tty_path);
		return -1;
	}

	free(tty_path);

	/* initial tty setup */
	flags = fcntl(th->fd, F_GETFL, 0);
	flags |= FNDELAY;
	fcntl(th->fd, F_SETFL, flags);

	th->poller = console_register_poller(console, handler, tty_poll,
			th->fd, POLLIN, NULL);
	th->console = console;

	return 0;
}

static int tty_data(struct handler *handler, uint8_t *buf, size_t len)
{
	struct tty_handler *th = to_tty_handler(handler);
	return write_buf_to_fd(th->fd, buf, len);
}

static void tty_fini(struct handler *handler)
{
	struct tty_handler *th = to_tty_handler(handler);
	if (th->poller)
		console_unregister_poller(th->console, th->poller);
	close(th->fd);
}

static struct tty_handler tty_handler = {
	.handler = {
		.name		= "tty",
		.init		= tty_init,
		.data_in	= tty_data,
		.fini		= tty_fini,
	},
};

console_register_handler(&tty_handler.handler);

int flowctl_toggle(bool flowctl){
	int fd = console_tty_fd;
	return tcflow(fd, flowctl == 1 ? TCION : TCIOFF);
}

