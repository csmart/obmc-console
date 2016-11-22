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
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "console-server.h"

const size_t buffer_size_max = 100 * 1;
int flowctl;

struct client {
	struct poller	*poller;
	int		fd;
	uint8_t		*buf;
	size_t		buf_alloc;
	size_t		buf_len;
	bool		flowctl;
};

struct socket_handler {
	struct handler	handler;
	struct console	*console;
	struct poller	*poller;
	int		sd;

	struct client	**clients;
	int		n_clients;
};

static struct socket_handler *to_socket_handler(struct handler *handler)
{
	return container_of(handler, struct socket_handler, handler);
}

static void client_close(struct socket_handler *sh, struct client *client)
{
	int idx;

	close(client->fd);
	if (client->poller)
		console_unregister_poller(sh->console, client->poller);

	for (idx = 0; idx < sh->n_clients; idx++)
		if (sh->clients[idx] == client)
			break;

	assert(idx < sh->n_clients);

	free(client);
	client = NULL;

	sh->n_clients--;
	memmove(&sh->clients[idx], &sh->clients[idx+1],
			sizeof(*sh->clients) * (sh->n_clients - idx));
	sh->clients = realloc(sh->clients,
			sizeof(*sh->clients) * sh->n_clients);
}

/* Write data to the client, until error or block.
 *
 * Returns -1 on hard failure, otherwise number of bytes written. A zero
 * return indicates that no bytes were written due to potential block,
 * but isn't a failure
 */
static ssize_t client_write_data(struct client *client, uint8_t *buf,
		size_t len)
{
	size_t pos;
	ssize_t rc;

	for (pos = 0; pos < len; pos += rc) {
		//printf("printing to client: %d\n", client->fd);
		rc = write(client->fd, buf + pos, len - pos);
		if (rc < 0) {
			// so if this would block, then just break out
			if (errno == EAGAIN || errno == EWOULDBLOCK){
				printf("got blocking error on fd: %d\n", client->fd);
				// set socket to BLOCKING
				//fcntl(client->fd, F_SETFL, fcntl(client->fd,F_GETFL) & ~O_NONBLOCK);
				printf("flow control on, %lld %lld client: %d\n", (unsigned long long)(client->buf_len), (unsigned long long)(len), client->fd);
				
				// do flow control on upstream
				printf("flowctl toggle on (should be 0): %d\n" , flowctl_toggle(0));
				
				// tag that this client caused flowctl
				client->flowctl = 1;
				flowctl++;
				printf("flowctl client: %d\n", flowctl);

				rc=0;
				continue;
				//break;
			}

			if (errno == EINTR){
				printf("got error on fd: %d\n", client->fd);
				continue;
			}

			return -1;
		}
		if (rc == 0)
			return -1;
	}

	return pos;
}

static enum poller_ret client_poll(struct handler *handler,
		int events, void *data)
{
	struct socket_handler *sh = to_socket_handler(handler);
	struct client *client = data;
	uint8_t buf[4096];
	ssize_t len;
	int rc;

	if (events & POLLIN) {
		rc = read(client->fd, buf, sizeof(buf));
		if (rc <= 0)
			goto err_close;

		console_data_out(sh->console, buf, rc);
	}

	if (events & POLLOUT) {
		len = client_write_data(client, client->buf, client->buf_len);
		if (len < 0)
			goto err_close;

		/* consume from the queue */
		client->buf_len -= len;
		memmove(client->buf, client->buf + len,
				client->buf_len);

		if (client->buf_len == 0) {
			printf("buffer is ZERO for client: %d\n", client->fd);
			// set socket to BLOCKING
			//fcntl(client->fd, F_SETFL, fcntl(client->fd,F_GETFL) | O_NONBLOCK);
			printf("flow control off, %lld %lld client: %d\n", (unsigned long long)(client->buf_len), (unsigned long long)(len), client->fd);
			
			// tag that this client caused flowctl
			// do flow control on upstream
			client->flowctl = 0;
			flowctl--;
			if (flowctl == 0) {
				printf("flowctl toggle (should be 0): %d\n" , flowctl_toggle(1));
			}
			
			printf("flowctl client: %d\n", flowctl);
		} else {
			printf("buffer not zero for client: %d\n", client->fd);
		}

	}

	return POLLER_OK;

err_close:
	client->poller = NULL;
	client_close(sh, client);
	return POLLER_REMOVE;
}

static int client_queue_data(struct client *client, uint8_t *buf, size_t len)
{
	if (client->buf_len + len > client->buf_alloc) {
		if (!client->buf_alloc)
			client->buf_alloc = 2048;
		client->buf_alloc *= 2;

		/*
		if (client->buf_len + len > 2048) {
			// set socket to BLOCKING
			fcntl(client->fd, F_SETFL, fcntl(client->fd,F_GETFL) & ~O_NONBLOCK);
			printf("flow control on, %lld %lld client: %d\n", (unsigned long long)(client->buf_len), (unsigned long long)(len)), client->fd);
			
			// do flow control on upstream
			printf("flowctl toggle (should be 0): %d\n" , flowctl_toggle(0));
			
			// tag that this client caused flowctl
			client->flowctl = 1;
			flowctl++;
			printf("flowctl client: %d\n", flowctl);
		}
		*/

		// should never hit this
		if (client->buf_alloc > buffer_size_max)
			return -1;

		client->buf = realloc(client->buf, client->buf_alloc);
	}

	memcpy(client->buf + client->buf_len, buf, len);
	client->buf_len += len;
	return 0;
}

static int client_send_or_queue(struct client *client, uint8_t *buf, size_t len)
{
	ssize_t rc;

	rc = client_write_data(client, buf, len);
	if (rc < 0)
		return -1;

	if ((size_t)rc < len) {
		rc = client_queue_data(client, buf + rc, len - rc);
		if (rc)
			return -1;
	}

	/*
	// re-enable flow
	if (client->flowctl && client->buf_len < 2048){
		flowctl--;
		if (flowctl == 0){
			printf("flowctl toggle (should be 0): %d\n" , flowctl_toggle(1));;
			// re-enable flow
		}
		printf("flowctl clients: %d client: %d\n" , flowctl, client->fd);
	}
	*/

	return 0;
}

static enum poller_ret socket_poll(struct handler *handler,
		int events, void __attribute__((unused)) *data)
{
	struct socket_handler *sh = to_socket_handler(handler);
	struct client *client;
	int fd, n;

	if (!(events & POLLIN))
		return POLLER_OK;

	fd = accept4(sh->sd, NULL, NULL, SOCK_NONBLOCK);
	if (fd < 0)
		return POLLER_OK;

	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	client->fd = fd;
	client->poller = console_register_poller(sh->console, handler,
			client_poll, client->fd, POLLIN, client);

	n = sh->n_clients++;
	sh->clients = realloc(sh->clients,
			sizeof(*sh->clients) * sh->n_clients);
	sh->clients[n] = client;

	return POLLER_OK;

}

static int socket_init(struct handler *handler, struct console *console,
		struct config *config __attribute__((unused)))
{
	struct socket_handler *sh = to_socket_handler(handler);
	struct sockaddr_un addr;
	int rc;

	sh->console = console;
	sh->clients = NULL;
	sh->n_clients = 0;

	sh->sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sh->sd < 0) {
		warn("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, &console_socket_path, console_socket_path_len);

	rc = bind(sh->sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		warn("Can't bind to socket path %s",
				console_socket_path_readable);
		return -1;
	}

	rc = listen(sh->sd, 1);
	if (rc) {
		warn("Can't listen for incoming connections");
		return -1;
	}

	sh->poller = console_register_poller(console, handler, socket_poll,
			sh->sd, POLLIN, NULL);

	return 0;
}

static int socket_data(struct handler *handler, uint8_t *buf, size_t len)
{
	struct socket_handler *sh = to_socket_handler(handler);
	int i, rc;

	for (i = 0; i < sh->n_clients; i++) {
		struct client *client = sh->clients[i];
		rc = client_send_or_queue(client, buf, len);
		if (!rc)
			continue;

		/* if we failed to send data, close the client. This will
		 * remove it from the clients array, so skip back to the item
		 * that has taken its place
		 */
		client_close(sh, client);
		i--;
	}
	return 0;
}

static void socket_fini(struct handler *handler)
{
	struct socket_handler *sh = to_socket_handler(handler);
	int i;

	for (i = 0; i < sh->n_clients; i++)
		client_close(sh, sh->clients[i]);

	if (sh->poller)
		console_unregister_poller(sh->console, sh->poller);

	close(sh->sd);
}

static struct socket_handler socket_handler = {
	.handler = {
		.name		= "socket",
		.init		= socket_init,
		.data_in	= socket_data,
		.fini		= socket_fini,
	},
};

console_register_handler(&socket_handler.handler);

