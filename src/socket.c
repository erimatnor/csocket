/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright [2012] [Erik Nordström <erik.nordstrom@gmail.com>]
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <csocket/socket.h>
#include "socket_internal.h"

static short socket_events_to_poll(short events)
{
    short poll_events = 0;

    if (events & SOCKET_EV_READ)
        poll_events |= POLLIN;

    if (events & SOCKET_EV_WRITE)
        poll_events |= POLLOUT;

    if (events & SOCKET_EV_ERR)
        poll_events |= POLLERR;

    if (events & SOCKET_EV_HUP)
        poll_events |= POLLHUP;

    return poll_events;
}

static short poll_events_to_socket(short events)
{
    short socket_events = 0;

    if (events & POLLIN)
        socket_events |= SOCKET_EV_READ;

    if (events & POLLOUT)
        socket_events |= SOCKET_EV_WRITE;

    if (events & POLLERR)
        socket_events |= SOCKET_EV_ERR;

    if (events & POLLHUP)
        socket_events |= SOCKET_EV_HUP;

    return socket_events;
}

struct socket *socket_create(const struct socket_ops *ops)
{
    struct socket *sock;

    if (ops->socket_size < sizeof(struct socket)) {
        return NULL;
    }
    
    sock = malloc(ops->socket_size);

    if (!sock)
        return NULL;

    memset(sock, 0, ops->socket_size);

    *sock = (struct socket) {
        .fd = socket(ops->domain, ops->socktype, ops->protocol),
        .ops = ops,
        .state = SOCKET_INITIALIZED,
    };

    printf("sock->fd=%d\n", sock->fd);

    if (sock->fd == -1) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        free(sock);
        return NULL;
    }
    if (ops->init && ops->init(sock) < 0) {
        free(sock);
        return NULL;
    }
    
    return sock;
}

static int socket_init_internal(struct socket *sock)
{
    return 0;
}

void socket_free(struct socket *sock)
{
    if (sock->state != SOCKET_INITIALIZED)
        sock->ops->close(sock);
    
    sock->ops->destroy(sock);
    free(sock);
}

int socket_bind(struct socket *s, const struct sockaddr *address, socklen_t address_len)
{
    return s->ops->bind(s, address, address_len);
}

ssize_t socket_send(struct socket *s, const void *buffer, size_t length, int flags)
{
    return s->ops->send(s, buffer, length, flags);
}

ssize_t socket_sendmsg(struct socket *s, const struct msghdr *msg, int flags)
{
    return s->ops->sendmsg(s, msg, flags);
}

ssize_t socket_recv(struct socket *s, void *buffer, size_t length, int flags)
{
    return s->ops->recv(s, buffer, length, flags);
}

int socket_vprintf(struct socket *s, const char * format, va_list ap)
{
    return s->ops->vprintf(s, format, ap);
}

int socket_printf(struct socket *s, const char *format, ...)
{
    va_list ap;
    int ret;
    
    va_start (ap, format);
    ret = s->ops->vprintf(s, format, ap);
    va_end(ap);
    
    return ret;
}

int socket_connect(struct socket *s, const struct sockaddr *address, socklen_t address_len)
{
    return s->ops->connect(s, address, address_len);
}

int socket_connect_service(struct socket *s, const char *service)
{
    return s->ops->connect_service(s, service);
}

int socket_poll(struct socket *s, short *events, int timeout)
{
    return s->ops->poll(s, events, timeout);
}

int socket_close(struct socket *s)
{
    return s->ops->close(s);
}

int socket_is_connected(struct socket *s)
{
    return s->state == SOCKET_CONNECTED;
}

const char *socket_strerror(struct socket *sock)
{
    return sock->ops->strerror(sock);
}

static int socket_connect_internal(struct socket *sock, 
                                   const struct sockaddr *address, 
                                   socklen_t address_len)
{
    int ret;

    ret = connect(sock->fd, address, address_len);

    if (ret == -1) {
        sock->err = errno;
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return ret;
    }

    sock->state = SOCKET_CONNECTED;

    return ret;
}

static ssize_t socket_send_internal(struct socket *sock, 
                                    const void *buffer, size_t length, int flags)
{
    return send(sock->fd, buffer, length, flags);
}

ssize_t socket_sendmsg_internal(struct socket *sock, const struct msghdr *msg, int flags)
{
    return sendmsg(sock->fd, msg, flags);
}

static ssize_t socket_recv_internal(struct socket *sock, 
                                    void *buffer, size_t length, int flags)
{
    return recv(sock->fd, buffer, length, flags);
}

static int socket_vprintf_internal(struct socket *sock, const char * format, va_list ap)
{
    return vdprintf(sock->fd, format, ap);
}

static int socket_printf_internal(struct socket *sock, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start (ap, format);
    ret = vdprintf(sock->fd, format, ap);
    va_end(ap);

    return ret;
}

static int socket_poll_internal(struct socket *sock,
                                short *events, int timeout)
{
    struct pollfd fds;
    int ret;

    if (!sock || !events)
        return -1;
    
    fds = (struct pollfd) { 
        .fd = sock->fd, 
        .events = socket_events_to_poll(*events),
        .revents = 0,
    };
    
    ret = poll(&fds, 1, timeout);
\
    *events = poll_events_to_socket(fds.revents);

    return ret;
}

static int socket_close_internal(struct socket *sock)
{
    sock->state = SOCKET_CLOSED;
    return close(sock->fd);
}

static int socket_connect_service_internal(struct socket *sock, const char *service)
{
    struct addrinfo hints, *ai, *ai_it;
    const char *port = NULL;
    char host[strlen(service) + 1];
    size_t i;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = sock->ops->domain;
    hints.ai_socktype = sock->ops->socktype;
    hints.ai_flags = 0;

    strcpy(host, service);
    
    for (i = 0; host[i]; i++) {
        if (host[i] == ':') {
            host[i] = '\0';
            port = &host[i+1];
            break;
        }
    }
    
    ret = getaddrinfo(host, port, &hints, &ai);

    if (ret != 0) {
        fprintf(stderr, "connect: %s", gai_strerror(ret));
        return ret;
    }
    
    for (ai_it = ai; ai_it; ai_it = ai_it->ai_next) {
        char buf[256];
        
        if (sock->ops->domain == AF_INET) {
            struct sockaddr_in *inaddr = (struct sockaddr_in *)ai_it->ai_addr;
            inet_ntop(sock->ops->domain, &inaddr->sin_addr, buf, 256);
            printf("connecting to %s\n", buf);
        }
	       
        ret = socket_connect_internal(sock, ai_it->ai_addr, ai_it->ai_addrlen);

        if (ret == -1) {
            sock->err = errno;
            if (errno == EINPROGRESS)
                break;
        } else if (ret == 0) {
            break;
        }
    }

    freeaddrinfo(ai);

    return ret;
}

static void socket_destroy_internal(struct socket *sock)
{
    
}

static const char *socket_strerror_internal(struct socket *sock)
{
    int ret = strerror_r(errno, sock->strerror, sizeof(sock->strerror));

    if (ret != 0) {
        strcpy(sock->strerror, "Unknown error\n");
    }

    return sock->strerror;
}

const struct socket_ops inet_stream_socket_ops = {
    .domain = AF_INET,
    .socktype = SOCK_STREAM,
    .protocol = 0,
    .conntype = CONNECTION_PLAIN,
    .socket_size = sizeof(struct socket),
    .init = socket_init_internal,
    .connect = socket_connect_internal,
    .connect_service = socket_connect_service_internal,
    .send = socket_send_internal,
    .sendmsg = socket_sendmsg_internal,
    .printf = socket_printf_internal,
    .vprintf = socket_vprintf_internal,
    .recv = socket_recv_internal,
    .poll = socket_poll_internal,
    .close = socket_close_internal,
    .destroy = socket_destroy_internal,
    .strerror = socket_strerror_internal,
};

const struct socket_ops inet6_stream_socket_ops = {
    .domain = AF_INET6,
    .socktype = SOCK_STREAM,
    .protocol = 0,
    .conntype = CONNECTION_PLAIN,
    .socket_size = sizeof(struct socket),
    .init = socket_init_internal,
    .connect = socket_connect_internal,
    .connect_service = socket_connect_service_internal,
    .send = socket_send_internal,
    .sendmsg = socket_sendmsg_internal,
    .printf = socket_printf_internal,
    .vprintf = socket_vprintf_internal,
    .recv = socket_recv_internal,
    .poll = socket_poll_internal,
    .close = socket_close_internal,
    .destroy = socket_destroy_internal,
    .strerror = socket_strerror_internal,
};

int socket_lib_init(void)
{
    return 0;
}

void socket_lib_fini(void)
{
}
