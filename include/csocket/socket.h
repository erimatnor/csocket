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
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <sys/socket.h>
#include <stdarg.h>

struct socket_ops;

enum connection_type {
    CONNECTION_PLAIN,
    CONNECTION_SSL,
};

enum socket_state {
    SOCKET_INITIALIZED,
    SOCKET_BOUND,
    SOCKET_CONNECTED,
    SOCKET_CLOSED,
};

enum socket_events {
    SOCKET_EV_READ  = (1 << 0),
    SOCKET_EV_WRITE = (1 << 1),
    SOCKET_EV_HUP   = (1 << 2),
    SOCKET_EV_ERR   = (1 << 3),
};

struct socket;

struct socket_ops {
    size_t socket_size;
    enum connection_type conntype;
    int domain;
    int socktype;
    int protocol;
    const struct socket_ops *base;
    int (*init)(struct socket *s);
    int (*bind)(struct socket *s, const struct sockaddr *address, socklen_t address_len);
    ssize_t (*send)(struct socket *s, const void *buffer, size_t length, int flags);
    ssize_t (*sendmsg)(struct socket *s, const struct msghdr *msg, int flags);
    int (*vprintf)(struct socket *s, const char *format, va_list ap);
    int (*printf)(struct socket *s, const char *format, ...);
    ssize_t (*recv)(struct socket *s, void *buffer, size_t length, int flags);
    int (*connect)(struct socket *s, const struct sockaddr *address, socklen_t address_len);
    int (*connect_service)(struct socket *s, const char *service);
    int (*poll)(struct socket *s, short *events, int timeout);
    int (*close)(struct socket *s);
    void (*destroy)(struct socket *s);
    const char *(*strerror)(struct socket *s);
};

struct socket *socket_create(const struct socket_ops *ops);
void socket_free(struct socket *sock);
int socket_bind(struct socket *s, const struct sockaddr *address, socklen_t address_len);
ssize_t socket_send(struct socket *s, const void *buffer, size_t length, int flags);
ssize_t socket_sendmsg(struct socket *s, const struct msghdr *msg, int flags);
int socket_vprintf(struct socket *s, const char * format, va_list ap);
int socket_printf(struct socket *s, const char *format, ...);
ssize_t socket_recv(struct socket *s, void *buffer, size_t length, int flags);
int socket_connect(struct socket *s, const struct sockaddr *address, socklen_t address_len);
int socket_connect_service(struct socket *s, const char *service);
int socket_poll(struct socket *s, short *events, int timeout);
int socket_close(struct socket *s);
int socket_is_connected(struct socket *s);
const char *socket_strerror(struct socket *s);

extern const struct socket_ops inet_stream_socket_ops;
extern const struct socket_ops inet6_stream_socket_ops;

#endif /* __SOCKET_H__ */
