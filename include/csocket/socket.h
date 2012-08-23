/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <sys/socket.h>

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

struct socket {
    int fd;
    int flags;
    enum socket_state state;
    const struct socket_ops *ops;
    void *private;
};

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
    ssize_t (*recv)(struct socket *s, void *buffer, size_t length, int flags);
    int (*connect)(struct socket *s, const struct sockaddr *address, socklen_t address_len);
    int (*connect_service)(struct socket *s, const char *service);
    int (*close)(struct socket *s);
    void (*destroy)(struct socket *s);
};

struct socket *socket_create(const struct socket_ops *ops);
void socket_free(struct socket *sock);
int socket_bind(struct socket *s, const struct sockaddr *address, socklen_t address_len);
ssize_t socket_send(struct socket *s, const void *buffer, size_t length, int flags);
ssize_t socket_recv(struct socket *s, void *buffer, size_t length, int flags);
int socket_connect(struct socket *s, const struct sockaddr *address, socklen_t address_len);
int socket_connect_service(struct socket *s, const char *service);
int socket_close(struct socket *s);
int socket_is_connected(struct socket *s);

extern const struct socket_ops inet_stream_socket_ops;
extern const struct socket_ops inet6_stream_socket_ops;

#endif /* __SOCKET_H__ */
