/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __SSL_SOCKET_H__
#define __SSL_SOCKET_H__

#include <openssl/ssl.h>
#include "socket.h"

struct ssl_socket {
    struct socket sock;
    SSL_CTX *ctx;
    SSL *ssl;
};

extern const struct socket_ops ssl_socket_ops;

#endif /* __SSL_SOCKET_H__ */
