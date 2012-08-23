/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright [2012] [Erik Nordström]
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
