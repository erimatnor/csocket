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
#ifndef __SOCKET_INTERNAL_H__
#define __SOCKET_INTERNAL_H__

#include <csocket/socket.h>

#define MAX_STRERROR_LEN 128

struct socket {
    int fd;
    int flags;
    int err;
    char strerror[MAX_STRERROR_LEN];
    enum socket_state state;
    const struct socket_ops *ops;
    void *private;
};


#endif /* __SOCKET_INTERNAL_H__ */
