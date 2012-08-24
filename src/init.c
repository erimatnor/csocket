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
#include "config.h"

extern int socket_lib_init(void);
extern void socket_lib_fini(void);
#if defined(HAVE_OPENSSL)
extern int ssl_socket_lib_init(void);
extern void ssl_socket_lib_fini(void);
#endif

int csocket_lib_init(void)
{
    int ret = 0;

    ret = socket_lib_init();

    if (ret == -1)
	return -1;

#if defined(HAVE_OPENSSL)
    ret = ssl_socket_lib_init();
#endif

    return ret;
}

void csocket_lib_fini(void)
{
    socket_lib_fini();

#if defined(HAVE_OPENSSL)
    ssl_socket_lib_fini();
#endif
}
