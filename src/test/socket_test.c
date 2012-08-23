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
#include <csocket/ssl_socket.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char **argv)
{
    struct socket *s;
    const char *service = "localhost:80";
    int ret;

    socket_lib_init();

    s = socket_create(&ssl_socket_ops);
    //s = socket_create(&inet_stream_socket_ops);

    if (!s) {
	fprintf(stderr, "could not create socket\n");
	return -1;
    }
    if (argc > 1)
	service = argv[1];
    
    ret = socket_connect_service(s, service); 
    
    if (ret == -1) {
	fprintf(stderr, "failed to connect to %s: %s\n",
		service, strerror(errno));
    } else {
	printf("connected to service %s\n", service);
    } 

    sleep(3);
    
    socket_close(s);
    socket_free(s);

    socket_lib_fini();

    return 0;
}
