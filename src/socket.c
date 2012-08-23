/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "socket.h"

#define HAVE_OPENSSL 1

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

ssize_t socket_recv(struct socket *s, void *buffer, size_t length, int flags)
{
    return s->ops->recv(s, buffer, length, flags);
}

int socket_connect(struct socket *s, const struct sockaddr *address, socklen_t address_len)
{
    return s->ops->connect(s, address, address_len);
}

int socket_connect_service(struct socket *s, const char *service)
{
    return s->ops->connect_service(s, service);
}

int socket_close(struct socket *s)
{
    return s->ops->close(s);
}

int socket_is_connected(struct socket *s)
{
    return s->state == SOCKET_CONNECTED;
}

static int socket_connect_internal(struct socket *sock, 
				   const struct sockaddr *address, 
				   socklen_t address_len)
{
    int ret;

    ret = connect(sock->fd, address, address_len);

    if (ret == -1) {
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

static ssize_t socket_recv_internal(struct socket *sock, 
				    void *buffer, size_t length, int flags)
{
    return recv(sock->fd, buffer, length, flags);
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
    .recv = socket_recv_internal,
    .close = socket_close_internal,
    .destroy = socket_destroy_internal,
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
    .recv = socket_recv_internal,
    .close = socket_close_internal,
    .destroy = socket_destroy_internal,
};

#if defined(HAVE_OPENSSL)
extern int ssl_socket_lib_init(void);
#endif

int socket_lib_init(void)
{
    int ret = 0;
#if defined(HAVE_OPENSSL)
    ret = ssl_socket_lib_init();
#endif
    return ret;
}

void socket_lib_fini(void)
{
#if defined(HAVE_OPENSSL)
#endif
}

#include "ssl_socket.h"

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
