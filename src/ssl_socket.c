/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "ssl_socket.h"

#define ssl_sock(sock) ((struct ssl_socket *)sock)

static int ssl_init(struct socket *sock)
{
    struct ssl_socket *sslsock = ssl_sock(sock);
    int ret;

    sslsock->ctx = SSL_CTX_new(SSLv23_client_method());

    if (!sslsock->ctx)
        return -1;

/*
    if(! SSL_CTX_load_verify_locations(ctx, "/path/to/TrustStore.pem", NULL))
    {
    
    }
*/
    sslsock->ssl = SSL_new(sslsock->ctx);
    
    if (!sslsock->ssl)
        return -1;
    
    ret = SSL_set_fd(sslsock->ssl, sock->fd);

    if (ret == 0)
        return -1;

    printf("SSL initialized\n");

    return 0;
}

static int ssl_connect_internal(struct socket *sock)
{
    struct ssl_socket *sslsock = ssl_sock(sock);
    int ret;
    
    ret = SSL_connect(sslsock->ssl);

    switch (ret) {
    case 1:
        /* TLS/SSL handshake success */
        ret = 0;
        break;
    case 2:
        /* TLS/SSL handshake failure */
        fprintf(stderr, "TLS/SSL handshake failed\n");
        ret = -1;
        break;
    default:
        /* Fatal error */
        fprintf(stderr, "TLS/SSL fatal error\n");
        ret = -1;
        break;
    }
    
    return ret;

}

static int ssl_connect(struct socket *sock, 
                       const struct sockaddr *address, 
                       socklen_t address_len)
{
    int ret;

    ret = sock->ops->base->connect(sock, address, address_len);

    if (ret == -1)
        return ret;

    return ssl_connect_internal(sock);
}

static int ssl_connect_service(struct socket *sock, const char *service)
{
    int ret;

    printf("connecting with SSL\n");

    ret = sock->ops->base->connect_service(sock, service);

    if (ret == -1)
        return ret;

    printf("successfully connected to %s\n", service);

    return ssl_connect_internal(sock);
}

static ssize_t ssl_send(struct socket *sock, 
                        const void *buffer, size_t length, int flags)
{
    struct ssl_socket *sslsock = ssl_sock(sock);

    return SSL_write(sslsock->ssl, buffer, length);
}

static ssize_t ssl_recv(struct socket *sock, 
                        void *buffer, size_t length, int flags)
{
    struct ssl_socket *sslsock = ssl_sock(sock);

    return SSL_read(sslsock->ssl, buffer, length);
}

static int ssl_close(struct socket *sock)
{
    struct ssl_socket *sslsock = ssl_sock(sock);
    
    SSL_shutdown(sslsock->ssl);

    return sock->ops->base->close(sock);
}

static void ssl_destroy(struct socket *sock)
{
    struct ssl_socket *sslsock = ssl_sock(sock);

    SSL_free(sslsock->ssl);
    SSL_CTX_free(sslsock->ctx);
    
    return sock->ops->base->destroy(sock);
}

int ssl_socket_lib_init(void)
{
    SSL_library_init();
    
    return 0;
}

void ssl_socket_lib_fini(void)
{

}

const struct socket_ops ssl_socket_ops = {
    .domain = AF_INET,
    .socktype = SOCK_STREAM,
    .protocol = 0,
    .conntype = CONNECTION_SSL,
    .socket_size = sizeof(struct ssl_socket),
    .base = &inet_stream_socket_ops,
    .init = ssl_init,
    .connect = ssl_connect,
    .connect_service = ssl_connect_service,
    .send = ssl_send,
    .recv = ssl_recv,
    .close = ssl_close,
    .destroy = ssl_destroy,
};
