/*
 * SPIKE CODE — not production.
 *
 * Minimal TLS 1.2 client that completes a handshake and then attempts
 * client-initiated renegotiation, to verify the worker-facing server
 * context rejects it (OP_NO_RENEGOTIATION). Hand-declared prototypes:
 * the host has no OpenSSL development headers.
 *
 * Build: gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
 *          reneg_client.c -o reneg_client -l:libssl.so.3 -l:libcrypto.so.3
 * Usage: reneg_client PORT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

extern const SSL_METHOD *TLSv1_2_client_method(void);
extern SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
extern SSL *SSL_new(SSL_CTX *ctx);
extern int SSL_set_fd(SSL *ssl, int fd);
extern long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
extern int SSL_connect(SSL *ssl);
extern int SSL_renegotiate(SSL *ssl);
extern int SSL_do_handshake(SSL *ssl);
extern int SSL_get_error(const SSL *ssl, int ret);
extern int SSL_read(SSL *ssl, void *buf, int num);
extern unsigned long ERR_get_error(void);
extern void ERR_error_string_n(unsigned long e, char *buf, size_t len);

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;
    int rc;
    char errbuf[256];
    char rbuf[64];

    if (argc != 2) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 64;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)atoi(argv[1]));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 65;
    }

    ctx = SSL_CTX_new(TLSv1_2_client_method());
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
             "approved.example.test");
    rc = SSL_connect(ssl);
    printf("initial handshake rc=%d\n", rc);
    if (rc != 1)
        return 66;

    rc = SSL_renegotiate(ssl);
    printf("SSL_renegotiate rc=%d\n", rc);
    rc = SSL_do_handshake(ssl);
    if (rc == 1) {
        printf("RENEGOTIATION_COMPLETED\n");
    } else {
        int err = SSL_get_error(ssl, rc);
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        printf("RENEGOTIATION_REFUSED ssl_error=%d detail=%s\n", err, errbuf);
    }
    /* try to read any alert */
    rc = SSL_read(ssl, rbuf, sizeof(rbuf));
    if (rc <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        printf("post-reneg read rc=%d detail=%s\n", rc, errbuf);
    }
    return 0;
}
