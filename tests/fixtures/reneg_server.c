/*
 * CONFORMANCE FIXTURE — tests only, not production.
 *
 * Minimal TLS 1.2 server double: completes one handshake (selecting ALPN
 * http/1.1, the only protocol the origin leg accepts) and then sends a
 * server-initiated HelloRequest (SSL_renegotiate), verifying an origin
 * client context hardened with OP_NO_RENEGOTIATION refuses it.  This is
 * the inverted counterpart of reneg_client.c: there the worker-facing
 * server is under test and the C probe is the client; here the origin
 * TLS CLIENT is under test and this probe is the server.  Hand-declared
 * prototypes: the host has no OpenSSL development headers.
 *
 * Build: cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
 *          reneg_server.c -o reneg_server -l:libssl.so.3 -l:libcrypto.so.3
 * Usage: reneg_server CERT_PEM KEY_PEM
 *   Binds 127.0.0.1:0 and prints "PORT <n>" on stdout before accepting.
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

extern const SSL_METHOD *TLSv1_2_server_method(void);
extern SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
extern int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
extern int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file,
                                       int type);
extern SSL *SSL_new(SSL_CTX *ctx);
extern int SSL_set_fd(SSL *ssl, int fd);
extern int SSL_accept(SSL *ssl);
extern int SSL_renegotiate(SSL *ssl);
extern int SSL_renegotiate_pending(const SSL *ssl);
extern int SSL_do_handshake(SSL *ssl);
extern int SSL_get_error(const SSL *ssl, int ret);
extern int SSL_read(SSL *ssl, void *buf, int num);
extern unsigned long ERR_get_error(void);
extern void ERR_error_string_n(unsigned long e, char *buf, size_t len);
extern int SSL_CTX_set_alpn_select_cb(
    SSL_CTX *ctx,
    int (*cb)(SSL *ssl, const unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg),
    void *arg);

#define SSL_FILETYPE_PEM 1
#define SSL_TLSEXT_ERR_OK 0
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

/* The OpenSSL 3.5 server-side ALPN select callback returns the RAW
 * protocol name (no length prefix) via the out/outlen parameters; the
 * library adds
 * the length prefixes itself when it constructs the extension.  (The
 * CLIENT-side SSL_CTX_set_alpn_protos in reneg_client.c takes the
 * length-prefixed wire format instead — the two APIs differ.) */
static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char proto[] = "http/1.1";
    (void)ssl;
    (void)in;
    (void)inlen;
    (void)arg;
    *out = proto;
    *outlen = (unsigned char)(sizeof(proto) - 1);
    return SSL_TLSEXT_ERR_OK;
}

int main(int argc, char **argv)
{
    int listener, fd, rc, attempt;
    struct sockaddr_in addr;
    socklen_t addrlen;
    SSL_CTX *ctx;
    SSL *ssl;
    char errbuf[256];
    char rbuf[64];

    if (argc != 3) {
        fprintf(stderr, "usage: %s CERT_PEM KEY_PEM\n", argv[0]);
        return 64;
    }
    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 65;
    }
    if (listen(listener, 1) < 0) {
        perror("listen");
        return 65;
    }
    addrlen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) < 0) {
        perror("getsockname");
        return 65;
    }
    printf("PORT %u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);

    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (SSL_CTX_use_certificate_chain_file(ctx, argv[1]) != 1) {
        fprintf(stderr, "certificate load failed\n");
        return 66;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "key load failed\n");
        return 66;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, NULL);

    fd = accept(listener, NULL, NULL);
    if (fd < 0) {
        perror("accept");
        return 67;
    }
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    rc = SSL_accept(ssl);
    printf("initial handshake rc=%d\n", rc);
    fflush(stdout);
    if (rc != 1)
        return 68;

    /* Server-initiated renegotiation: send HelloRequest, then drive the
     * second handshake.  A server-side HelloRequest is only a REQUEST —
     * the second handshake is client-driven, so SSL_do_handshake rc==1
     * here means nothing on its own.  Drive reads until the pending
     * renegotiation resolves: a complying client completes it
     * (SSL_renegotiate_pending drops to 0); an OP_NO_RENEGOTIATION client
     * answers with a no_renegotiation alert and the read fails. */
    rc = SSL_renegotiate(ssl);
    printf("SSL_renegotiate rc=%d\n", rc);
    rc = SSL_do_handshake(ssl);
    printf("HelloRequest drive rc=%d\n", rc);
    fflush(stdout);
    for (attempt = 0; attempt < 4; attempt++) {
        rc = SSL_read(ssl, rbuf, sizeof(rbuf));
        if (!SSL_renegotiate_pending(ssl)) {
            printf("RENEGOTIATION_COMPLETED read_rc=%d\n", rc);
            break;
        }
        if (rc <= 0) {
            int err = SSL_get_error(ssl, rc);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            printf("reneg read rc=%d ssl_error=%d detail=%s\n",
                   rc, err, errbuf);
            fflush(stdout);
            if (strstr(errbuf, "no renegotiation") != NULL) {
                printf("RENEGOTIATION_REFUSED\n");
                break;
            }
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                break;
        }
    }
    fflush(stdout);
    return 0;
}
