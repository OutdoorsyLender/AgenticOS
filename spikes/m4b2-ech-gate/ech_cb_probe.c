/*
 * SPIKE CODE — not production.
 *
 * Candidate A probe: minimal OpenSSL server using SSL_CTX_set_client_hello_cb
 * and SSL_client_hello_get0_ext / SSL_client_hello_get1_extensions_present to
 * observe (log mode) or reject (deny-ech mode) TLS extension 0xfe0d (ECH)
 * before any SNI-based trust decision.
 *
 * The host has no OpenSSL development headers installed (spike evidence:
 * /usr/include/openssl is absent). Prototypes and constants are therefore
 * hand-declared below against the documented OpenSSL 3.x ABI, and the binary
 * links directly against the versioned runtime libraries. Every declaration
 * is cross-checked against the published OpenSSL 3.0+ man pages.
 *
 * Build: gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
 *          ech_cb_probe.c -o ech_cb_probe -l:libssl.so.3 -l:libcrypto.so.3
 *
 * Usage: ech_cb_probe MODE PORT CERT KEY
 *   MODE = log      -> log extension IDs + SNI, never reject at the callback
 *   MODE = deny-ech -> return SSL_CLIENT_HELLO_ERROR if 0xfe0d is present
 *
 * The probe accepts exactly one TCP connection on 127.0.0.1:PORT, runs one
 * TLS handshake attempt, prints observation lines to stdout, and exits.
 * Lines (protocol for the Python harness):
 *   CHCB fire=<n> exts=<comma-hex> ech=<0|1> sni_cb_yet=<0|1>
 *   SNICB fire=<n> name=<string|NONE>
 *   RESULT outcome=<ok|fail> detail=<string>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* ---- hand-declared OpenSSL ABI (headers absent on this host) ----------- */

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

extern const SSL_METHOD *TLS_server_method(void);
extern SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
extern void SSL_CTX_free(SSL_CTX *ctx);
extern int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file,
                                              int type);
extern int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file,
                                       int type);
extern long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
extern long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd,
                                  void (*fp)(void));

extern SSL *SSL_new(SSL_CTX *ctx);
extern void SSL_free(SSL *ssl);
extern int SSL_set_fd(SSL *ssl, int fd);
extern int SSL_accept(SSL *ssl);
extern int SSL_get_error(const SSL *ssl, int ret);
extern const char *SSL_get_servername(const SSL *ssl, const int type);

extern void SSL_CTX_set_client_hello_cb(
    SSL_CTX *ctx,
    int (*cb)(SSL *s, int *al, void *arg),
    void *arg);
extern int SSL_client_hello_get0_ext(const SSL *s, unsigned int ext_type,
                                     const unsigned char **out,
                                     size_t *outlen);
extern int SSL_client_hello_get1_extensions_present(SSL *s, int **out,
                                                    size_t *outlen);
extern int SSL_client_hello_get_extension_order(SSL *s, uint16_t *exts,
                                                size_t *num_exts);
extern int SSL_client_hello_isv2(const SSL *s);

/* custom extension API: register 0xfe0d so it becomes visible to us.
 * NOTE: this build exports only the original 6-argument parse callback ABI
 * (SSL_CTX_add_custom_ext); the 9-argument _ex form is not available. */
typedef struct x509_st X509;
typedef int (*custom_ext_add_cb)(SSL *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 X509 *x, size_t chainidx, int *al,
                                 void *add_arg);
typedef void (*custom_ext_free_cb)(SSL *s, unsigned int ext_type,
                                   const unsigned char *out, void *add_arg);
typedef int (*custom_ext_parse_cb)(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *parse_arg);
extern int SSL_CTX_add_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  unsigned int context,
                                  custom_ext_add_cb add_cb,
                                  custom_ext_free_cb free_cb, void *add_arg,
                                  custom_ext_parse_cb parse_cb,
                                  void *parse_arg);
#define SSL_EXT_CLIENT_HELLO 0x0001

extern unsigned long ERR_get_error(void);
extern void ERR_error_string_n(unsigned long e, char *buf, size_t len);
/* OPENSSL_free is a macro over CRYPTO_free in OpenSSL 3.x */
extern void CRYPTO_free(void *addr, const char *file, int line);
#define OPENSSL_free(addr) CRYPTO_free((addr), "ech_cb_probe.c", 0)

/* constants from the public OpenSSL headers (stable ABI values) */
#define SSL_FILETYPE_PEM 1
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54
#define SSL_TLSEXT_ERR_OK 0
#define SSL_CLIENT_HELLO_SUCCESS 1
#define SSL_CLIENT_HELLO_ERROR 0
#define SSL_AD_ILLEGAL_PARAMETER 47
#define TLSEXT_TYPE_host_name 0
#define EXT_ECH 0xfe0d

/* ---- probe state -------------------------------------------------------- */

struct probe_state {
    int mode_deny_ech;
    int chcb_fires;
    int snicb_fires;
    int ech_seen;
};

static struct probe_state g_state;

static int custom_add_cb(SSL *s, unsigned int ext_type,
                         const unsigned char **out, size_t *outlen, X509 *x,
                         size_t chainidx, int *al, void *add_arg)
{
    (void)s; (void)ext_type; (void)out; (void)outlen;
    (void)x; (void)chainidx; (void)al; (void)add_arg;
    return 0; /* never send this extension */
}

static int custom_parse_cb(SSL *s, unsigned int ext_type,
                           const unsigned char *in, size_t inlen,
                           int *al, void *parse_arg)
{
    struct probe_state *st = parse_arg;
    (void)s; (void)in;
    printf("CUSTEXT type=%04x inlen=%zu sni_cb_yet=%d chcb_yet=%d\n",
           ext_type, inlen,
           st->snicb_fires > 0 ? 1 : 0, st->chcb_fires);
    fflush(stdout);
    if (ext_type == EXT_ECH) {
        st->ech_seen = 1;
        if (st->mode_deny_ech) {
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return 0; /* fatal: reject before any SNI trust */
        }
    }
    return 1;
}

static int servername_cb(SSL *ssl, int *ad, void *arg)
{
    const char *name;
    (void)ad;
    (void)arg;
    g_state.snicb_fires++;
    name = SSL_get_servername(ssl, TLSEXT_TYPE_host_name);
    printf("SNICB fire=%d name=%s\n", g_state.snicb_fires,
           name != NULL ? name : "NONE");
    fflush(stdout);
    return SSL_TLSEXT_ERR_OK;
}

static int client_hello_cb(SSL *ssl, int *al, void *arg)
{
    struct probe_state *st = arg;
    const unsigned char *ech = NULL;
    size_t ech_len = 0;
    int *exts = NULL;
    size_t nexts = 0;
    size_t i;
    int has_ech;

    st->chcb_fires++;
    has_ech = SSL_client_hello_get0_ext(ssl, EXT_ECH, &ech, &ech_len);
    if (has_ech)
        st->ech_seen = 1;
    {
        const unsigned char *p = NULL;
        size_t n = 0;
        int r_cafe = SSL_client_hello_get0_ext(ssl, 0xcafe, &p, &n);
        int r_sni = SSL_client_hello_get0_ext(ssl, 0x0000, &p, &n);
        size_t norder = 0;
        size_t i2;
        int rc1 = SSL_client_hello_get_extension_order(ssl, NULL, &norder);
        uint16_t order_buf[512];
        size_t order_cap = 512;
        int rc2;
        printf("PROBE get0_cafe=%d get0_sni=%d order_count_rc=%d order_n=%zu\n",
               r_cafe, r_sni, rc1, norder);
        rc2 = SSL_client_hello_get_extension_order(ssl, order_buf, &order_cap);
        printf("PROBE order_rc=%d order=", rc2);
        if (rc2 == 1)
            for (i2 = 0; i2 < order_cap; i2++)
                printf("%s%04x", i2 == 0 ? "" : ",", (unsigned int)order_buf[i2]);
        printf("\n");
        fflush(stdout);
    }

    printf("CHCB fire=%d isv2=%d ech=%d ech_len=%zu sni_cb_yet=%d exts=",
           st->chcb_fires, SSL_client_hello_isv2(ssl), has_ech,
           has_ech ? ech_len : (size_t)0,
           st->snicb_fires > 0 ? 1 : 0);
    if (SSL_client_hello_get1_extensions_present(ssl, &exts, &nexts)) {
        for (i = 0; i < nexts; i++)
            printf("%s%04x", i == 0 ? "" : ",", (unsigned int)exts[i]);
        OPENSSL_free(exts);
        exts = NULL;
    }
    printf("\n");
    fflush(stdout);

    if (st->mode_deny_ech && has_ech) {
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return SSL_CLIENT_HELLO_ERROR;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

int main(int argc, char **argv)
{
    const char *mode;
    int port;
    unsigned int reg_ext;
    int listen_fd;
    int conn_fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;
    int rc;
    char errbuf[256];
    int one = 1;

    if (argc < 5 || argc > 6) {
        fprintf(stderr, "usage: %s MODE PORT CERT KEY [reg_ext_hex]\n", argv[0]);
        return 64;
    }
    mode = argv[1];
    port = atoi(argv[2]);
    reg_ext = (argc == 6) ? (unsigned int)strtoul(argv[5], NULL, 16) : EXT_ECH;
    memset(&g_state, 0, sizeof(g_state));
    g_state.mode_deny_ech = strcmp(mode, "deny-ech") == 0;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 65;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, argv[3], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "cert/key load failed\n");
        return 66;
    }
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, &g_state);
    /* Register 0xfe0d as a custom extension so this ECH-disabled OpenSSL
     * build makes it visible; the parse callback fires during extension
     * parsing, before the servername callback and before client_hello_cb. */
    if (!SSL_CTX_add_custom_ext(ctx, reg_ext, SSL_EXT_CLIENT_HELLO,
                                custom_add_cb, NULL, NULL,
                                custom_parse_cb, &g_state)) {
        fprintf(stderr, "add_custom_ext(0xfe0d) failed\n");
        return 71;
    }
    /* SSL_CTX_set_tlsext_servername_callback is a macro over callback_ctrl */
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                          (void (*)(void))servername_cb);
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, NULL);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 67;
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 68;
    }
    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        return 69;
    }
    printf("READY\n");
    fflush(stdout);

    conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        return 70;
    }
    close(listen_fd);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, conn_fd);
    rc = SSL_accept(ssl);
    if (rc == 1) {
        printf("RESULT outcome=ok sni_cb_fires=%d chcb_fires=%d ech_seen=%d\n",
               g_state.snicb_fires, g_state.chcb_fires, g_state.ech_seen);
    } else {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        printf("RESULT outcome=fail sni_cb_fires=%d chcb_fires=%d ech_seen=%d "
               "detail=%s\n",
               g_state.snicb_fires, g_state.chcb_fires, g_state.ech_seen,
               errbuf);
    }
    fflush(stdout);

    SSL_free(ssl);
    close(conn_fd);
    SSL_CTX_free(ctx);
    return 0;
}
