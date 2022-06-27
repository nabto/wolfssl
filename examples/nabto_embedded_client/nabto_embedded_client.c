#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#if defined(HAVE_ALPN)

const char *ip = "127.0.0.1";
uint16_t port = 22222;

static void print_error(const char *msg)
{
    printf("%s\n", msg);
    exit(1);
}

static int wolfssl_send(WOLFSSL* ssl, char* buffer,
                         int bufferSize, void* data);
                         static int wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* data);

static void client_test(void);
static void logging_callback(const int logLevel, const char *const logMessage);

void logging_callback(const int logLevel, const char *const logMessage)
{
    printf("%d: %s\n", logLevel, logMessage);
}

struct io_ctx {
    int fd;
    struct sockaddr_in peerAddr;
};

void client_test()
{
    struct io_ctx ioCtx;
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();

    const char *caCert = caEccCertFile;
    WOLFSSL_METHOD *method = wolfDTLSv1_2_client_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);

    // our protocol uses TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    const char *cipherList = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    if (wolfSSL_CTX_set_cipher_list(ctx, cipherList) != WOLFSSL_SUCCESS)
    {
        print_error("server can't set custom cipher list");
    }

    // Load ca such that we can verify the basestation.
    if (wolfSSL_CTX_load_verify_locations(ctx, caCert, NULL) != WOLFSSL_SUCCESS)
    {
        print_error("cannot load ca certificate");
    }

    wolfSSL_SetIORecv(ctx, wolfssl_recv);
    wolfSSL_SetIOSend(ctx, wolfssl_send);
    //wolfSSL_SSLSetIOSend

    WOLFSSL *ssl = wolfSSL_new(ctx);

    // Create a selfsigned certificate, this can be moved somewhere else. The
    // end result is that the embedded dtls client uses a self signed certificate.
    uint8_t derCert[512];

    Cert cert;
    wc_InitCert(&cert);

    strncpy(cert.subject.country, "DK", CTC_NAME_SIZE);
    strncpy(cert.subject.commonName, "nabto", CTC_NAME_SIZE);

    WC_RNG rng;
    if (wc_InitRng(&rng) != 0)
    {
        print_error("failed to init rng");
    }

    ecc_key eccKey;
    if (wc_ecc_init(&eccKey) != 0)
    {
        print_error("failed to init ecc key");
    }

    if (wc_ecc_make_key(&rng, 32, &eccKey) != 0)
    {
        print_error("failed to make ecc key");
    }

    int ret = wc_MakeCert(&cert, derCert, sizeof(derCert), NULL, &eccKey, &rng);
    if (ret < 0)
    {
        print_error("Could not create certificate request");
    }

    int certLen = wc_SignCert(cert.bodySz, cert.sigType,
                              derCert, sizeof(derCert), NULL, &eccKey, &rng);

    uint8_t eccKeyDer[512];
    int len = wc_EccKeyToDer(&eccKey, eccKeyDer, sizeof(eccKeyDer));
    if (len < 0)
    {
        print_error("could not encode private key as der.");
    }

    if (wolfSSL_use_PrivateKey_buffer(ssl, eccKeyDer, len, SSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
    {
        print_error("could not set privatekey from der format");
    }

    int ec = wolfSSL_use_certificate_buffer(ssl, derCert, certLen, WOLFSSL_FILETYPE_ASN1);
    if (ec != WOLFSSL_SUCCESS)
    {
        print_error("could not use cert from buffer");
    }

    const char *alpnList = "n5";

    if (wolfSSL_UseALPN(ssl, (char *)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
        print_error("cannot set alpns");
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(port);

    ioCtx.fd = fd;
    memcpy(&ioCtx.peerAddr, &sa, sizeof(struct sockaddr_in));

    wolfSSL_SetIOReadCtx(ssl, &ioCtx);
    wolfSSL_SetIOWriteCtx(ssl, &ioCtx);

    //wolfSSL_dtls_set_peer(ssl, &sa, sizeof(sa));

    // if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    // {
    //     print_error("connect failed");
    // }



    // if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
    // {
    //    print_error("failed to set fd");
    // }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        print_error("ERROR: failed to set non-blocking");
    }

    wolfSSL_dtls_set_using_nonblock(ssl, 1);

    do {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_FATAL_ERROR) {
            int err = wolfSSL_get_error(ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                // try again
            } else {
                print_error("connect failed");
            }
        }
        usleep(100000);
    } while (ret != WOLFSSL_SUCCESS);

    const char *data = "hello";

    do {
        ret = wolfSSL_write(ssl, data, strlen(data));
    } while (ret <= 0);
    if (ret != (int)strlen(data)) {
        print_error("write failed");
    }

    uint8_t buffer[42];
    do {
        wolfSSL_read(ssl, buffer, sizeof(buffer));
    } while (ret <= 0);
    if (ret != (int)strlen(data)) {
        print_error("read failed");
    }

    close(fd);
    shutdown(fd, SHUT_RDWR);
    printf("test done\n");
}

int wolfssl_send(WOLFSSL* ssl, char* buffer,
                         int bufferSize, void* data)
{
    (void)ssl;
    static int count = 0;
    count++;
    if (count%2 == 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    struct io_ctx* ctx = data;

    int ret = sendto(ctx->fd, buffer, bufferSize, 0, (struct sockaddr*)&ctx->peerAddr, (socklen_t)sizeof(struct sockaddr_in));
    return ret;
}

int wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* data)
{
    (void)ssl;
    struct io_ctx* ctx = data;
    struct sockaddr_in addr;
    socklen_t l = sizeof(struct sockaddr_in);
    static int count = 0;
    count++;
    if (count %2 == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    int ret = recvfrom(ctx->fd, buffer, bufferSize, 0, (struct sockaddr*)&addr, &l);
    if (ret <= 0) {
        if (errno = EWOULDBLOCK || errno == EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        } else {
            print_error("somethind not ewouldblock happened");
        }

    } else {
        return ret;
    }
}



int main()
{
    wolfSSL_Init();
    ChangeToWolfRoot();
    client_test();
    wolfSSL_Cleanup();
}



#else
int main()
{
    printf("missing required configuration options\n");
}
#endif
