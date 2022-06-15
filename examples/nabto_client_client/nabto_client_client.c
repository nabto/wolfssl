#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>

#include <stdarg.h>

#if defined(HAVE_ALPN)

const char* ip = "127.0.0.1";
uint16_t port = 22222;

static void print_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    exit(1);
}

void client_test(void);
void logging_callback(const int logLevel, const char* const logMessage);

void logging_callback(const int logLevel, const char* const logMessage) {
    printf("%d: %s\n", logLevel, logMessage);
}

static void* cbData = (void*)42;

static int verify_callback(int foo, WOLFSSL_X509_STORE_CTX* chain)
{
    (void)foo;
    (void)chain;
    if (chain->userCtx != cbData) {
        print_error("");
    }
    return WOLFSSL_SUCCESS;
}

void client_test()
{
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();

    WOLFSSL_METHOD *method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);


    const char *cipherList = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
    if (wolfSSL_CTX_set_cipher_list(ctx, cipherList) != WOLFSSL_SUCCESS)
    {
        print_error("server can't set custom cipher list");
    }

    wolfSSL_CTX_set_verify(ctx, (SSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), verify_callback);

    WOLFSSL* ssl = wolfSSL_new(ctx);

    wolfSSL_SetCertCbCtx(ssl, cbData);

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



    const char* alpnList = "n5";

    if (wolfSSL_UseALPN(ssl, (char*)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS) {
        print_error("cannot set alpns");
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(port);

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        print_error("connect failed");
    }

    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS) {
        print_error("failed to set fd");
    }

    ec = wolfSSL_connect(ssl);
    if (ec != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ec);
        print_error("connect failed %d",err);
    }

    const char* data = "hello";

    if (wolfSSL_write(ssl, data, strlen(data)) != (int)strlen(data)) {
        print_error("failed to write data to connection");
    }

    uint8_t buffer[42];
    if (wolfSSL_read(ssl, buffer, sizeof(buffer)) != (int)strlen(data)) {
        print_error("wrong amount of bytes read");
    }

    close(fd);
    shutdown(fd, SHUT_RDWR);
    printf("test done\n");

}

int main()
{
    wolfSSL_Init();
    client_test();
    wolfSSL_Cleanup();
}

#else
int main() {
    printf("missing required configuration options\n");
}
#endif
