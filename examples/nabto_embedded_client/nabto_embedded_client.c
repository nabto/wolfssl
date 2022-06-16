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

void client_test(void);
void logging_callback(const int logLevel, const char *const logMessage);

void logging_callback(const int logLevel, const char *const logMessage)
{
    printf("%d: %s\n", logLevel, logMessage);
}

void client_test()
{
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

    wolfSSL_dtls_set_peer(ssl, &sa, sizeof(sa));

    // if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    // {
    //     print_error("connect failed");
    // }



    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
    {
        print_error("failed to set fd");
    }

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS)
    {
        print_error("connect failed");
    }

    const char *data = "hello";

    if (wolfSSL_write(ssl, data, strlen(data)) != (int)strlen(data))
    {
        print_error("failed to write data to connection");
    }

    uint8_t buffer[42];
    if (wolfSSL_read(ssl, buffer, sizeof(buffer)) != (int)strlen(data))
    {
        print_error("wrong amount of bytes read");
    }

    close(fd);
    shutdown(fd, SHUT_RDWR);
    printf("test done\n");
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
