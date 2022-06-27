//#include <config.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>

#include <stdarg.h>
#include <stdbool.h>

#if defined(HAVE_ALPN) && defined(KEEP_PEER_CERT)

static uint16_t port = 22222;

static void print_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    exit(1);
}

static void logging_callback(const int logLevel, const char *const logMessage)
{
    printf("%d: %s\n", logLevel, logMessage);
}

static int verify_callback(int foo, WOLFSSL_X509_STORE_CTX *chain)
{
    (void)foo;
    (void)chain;
    return WOLFSSL_SUCCESS;
}

static void server_test()
{
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();

    int listenFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenFd < 0)
    {
        print_error("cannot create listen fd");
    }

    // int optVal = 1;
    // if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) == -1) {
    //     print_error("cannot set reuseaddr");
    // }

    {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(struct sockaddr_in));
        sa.sin_addr.s_addr = inet_addr("0.0.0.0");
        sa.sin_port = htons(port);
        sa.sin_family = AF_INET;

        int ec = bind(listenFd, (struct sockaddr *)&sa, sizeof(sa));
        if (ec < 0) {
            print_error("bind failed");
        }
    }

    // int ec = listen(listenFd, 1);
    // if (ec != 0) {
    //     print_error("listen failed");
    // }

    // struct sockaddr acceptSa;
    // socklen_t acceptSaLen;
    // int fd = accept(listenFd, &acceptSa, &acceptSaLen);
    // if (fd < 0) {
    //     print_error_fmt("accept failed %d", errno);
    // }

    // const char *verifyCert = cliEccCertFile;
    const char *ourCert = eccCertFile;
    const char *ourKey = eccKeyFile;
    const char *caCert = caEccCertFile;
    WOLFSSL_METHOD *method = 0;
    method = wolfDTLSv1_2_server_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);

    // our protocol uses TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    const char *cipherList = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    if (wolfSSL_CTX_set_cipher_list(ctx, cipherList) != WOLFSSL_SUCCESS)
    {
        print_error("server can't set custom cipher list");
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCert, NULL) != WOLFSSL_SUCCESS)
    {
        print_error("cannot load ca certificate");
    }

    if (wolfSSL_CTX_use_certificate_chain_file(ctx, ourCert) != WOLFSSL_SUCCESS)
    {
        print_error("can't load server cert file, check file and run from wolfSSL home dir");
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, ourKey, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        print_error("cannot load private key");
    }

    wolfSSL_CTX_set_verify(ctx, (SSL_VERIFY_PEER), verify_callback);

    WOLFSSL *ssl = wolfSSL_new(ctx);

    const char *alpnList = "n5";

    if (wolfSSL_UseALPN(ssl, (char *)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
        print_error("cannot set alpns");
    }

    bool connection = false;
    do
    {
        uint8_t buffer[1500];
        struct sockaddr_in sa;
        socklen_t saLen = sizeof(sa);

        ssize_t recvLen = recvfrom(listenFd, buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr *)(&sa), &saLen);
        if (recvLen <= 0)
        {
        }
        else
        {
            printf("got packet %i\n", (int)recvLen);
            if (buffer[0] == 0x16)
            {
                connection = true;
                wolfSSL_dtls_set_peer(ssl, &sa, saLen);
            }
            else {
                // discard the packet
                recvfrom(listenFd, buffer, sizeof(buffer), 0, (struct sockaddr *)(&sa), &saLen);
            }
        }

    } while (!connection);

    wolfSSL_set_fd(ssl, listenFd);

    usleep(10000);
    wolfSSL_accept(ssl);
    usleep(10000);



    // Get client fingerprint
    //WOLFSSL_X509 *peerCert = wolfSSL_get_peer_certificate(ssl);
    //if (peerCert == NULL)
    //{
    //    print_error("could not get peer cert");
    //}

    uint8_t buffer[42];

    int len = wolfSSL_read(ssl, buffer, sizeof(buffer));
    if (len < 0)
    {
        print_error("read from connectedion failed.");
    }
    usleep(10000);

    int written = wolfSSL_write(ssl, buffer, len);
    if (written != len)
    {
        print_error("failed to write the right amount of bytes to the ssl connection");
    }

    usleep(10000);

    // close(fd);
    // shutdown(fd,SHUT_RDWR);
    close(listenFd);
}

int main()
{
    wolfSSL_Init();
    ChangeToWolfRoot();
    server_test();
    wolfSSL_Cleanup();
}

#else
int main()
{
    printf("missing required configuration options.\n");
}
#endif
