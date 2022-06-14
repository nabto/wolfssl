#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>

#if defined(HAVE_ALPN)

const char* ip = "127.0.0.1";
uint16_t port = 22222;

static void print_error(const char *msg)
{
    printf("%s\n", msg);
    exit(1);
}

void client_test(void);
void logging_callback(const int logLevel, const char* const logMessage);

void logging_callback(const int logLevel, const char* const logMessage) {
    printf("%d: %s\n", logLevel, logMessage);
}


void client_test()
{
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();

    const char *ourCert = cliEccCertFile;
    const char *ourKey = cliEccKeyFile;
    const char* caCert = caEccCertFile;
    WOLFSSL_METHOD *method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);


    const char *cipherList = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
    if (wolfSSL_CTX_set_cipher_list(ctx, cipherList) != WOLFSSL_SUCCESS)
    {
        print_error("server can't set custom cipher list");
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCert, NULL) != WOLFSSL_SUCCESS) {
        print_error("cannot load ca certificate");
    }

    WOLFSSL* ssl = wolfSSL_new(ctx);

    if (wolfSSL_use_PrivateKey_file(ssl, ourKey, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        print_error("could not set private_key");
    }

    int ec = wolfSSL_use_certificate_file(ssl, ourCert, WOLFSSL_FILETYPE_PEM);
    if (ec != WOLFSSL_SUCCESS)
    {
        print_error("can't load client cert file, check file and run from wolfSSL home dir");
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

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        print_error("connect failed");
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
    //func_args args;
    tcp_ready ready;
    StartTCP();
    //args.argc = argc;
    //args.argv = argv;
    //args.signal = &ready;
    //args.return_code = 0;

    InitTcpReady(&ready);
    wolfSSL_Init();
    ChangeToWolfRoot();
    client_test();
    wolfSSL_Cleanup();
    FreeTcpReady(&ready);
}

#else
int main() {
    printf("missing required configuration options\n");
}
#endif
