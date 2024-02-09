#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "string.h" // for strlen
//debug
//#include "mbedtls/debug.h"


#include "mbedtls/x509_crt.h"

// Add a global certificate chain variable
//mbedtls_x509_crt cacert;

void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    (void) ctx;
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

void print_net_context(const mbedtls_net_context *ctx) {
    const unsigned char *bytePtr = (const unsigned char *)ctx;
    size_t i;
    mbedtls_printf("net context\n");
    for (i = 0; i < sizeof(mbedtls_net_context); ++i) {
        mbedtls_printf("%02X ", bytePtr[i]);
        if ((i + 1) % 16 == 0)
            mbedtls_printf("\n");
    }
    mbedtls_printf("\n");
}

void print_ssl_config(const mbedtls_ssl_config *ctx) {
    const unsigned char *bytePtr = (const unsigned char *)ctx;
    size_t i;
    mbedtls_printf("ssl config\n");
    for (i = 0; i < sizeof(mbedtls_net_context); ++i) {
        mbedtls_printf("%02X ", bytePtr[i]);
        if ((i + 1) % 16 == 0)
            mbedtls_printf("\n");
    }
    mbedtls_printf("\n");
}

void print_ssl_context(const mbedtls_ssl_context *ctx) {
    const unsigned char *bytePtr = (const unsigned char *)ctx;
    size_t i;
    mbedtls_printf("ssl context\n");
    for (i = 0; i < sizeof(mbedtls_net_context); ++i) {
        mbedtls_printf("%02X ", bytePtr[i]);
        if ((i + 1) % 16 == 0)
            mbedtls_printf("\n");
    }
    mbedtls_printf("\n");
}






void initialize_mbedtls(mbedtls_net_context *ctx,
                          mbedtls_ssl_context *ssl,
                          mbedtls_ssl_config *conf,
                          mbedtls_entropy_context *entropy,
                          mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *cacert)
{
    const char *pers = "mbedtls_client";

// debug print of addresses
    mbedtls_printf("entering init function\n");
    mbedtls_printf("Address of ctx: %p\n", (void *)ctx);
    mbedtls_printf("Address of ssl: %p\n", (void *)ssl);
    mbedtls_printf("Address of conf: %p\n", (void *)conf);
    mbedtls_printf("Address of entropy: %p\n", (void *)entropy);
    mbedtls_printf("Address of ctr_drbg: %p\n", (void *)ctr_drbg);


    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);

    mbedtls_net_init(ctx);

    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);

    mbedtls_ssl_init(ssl);

    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);

    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);
    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);

    mbedtls_x509_crt_init(cacert); // Initialize the certificate chain

    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);


    // Seed the random number generator
    mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) pers, strlen(pers));


    // Set up the SSL/TLS structure
    mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    // Load the trusted CA certificates
    int ret = mbedtls_x509_crt_parse_file(cacert, "./ca-certificates.crt");
    //int ret = mbedtls_x509_crt_parse_file(cacert, "./isrgrootx1.pem");

    if (ret != 0) {
        // Handle error: Failed to parse CA certificates
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Failed to parse CA certificates: %s\n", error_buf);
        return;
    }

    // Set the CA chain for certificate verification
    mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);

// debug
//mbedtls_ssl_conf_dbg(conf, my_debug, stdout);
//mbedtls_debug_set_threshold(4);




    // Continue with the SSL setup
    mbedtls_ssl_setup(ssl, conf);

// debug again
    mbedtls_printf("exiting init function\n");
    mbedtls_printf("Address of ctx: %p\n", (void *)ctx);
    mbedtls_printf("Address of ssl: %p\n", (void *)ssl);
    mbedtls_printf("Address of conf: %p\n", (void *)conf);
    mbedtls_printf("Address of entropy: %p\n", (void *)entropy);
    mbedtls_printf("Address of ctr_drbg: %p\n", (void *)ctr_drbg);


    print_net_context(ctx);
    print_ssl_context(ssl);
    print_ssl_config(conf);


}

void connect_to_server(mbedtls_net_context *ctx,
                       mbedtls_ssl_context *ssl,
                       const char *hostname,
                       const char *port)
{
    mbedtls_printf("entered connect_to_server function\n");
    mbedtls_printf("Address of ctx: %p\n", (void *)ctx);
    mbedtls_printf("Address of ssl: %p\n", (void *)ssl);
    mbedtls_printf("host: %s\n", hostname);
    mbedtls_printf("port: %s\n", port);

    print_net_context(ctx);
    print_ssl_context(ssl);




    mbedtls_printf("ACHTUNG\n");
    // Establish a TCP connection
    mbedtls_net_connect(ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);
    print_net_context(ctx);
    print_ssl_context(ssl);

    mbedtls_printf("ACHTUNG\n");

    // Set the input/output functions for the SSL context
    mbedtls_ssl_set_bio(ssl, ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    print_net_context(ctx);
    print_ssl_context(ssl);



    mbedtls_ssl_set_hostname(ssl, hostname);
    // Perform the SSL handshake
    print_net_context(ctx);
    print_ssl_context(ssl);

    int ret = mbedtls_ssl_handshake(ssl);
    if (ret != 0) {
        // Handle failed handshake
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Handshake failed: %s\n", error_buf);
        return;
    }
    mbedtls_printf("exiting connect_to_server function\n");
    mbedtls_printf("Address of ctx: %p\n", (void *)ctx);
    mbedtls_printf("Address of ssl: %p\n", (void *)ssl);
    print_net_context(ctx);
    print_ssl_context(ssl);


}

//void send_request_and_read_response() {
void send_request_and_read_response(mbedtls_ssl_context *ssl, const char *hostname) {

    mbedtls_printf("got hostname: %s\n", hostname);
    //const char *http_request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n";

    const char *http_request_format = "GET / HTTP/1.1\r\nHost: %s\r\n\r\n";
    char http_request[256]; // Ensure this buffer is large enough to hold the request string.
    snprintf(http_request, sizeof(http_request), http_request_format, hostname);

    size_t len = strlen(http_request);
    print_ssl_context(ssl);


    // Send an HTTP request over TLS
    mbedtls_ssl_write(ssl, (const unsigned char *) http_request, len);
    print_ssl_context(ssl);


    // Read the server's response
    const int buf_size = 4096;
    unsigned char buf[buf_size];
    int ret = mbedtls_ssl_read(ssl, buf, buf_size - 1);

    print_ssl_context(ssl);


    if (ret > 0) {
        buf[ret] = '\0';
        mbedtls_printf("Received:\n%s\n", buf);
    } else {
        mbedtls_printf("Receive failed\n");// Handle read error or connection close
    }
}

void close_connection(mbedtls_net_context *ctx,
                      mbedtls_ssl_context *ssl,
                      mbedtls_ssl_config *conf,
                      mbedtls_entropy_context *entropy,
                      mbedtls_ctr_drbg_context *ctr_drbg) {

    mbedtls_ssl_close_notify(ssl);
    mbedtls_net_free(ctx);
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
}

void begin(const char *hostname1, const char *port1)
//int main()
{
  const char *hostname="norayr.am"; const char *port="443";
    mbedtls_printf("Got hostname: %s\n", hostname);
  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_x509_crt cacert;

  initialize_mbedtls(&server_fd, &ssl, &conf, &entropy, &ctr_drbg, &cacert);
    //connect_to_server(&server_fd, &ssl, "google.com", "443");
    connect_to_server(&server_fd, &ssl, hostname, port);
    send_request_and_read_response(&ssl, hostname);
    close_connection(&server_fd, &ssl, &conf, &entropy, &ctr_drbg);
}




