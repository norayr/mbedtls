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

    mbedtls_net_init(ctx);

    mbedtls_ssl_init(ssl);

    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    mbedtls_x509_crt_init(cacert); // Initialize the certificate chain

    // Seed the random number generator
    mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) pers, strlen(pers));

    // Set up the SSL/TLS structure
    mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    // Load the trusted CA certificates
    int ret = mbedtls_x509_crt_parse_file(cacert, "./ca-certificates.crt");
    //int ret = mbedtls_x509_crt_parse_file(cacert, "/etc/ssl/certs/ca-certificates.crt");
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

    // Continue with the SSL setup
    mbedtls_ssl_setup(ssl, conf);
}

//int sslConnect(char *ctx, char *ssl, const char * hostname, const char * port)
int sslConnect(char *ctx, char *ssl, const char *conf, const char * entropy, const char * ctr, const char * crt, const char * hostname, const char * port)
{
initialize_mbedtls((mbedtls_net_context *)  ctx,
                    (mbedtls_ssl_context *) ssl,
                    (mbedtls_ssl_config *) conf,
            (mbedtls_entropy_context *) entropy,
            (mbedtls_ctr_drbg_context *)    ctr,
            (mbedtls_x509_crt *)           crt);



    printf("entered sslConnect function\n");
    mbedtls_printf("host: '%s'\n", hostname);
    mbedtls_printf("port: '%s'\n", port);

    int i;
    i = mbedtls_net_connect((mbedtls_net_context *)ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);

    // Set the input/output functions for the SSL context
    mbedtls_ssl_set_bio((mbedtls_ssl_context *)ssl, (mbedtls_net_context *)ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    i= mbedtls_ssl_set_hostname((mbedtls_ssl_context *)ssl, hostname);

    int ret = mbedtls_ssl_handshake((mbedtls_ssl_context *)ssl);
    if (ret != 0) {
        // Handle failed handshake
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Handshake failed: %s\n", error_buf);
    }
    return ret;
}
/*
int sslConnect(char *ctx, char *ssl, const char * hostname, const char * port)
{
    printf("entered sslConnect function\n");
    mbedtls_printf("host: '%s'\n", hostname);
    mbedtls_printf("port: '%s'\n", port);

    int i;
    i = mbedtls_net_connect((mbedtls_net_context *)ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);

    // Set the input/output functions for the SSL context
    mbedtls_ssl_set_bio((mbedtls_ssl_context *)ssl, (mbedtls_net_context *)ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    i= mbedtls_ssl_set_hostname(ssl, hostname);

    int ret = mbedtls_ssl_handshake((mbedtls_ssl_context *)ssl);
    if (ret != 0) {
        // Handle failed handshake
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Handshake failed: %s\n", error_buf);
    }
    return ret;
}
*/

int sslRead(char *ssl, char *buf, int blen)
{
  int i;
  i = mbedtls_ssl_read((mbedtls_ssl_context *)ssl, buf, blen);
  return i;
}
/*
int sslRead(mbedtls_ssl_context *ssl, const char *buf, int blen)
{
  int i;
  i = mbedtls_ssl_read(ssl, buf, blen);
  return i;
}
*/
/*
int sslWrite(mbedtls_ssl_context *ssl, const char *req, int rlen)
{
  int i;
  i = mbedtls_ssl_write(ssl, req, rlen);
  return i;

}
*/
int sslWrite(char *ssl, char *req, int rlen)
{
  int i;
  i = mbedtls_ssl_write((mbedtls_ssl_context *)ssl, req, rlen);
  return i;

}
/*
void send_request_and_read_response(mbedtls_ssl_context *ssl, const char *hostname, const char *headers, int hlen) {


    // Send an HTTP request over TLS
    //mbedtls_ssl_write(ssl, (const unsigned char *) headers, hlen);
    sslWrite(ssl, headers, hlen);

    // Read the server's response
    const int buf_size = 4096;
    unsigned char buf[buf_size];
    int ret = mbedtls_ssl_read(ssl, buf, buf_size - 1);

    if (ret > 0) {
        buf[ret] = '\0';
        mbedtls_printf("Received:\n%s\n", buf);
    } else {
        mbedtls_printf("Receive failed\n");// Handle read error or connection close
    }
}
*/
void sslDisconnect(char *ctx, char *ssl, char *conf, char *entropy, char *ctr_drbg)
{

    mbedtls_ssl_close_notify((mbedtls_ssl_context *)ssl);
    mbedtls_net_free((mbedtls_net_context *)ctx);
    mbedtls_ssl_free((mbedtls_ssl_context *)ssl);
    mbedtls_ssl_config_free((mbedtls_ssl_config *)conf);
    mbedtls_ctr_drbg_free((mbedtls_ctr_drbg_context *)ctr_drbg);
    mbedtls_entropy_free((mbedtls_entropy_context *)entropy);
}

/*
void sslDisconnect(mbedtls_net_context *ctx,
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
*/

#include "/opt/voc/C/include/SYSTEM.h"
/*
void begin(const char *hostname, ADDRESS hostname__len, const char *port, ADDRESS port__len, const char *headers, int len)
{

  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_x509_crt cacert;

  initialize_mbedtls(&server_fd, &ssl, &conf, &entropy, &ctr_drbg, &cacert);
    sslConnect(&server_fd, &ssl, hostname, port);
    send_request_and_read_response(&ssl, hostname, headers, len);
    sslDisconnect(&server_fd, &ssl, &conf, &entropy, &ctr_drbg);
}

*/
