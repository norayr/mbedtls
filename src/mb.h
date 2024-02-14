//#include "mbedtls/ssl.h"
//#include "mbedtls/net_sockets.h"
//#include "mbedtls/entropy.h"
//#include "mbedtls/ctr_drbg.h"
//#include "mbedtls/config.h"

//void begin(const char *hostname, const char *port, const char *headers, int len);
void begin(const char *hostname, ADDRESS hostname__len, const char *port, ADDRESS port__len, const char *headers, int len);

//int sslConnect(mbedtls_net_context *ctx, mbedtls_ssl_context *ssl, const char * hostname, const char * port);
//int sslConnect(char *ctx, char *ssl, const char * hostname, const char * port);
int sslConnect(char *ctx, char *ssl, const char *conf, const char * entropy, const char * ctr, const char * crt, const char * hostname, const char * port);

void sslDisconnect(char *ctx, char *ssl, char *conf, char *entropy, char *ctr_drbg);
//void sslDisconnect(mbedtls_net_context *ctx, mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg);

//int sslWrite(mbedtls_ssl_context *ssl, const char * req, int rlen);
int sslWrite(char *ssl, char * req, int rlen);

//int sslRead(mbedtls_ssl_context ssl, char *buf, int blen);
int sslRead(char *ssl, char *buf, int blen);


