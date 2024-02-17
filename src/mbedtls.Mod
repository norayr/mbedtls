MODULE mbedtls;

IMPORT SYSTEM, Out, Strings := oocStrings, http;


PROCEDURE -aincludeA
'#include "mbedtls/net.h"';

PROCEDURE -aincludeB
'#include "mbedtls/ssl.h"';

PROCEDURE -aincludeE
'#include "mbedtls/entropy.h"';

PROCEDURE -aincludeC
'#include "mbedtls/ctr_drbg.h"';

PROCEDURE -aincludeCo
'#include "mbedtls/config.h"';


PROCEDURE -aincludeNS
'#include "mbedtls/net_sockets.h"';

PROCEDURE -aincludex509crt
'#include "mbedtls/x509_crt.h"';

(*
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
*)
(*
#include "mbedtls/error.h"
#include "string.h" // for strlen
*)
(*
PROCEDURE -aaa
'#include "mb.h"';
*)

PROCEDURE -netInit(VAR ctx: ARRAY OF SYSTEM.BYTE)
"mbedtls_net_init( (mbedtls_net_context *) ctx)";

PROCEDURE -sslInit(VAR ssl: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_init( (mbedtls_ssl_context *) ssl)";

PROCEDURE -sslConfigInit(VAR conf: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_config_init( (mbedtls_ssl_config *) conf )";

PROCEDURE -ctrDrbgInit(VAR ctr: ARRAY OF SYSTEM.BYTE)
"mbedtls_ctr_drbg_init( (mbedtls_ctr_drbg_context *) ctr )";

PROCEDURE -entropyInit(VAR entr: ARRAY OF SYSTEM.BYTE)
"mbedtls_entropy_init( (mbedtls_entropy_context *)entr)";

PROCEDURE -x509ctrInit(VAR cacert: ARRAY OF SYSTEM.BYTE)
"mbedtls_x509_crt_init( (mbedtls_x509_crt *)  cacert)";

PROCEDURE -ctrDrbgSeed(VAR ctr, entr: ARRAY OF SYSTEM.BYTE; pers: ARRAY OF CHAR; plen: LONGINT)
"mbedtls_ctr_drbg_seed((mbedtls_ctr_drbg_context *)ctr, mbedtls_entropy_func, (mbedtls_entropy_context *) entr, pers, plen)";

PROCEDURE -sslConfigDefaults(conf: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_config_defaults((mbedtls_ssl_config *)conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)";

PROCEDURE -sslConfRng(conf, ctr: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_conf_rng(  (mbedtls_ssl_config *) conf, mbedtls_ctr_drbg_random, (mbedtls_ctr_drbg_context *) ctr)";

PROCEDURE -x509crtParseFile(cacert: ARRAY OF SYSTEM.BYTE; path: ARRAY OF CHAR): LONGINT
"(LONGINT)mbedtls_x509_crt_parse_file((mbedtls_x509_crt *)cacert, path)";

PROCEDURE -sslConfCaChain(conf, cacert: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_conf_ca_chain((mbedtls_ssl_config *) conf, (mbedtls_x509_crt *)  cacert, NULL   )";

PROCEDURE -sslSetup(ssl, conf: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_setup( (mbedtls_ssl_context *) ssl, (mbedtls_ssl_config *) conf)";

PROCEDURE -netConnect(VAR net: ARRAY OF SYSTEM.BYTE; hostname, port: ARRAY OF CHAR): LONGINT
"(LONGINT) mbedtls_net_connect((mbedtls_net_context *)net, hostname, port, MBEDTLS_NET_PROTO_TCP)";

PROCEDURE -sslSetBio(VAR ssl, ctx: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_set_bio((mbedtls_ssl_context *)ssl, (mbedtls_net_context *)ctx, mbedtls_net_send, mbedtls_net_recv, NULL)";

PROCEDURE -sslSetHostname(VAR ssl: ARRAY OF SYSTEM.BYTE; VAR hostname: ARRAY OF CHAR): LONGINT
"(LONGINT)mbedtls_ssl_set_hostname((mbedtls_ssl_context *)ssl, hostname)";

PROCEDURE -sslHandshake(VAR ssl: ARRAY OF SYSTEM.BYTE): LONGINT
"(LONGINT) mbedtls_ssl_handshake((mbedtls_ssl_context *)ssl)";

PROCEDURE -sslRead(VAR ssl: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; len: LONGINT):LONGINT
"(LONGINT)mbedtls_ssl_read((mbedtls_ssl_context *)ssl, str, len)";

PROCEDURE -sslWrite(VAR ssl: ARRAY OF SYSTEM.BYTE; VAR req: ARRAY OF CHAR; rlen: LONGINT):LONGINT
"(LONGINT) mbedtls_ssl_write((mbedtls_ssl_context *)ssl, req, rlen)";

PROCEDURE -sslCloseNotify(VAR ssl: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_close_notify((mbedtls_ssl_context *)ssl)";

PROCEDURE -netFree(VAR ctx: ARRAY OF SYSTEM.BYTE)
"mbedtls_net_free((mbedtls_net_context *)ctx)";

PROCEDURE -sslFree(VAR ssl: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_free((mbedtls_ssl_context *)ssl)";

PROCEDURE -sslConfigFree(VAR conf: ARRAY OF SYSTEM.BYTE)
"mbedtls_ssl_config_free((mbedtls_ssl_config *)conf)";

PROCEDURE -ctrDrbgFree(VAR ctr: ARRAY OF SYSTEM.BYTE)
"mbedtls_ctr_drbg_free((mbedtls_ctr_drbg_context *)ctr)";

PROCEDURE -entropyFree(VAR entropy: ARRAY OF SYSTEM.BYTE)
"mbedtls_entropy_free((mbedtls_entropy_context *)entropy)";


PROCEDURE init*(VAR ctx, ssl, conf, entr, ctr, cacert: ARRAY OF SYSTEM.BYTE; pers, certpath: ARRAY OF CHAR);
VAR
  ln, rt: LONGINT;
BEGIN
  netInit(ctx);
  sslInit(ssl);
  sslConfigInit(conf);
  ctrDrbgInit(ctr);
  entropyInit(entr);
  x509ctrInit(cacert);
  ln := Strings.Length(pers);
  ctrDrbgSeed(ctr, entr, pers, ln);
  sslConfigDefaults(conf);
  sslConfRng(conf, ctr);
  rt := x509crtParseFile(cacert, certpath);
  IF rt # 0 THEN
    Out.String("parsing "); Out.String(certpath);
    Out.String(" failed"); Out.Ln;
    HALT(5)
  END;
  sslConfCaChain(conf, cacert);
  sslSetup(ssl, conf);
END init;

PROCEDURE connect*(VAR netCtx, sslCtx, conf, entr, ctr, crt: ARRAY OF SYSTEM.BYTE; VAR host, port: ARRAY OF CHAR): LONGINT;
VAR
  i: LONGINT;
BEGIN
  (* do not forget to init separately*)
  i := netConnect(netCtx, host, port);
  sslSetBio(sslCtx, netCtx);
  i := sslSetHostname(sslCtx, host);
  i := sslHandshake(sslCtx);
  IF i # 0 THEN Out.String("ssl handshake failed"); Out.Ln END;
  RETURN i
END connect;


PROCEDURE disconnect*(VAR netCtx, sslCtx, conf, entr, ctr: ARRAY OF SYSTEM.BYTE): LONGINT;
BEGIN
  sslCloseNotify(sslCtx);
  netFree(netCtx);
  sslFree(sslCtx);
  sslConfigFree(conf);
  ctrDrbgFree(ctr);
  entropyFree(entr);
  RETURN 0;
END disconnect;

PROCEDURE read*(VAR ssl: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; len: LONGINT): LONGINT;
BEGIN
  RETURN sslRead(ssl, str, len);
END read;

PROCEDURE write*(VAR ssl: ARRAY OF SYSTEM.BYTE; VAR req: ARRAY OF CHAR; rlen: LONGINT): LONGINT;
BEGIN
  RETURN sslWrite(ssl, req, rlen);
END write;

PROCEDURE Min(a, b: LONGINT): LONGINT;
BEGIN
  IF a < b THEN
    RETURN a;
  ELSE
    RETURN b;
  END;
END Min;

PROCEDURE sslReadBuf(VAR net, ssl: ARRAY OF SYSTEM.BYTE; VAR output: ARRAY OF CHAR; VAR readLen: LONGINT): LONGINT;
CONST
  chunkSize = 64;
  sslWantRead  = -26880;
  sslWantWrite = -27648;
VAR
  ret, min, i: LONGINT;
  tempBuffer: ARRAY chunkSize OF CHAR; (* Temporary buffer to hold read data *)
  break: BOOLEAN;
BEGIN
  break := FALSE;
  ret := 0;
  WHILE (readLen < LEN(output)) & ~break DO
    min := Min(chunkSize, LEN(output) - readLen); (* Calculate the minimum size to read *)
    ret := sslRead(ssl, tempBuffer, min); (* Read into temporary buffer *)
    IF ret > 0 THEN
      FOR i := 0 TO ret - 1 DO
        output[readLen + i] := tempBuffer[i]; (* Copy from temporary buffer to output *)
      END;
      INC(readLen, ret); (* Update the read length *)
    ELSIF (ret = 0) OR (ret = sslWantRead) OR (ret = sslWantWrite) THEN
      break := TRUE; (* Set break to TRUE to exit loop if no more data to read or if a retry is needed *)
    ELSE
      Out.String("read error: "); Out.Int(ret, 0); Out.Ln;
      RETURN ret; (* Return error code *)
    END;
  END;
  IF readLen > 0 THEN RETURN 0 ELSE RETURN ret END; (* Return success if any data was read *)
END sslReadBuf;

PROCEDURE readBuf*(VAR netCntx, sslCntx: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; VAR len: LONGINT): LONGINT;
BEGIN
  RETURN sslReadBuf(netCntx, sslCntx, str, len);
END readBuf;
(*
PROCEDURE -connect*(VAR netCtx, sslCtx, conf, entr, ctr, crt: ARRAY OF SYSTEM.BYTE; VAR host, port: ARRAY OF CHAR): LONGINT
"(LONGINT)sslConnect(netCtx, sslCtx, conf, entr, ctr, crt, host, port)";
PROCEDURE -disconnect*(VAR netCtx, sslCtx, sslConf, entr, ctr: ARRAY OF SYSTEM.BYTE)
"sslDisconnect(netCtx, sslCtx, sslConf, entr, ctr)";

PROCEDURE -write*(VAR sslCntx: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; len: LONGINT): LONGINT
"(LONGINT)sslWrite(sslCntx, str, len)";

PROCEDURE -read*(VAR sslCntx: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; len: LONGINT): LONGINT
"(LONGINT)sslRead(sslCntx, str, len)";

PROCEDURE -readBuf*(VAR netCntx, sslCntx: ARRAY OF SYSTEM.BYTE; VAR str: ARRAY OF CHAR; VAR len: LONGINT): LONGINT
"(LONGINT)sslReadBuf(netCntx, sslCntx, str, str__len, len)";
*)

PROCEDURE zeroArr*(VAR arr: ARRAY OF SYSTEM.BYTE);
VAR
  i: LONGINT;
BEGIN
  i := 0;
  REPEAT
    arr[i] := 0;
    INC(i);
  UNTIL i = LEN(arr);
END zeroArr;

PROCEDURE dump*(VAR arr: ARRAY OF SYSTEM.BYTE);
VAR
  i: LONGINT;
BEGIN
  Out.String("------------------------------------------------------"); Out.Ln;
  i := 0;
  REPEAT
    IF SYSTEM.VAL(SHORTINT, arr[i]) # 0 THEN
      Out.Int(i, 0); Out.String("  ");
      Out.Int(SYSTEM.VAL(SHORTINT, arr[i]), 0);
      Out.String("  ");  Out.Char(SYSTEM.VAL(CHAR, (arr[i]))); Out.Ln;
    END;
    INC(i);
  UNTIL i = LEN(arr);
  Out.Ln;
  Out.String("------------------------------------------------------"); Out.Ln;
END dump;
(*
PROCEDURE call*(host, port, headers: ARRAY OF CHAR; hlen: LONGINT);
VAR
  phost, pport, phdrs: pstr;
BEGIN
  phost := SYSTEM.ADR(host); pport := SYSTEM.ADR(port); phdrs := SYSTEM.ADR(headers);
  (*begin(phost, pport, phdrs, hlen);*)
   begin(host, port, headers, hlen);
END call;
*)
(*
PROCEDURE test;
VAR
  host: ARRAY 64 OF CHAR;
  port: ARRAY 8 OF CHAR;
  phost, pport: pstr;
BEGIN
  COPY("norayr.am", host); COPY("443", port);
  phost := SYSTEM.ADR(host); pport := SYSTEM.ADR(port);
  begin(phost, pport);
END test;
*)
(*BEGIN
  test*)
END mbedtls.

