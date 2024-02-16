MODULE https;

IMPORT SYSTEM, Strings, Out,
       http, strTypes, strUtils, mbedtls;

TYPE
   TLSSocket = POINTER TO TLSSocketDesc;
   TLSSocketDesc = RECORD(http.transportDesc)
     netContext* : ARRAY 512 OF CHAR;    (* 4 bytes are enough *)
     sslContext* : ARRAY 512 OF CHAR;   (* 472 bytes *)
     sslConf*    : ARRAY 512 OF CHAR;   (* 400 bytes *)
   END;

   TLSClient = POINTER TO TLSClientDesc;
   TLSClientDesc* = RECORD(http.ClientDesc)
     entropy*    : ARRAY 40000 OF CHAR; (* 1080 on x86_64, 37000 on armhl *)
     ctrDrbg*    : ARRAY 512 OF CHAR;   (* 392 bytes *)
     cacert*     : ARRAY 1024 OF CHAR; (* 616 bytes *)
   END;

PROCEDURE -aaa
'#include "mb.h"';

PROCEDURE connector(VAR h: http.Client):BOOLEAN;
VAR i: LONGINT;
BEGIN
  h.connectionFlag := FALSE;
  IF h^.trn IS TLSSocket THEN
    i := mbedtls.connect(h^.trn(TLSSocket).netContext, h^.trn(TLSSocket).sslContext, h^.trn(TLSSocket).sslConf, h(TLSClient)^.entropy, h(TLSClient)^.ctrDrbg, h(TLSClient)^.cacert, h^.host^, h^.port^);
    IF i = 0 THEN h^.connectionFlag := TRUE ELSE h^.connectionFlag := FALSE END;
  ELSE
    Out.String("https client is not initialized with tls socket"); Out.Ln;
    HALT(5);
  END;
  RETURN h^.connectionFlag
END connector;

PROCEDURE disconnector(VAR h: http.Client);
BEGIN
  IF h IS TLSClient THEN
    mbedtls.disconnect(h^.trn(TLSSocket).netContext, h^.trn(TLSSocket).sslContext, h^.trn(TLSSocket).sslConf, h(TLSClient)^.entropy, h(TLSClient)^.ctrDrbg);
  ELSE
    Out.String("https client is not initialized with tls socket"); Out.Ln;
    HALT(5);
  END;
END disconnector;

PROCEDURE writer(VAR h: http.Client; buf: ARRAY OF CHAR):BOOLEAN;
VAR
  len: LONGINT; r: LONGINT;
BEGIN
  r := -1;
  IF h^.trn IS TLSSocket THEN
    len := Strings.Length(buf);
    r := mbedtls.write(h^.trn(TLSSocket).sslContext, buf, len);
  ELSE
    Out.String("https client is not initialized with tls socket"); Out.Ln;
    HALT(5);
  END;
  RETURN r = 0;
END writer;

PROCEDURE reader(VAR h: http.Client; VAR buf: ARRAY OF CHAR; toRead: LONGINT): BOOLEAN;
VAR
  len: LONGINT;
  r: LONGINT;
BEGIN
    r := -1;
  IF h^.trn IS TLSSocket THEN
    IF toRead = -1 THEN len := LEN(buf)-1 ELSE len := toRead END;
    r := mbedtls.read(h^.trn(TLSSocket).sslContext, buf, len);
  ELSE
    Out.String("https client is not initialized with tls socket"); Out.Ln;
    HALT(5);
  END;
  RETURN (r > 0)
END reader;

  (* returns number of bytes read *)

PROCEDURE readBuf(VAR h: http.Client; VAR buf: ARRAY OF CHAR; VAR haveRead: LONGINT): BOOLEAN;
VAR
  r: LONGINT;
BEGIN
  h^.connectionFlag := FALSE;
  IF h^.trn IS TLSSocket THEN
    r := mbedtls.readBuf(h^.trn(TLSSocket).netContext, h^.trn(TLSSocket).sslContext, buf, haveRead);
    IF r <= 0 THEN
      h^.connectionFlag := FALSE;
      haveRead := 0;
    ELSE
      h^.connectionFlag := TRUE
    END;
   ELSE
    Out.String("https client is not initialized with tls socket"); Out.Ln;
    HALT(5);
  END;
  RETURN h^.connectionFlag
END readBuf;

PROCEDURE Create*(host, port, path: ARRAY OF CHAR): TLSClient;
VAR
  hs: TLSClient;
  socket: TLSSocket;
BEGIN
  NEW(hs);
  hs^.eol[0] := 0DX;  hs^.eol[1] := 0AX; hs^.null[0] := 0X;
  strUtils.string2pstring(host, hs^.host);
  strUtils.string2pstring(port, hs^.port);
  strUtils.string2pstring(path, hs^.path);
  strUtils.string2pstring(http.defUserAgent, hs^.userAgent);
  strUtils.string2pstring(http.defHttpVersion, hs^.version);

  hs^.Get := http.get;
  hs^.setUserAgent := http.setuseragent;
  hs^.clearState := http.clearstate;
  hs^.Save := http.save;
  http.formReqHeader(hs);
  (*dumpHeaders(http^.reqHeader);*)


  hs^.rspnPstrings          := NIL;
  hs^.rspnFirstLine         := NIL;
  hs^.rspnDate              := NIL;
  hs^.rspnServer            := NIL;
  hs^.rspnLastModified      := NIL;
  hs^.rspnETag              := NIL;
  hs^.rspnAcceptRanges      := NIL;
  hs^.rspnContentLength     := 0;
  hs^.rspnVary              := NIL;
  hs^.rspnContentType       := NIL;
  hs^.rspnTransferEncoding  := NIL;
  hs^.rspnConnection        := NIL;
  hs^.rspnCacheControl      := NIL;
  hs^.rspnExpires           := NIL;
  hs^.rspnLocation          := NIL;
  hs^.rspnReportTo          := NIL;
  hs^.rspnNEL               := NIL;
  hs^.rspnCFRAY             := NIL;
  hs^.rspnBody              := NIL;

  NEW(socket);
  hs^.trn := socket;
  hs.Connect := connector;
  hs.Disconnect := disconnector;
  hs.Read := reader;
  hs.ReadBuf := readBuf;
  hs.Write := writer;

  RETURN hs

END Create;

(*
PROCEDURE zeroArr(VAR arr: ARRAY OF CHAR);
VAR
  i: LONGINT;
BEGIN
  i := 0;
  REPEAT
    arr[i] := 0;
    INC(i);
  UNTIL i = LEN(arr);
END zeroArr;

PROCEDURE dump(VAR arr: ARRAY OF SYSTEM.BYTE);
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
*)

PROCEDURE test;
VAR
  h: TLSClient;
  host: ARRAY 64 OF CHAR; port: ARRAY 8 OF CHAR;
  answer: strTypes.pstring;
BEGIN
  (*COPY("norayr.am", host); COPY("443", port);*)
  COPY("xn--y9a5bft.xn--y9a3aq", host); COPY("443", port);
  (*h := Create(host, port, "/index.html");*)
  h := Create(host, port, "/SETs.pdf");
  answer := h.Get(h);
  h.Save(h);
END test;

BEGIN
  test
END https.

