MODULE mbedtls;

IMPORT SYSTEM, Out;

TYPE
  pstr = SYSTEM.ADDRESS;

PROCEDURE -includeZ
'#include "mb.h"';
(*
PROCEDURE -begin*(host, port, headers: pstr; hl: LONGINT)
"begin(host, port, headers, hl)";
*)
PROCEDURE -begin*(host, port, headers: ARRAY OF CHAR; hl: LONGINT)
"begin(host, host__len,  port, port__len, headers, hl)";


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

PROCEDURE call*(host, port, headers: ARRAY OF CHAR; hlen: LONGINT);
VAR
  phost, pport, phdrs: pstr;
BEGIN
  phost := SYSTEM.ADR(host); pport := SYSTEM.ADR(port); phdrs := SYSTEM.ADR(headers);
  (*begin(phost, pport, phdrs, hlen);*)
   begin(host, port, headers, hlen);
END call;

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

