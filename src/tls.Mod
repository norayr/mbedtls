MODULE tls;

IMPORT Out,
       http, strTypes;

(*
PROCEDURE zeroArr(VAR arr: ARRAY OF SYSTEM.BYTE);
VAR
  i: LONGINT;
BEGIN
  i := 0;
  REPEAT
    arr[i] := 0;
    INC(i);
  UNTIL i = LEN(arr);
END zeroArr;
*)
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

PROCEDURE test;
VAR
  h: http.Client;
  host: ARRAY 64 OF CHAR;
  port: ARRAY 8 OF CHAR;
  hdrs: strTypes.pstring;
BEGIN
  COPY("norayr.am", host); COPY("448", port);
  h := http.Create(host, port, "index.html");
  hdrs := http.headersToString(h^.reqHeader);
  dump(hdrs^);
(*
  phost := SYSTEM.ADR(host); pport := SYSTEM.ADR(port);
  begin(phost, pport);
  *)
END test;

BEGIN
  test
END mbedtls.

