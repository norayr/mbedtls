MODULE testHttps;
IMPORT https, strTypes;

PROCEDURE test;
VAR
  h: https.TLSClient;
  host: ARRAY 64 OF CHAR; port: ARRAY 8 OF CHAR;
  answer: strTypes.pstring;
BEGIN
  (*COPY("norayr.am", host); COPY("443", port);*)
  COPY("xn--y9a5bft.xn--y9a3aq", host); COPY("443", port);
  (*h := https.Create(host, port, "/index.html");*)
  h := https.Create(host, port, "/SETs.pdf");
  answer := h.Get(h);
  h.Save(h);
END test;


BEGIN
  test
END testHttps.
