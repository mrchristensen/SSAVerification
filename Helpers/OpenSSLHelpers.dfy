include "Structs.dfy"

module OpenSSLHelpers {
  import opened Structs

  method SSL_CTX_get0_certificate(ctx : SSL_CTX) returns (X509 : string)
    requires ctx != null
  {
      // return X509 object that corresponds to the ssl_ctx obj given
      return ctx.X509;
  }
}