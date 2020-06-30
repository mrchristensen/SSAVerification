include "Structs.dfy"
include "Constants.dfy"

module OpenSSLHelpers {
  import opened Structs
  import opened Constants

  method SSL_CTX_get0_certificate(ctx : SSL_CTX) returns (X509 : string)
    requires ctx != null
  {
    // return X509 object that corresponds to the ssl_ctx obj given
    return ctx.X509;
  }

  method SSL_CTX_new(meth : string) returns (ctx : SSL_CTX) 
  {
    var ret : SSL_CTX;
    ret.Init();
    // assert statements here

    ret.meth := meth;
  }

  method SSL_CTX_use_certificate_chain_file() 
  {

  }
}