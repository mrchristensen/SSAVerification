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

  method SSL_CTX_new(meth : string) returns (ret : SSL_CTX)
    requires meth != ""
    ensures ret != null
    ensures fresh(ret.cert_store)
    ensures ret.references == 1
  {
    ret.Init();
    assert fresh(ret.cert_store);
    assert ret.references == 1;

    ret.meth := meth;
  }

  method SSL_CTX_use_certificate_chain_file() 
  {

  }
}