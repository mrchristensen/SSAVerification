include "Structs.dfy"
include "Constants.dfy"

module OpenSSLHelpers {
  import opened Structs
  import opened Constants

  // return X509 object that corresponds to the ssl_ctx obj given
  method SSL_CTX_get0_certificate(ctx : SSL_CTX?) returns (X509_ret : X509?)
    requires ctx != null
    ensures X509_ret == ctx.X509_cert
  {
    return ctx.X509_cert;
  }

  // There is more state change to this function, but for
  // now, this is all we'll include to verify cert chain
  // property
  method SSL_CTX_new(meth : string) returns (ret : SSL_CTX?)
    requires meth != ""
    ensures ret != null
    ensures fresh(ret.cert_store)
    ensures ret.references == 1
  {
    ret := new SSL_CTX;
    ret.Init();
    assert fresh(ret.cert_store);
    assert ret.references == 1;

    ret.meth := meth;
  }

  // TODO - WRITE THIS
  method SSL_CTX_use_certificate_chain_file() 
  {

  }
}