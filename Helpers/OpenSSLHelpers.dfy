include "Structs.dfy"
include "Constants.dfy"
include "HelperFunctions.dfy"

module OpenSSLHelpers {
  import opened Structs
  import opened Constants
  import opened HelperFunctions

  // return X509 object that corresponds to the ssl_ctx obj given
  method SSL_CTX_get0_certificate(ctx : SSL_CTX?) returns (X509_ret : X509?)
    requires ctx != null
    requires ctx.X509_cert != null
    ensures X509_ret == ctx.X509_cert
    ensures X509_ret != null // if SSL_CTX_use_certificate was not used - not secure
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
    ret := new SSL_CTX.Init();
    assert fresh(ret.cert_store);
    assert ret.references == 1;

    ret.meth := meth;
  }

  // loads a certificate chain from B<file> into B<ctx>.
  method SSL_CTX_use_certificate_chain_file(file : string, ctx : SSL_CTX?) returns (ret : int)
    modifies ctx.cert_store
    modifies ctx`num_certs
    requires file != ""
    requires ctx != null
    ensures ctx.num_certs == old(ctx.num_certs) + 1
  {
    // in C code, it parses object from file but we'll just make an empty one for now
    var x509 := new X509.Init(file);
    ctx.addX509(x509);
    ret := 0;
  }

  // just verify that this has been called
  method X509_verify_cert() returns (y : bool)
    ensures y == true
  {
    return true;
  }
}