include "Structs.dfy"
include "Constants.dfy"

module OpenSSLHelpers {
  import opened Structs
  import opened Constants

  // return X509 object that corresponds to the ssl_ctx obj given
  method SSL_CTX_get0_certificate(ctx : SSL_CTX?)
    returns (X509_ret : X509?)
    requires ctx != null
    requires ctx.X509_cert != null
    ensures X509_ret == ctx.X509_cert
    ensures X509_ret != null // if SSL_CTX_use_certificate was not used - not secure
  {
    if ctx.X509_cert != null {
      return ctx.X509_cert;
    }
  }

  // There is more state change to this function, but for
  // now, this is all we'll include to verify cert chain
  // property
  method SSL_CTX_new(meth : string)
    returns (ret : SSL_CTX?)
    requires meth != ""
    ensures ret != null
    ensures ret.references == 1
    ensures ret.X509_cert != null
    ensures ret.num_certs == 0
    ensures fresh(ret.cert_store)
  {
    ret := new SSL_CTX.Init();
    assert fresh(ret.cert_store);
    assert ret.references == 1;

    ret.called_new_ctx := true;
    ret.meth := meth;
  }

  // loads a certificate chain from B<file> into B<ctx>.
  method SSL_CTX_use_certificate_chain_file(file : string, ctx : SSL_CTX?)
    returns (ret : int)

    modifies ctx.cert_store
    modifies ctx`num_certs

    ensures if old(ctx.num_certs) >= ctx.cert_store.Length - 1 then
        true
      else
        fresh(ctx.cert_store[old(ctx.num_certs)])
  {
    // in C code, it parses object from file but we'll just make an empty one for now
    var x509 := new X509.Init(file);
    // assert(ctx.num_certs < ctx.cert_store.Length);
    ctx.addX509(x509);
    ret := 1;
  }

  // just verify that this has been called
  method X509_verify_cert()
    returns (ret : bool)
  {
    ret := true;
    return ret;
  }

  // the OpenSSL function that sets verification information
  // made the assumption to remove the callback fucntion
  method SSL_CTX_set_verify(ctx : SSL_CTX?, mode : int)
    returns (ret : int)

    modifies ctx
    modifies ctx`verify_mode

  {
    ctx.verify_mode := mode;
    ctx.set_verify := true;
    ret := 1;
  }
}