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
    ret := new SSL_CTX;
    ret.Init();
    assert fresh(ret.cert_store);
    assert ret.references == 1;

    ret.meth := meth;
  }

  // loads a certificate chain from B<file> into B<ctx>.
  method SSL_CTX_use_certificate_chain_file(file : string, ctx : SSL_CTX?) //TODO: this need to return an int
    requires file != ""
    requires ctx != null
    // ensures ctx.num_certs != old(ctx.num_certs)
  {
    // file_arr := ArrayFromSeq(file);
    // TODO - parse file so that each set of lines
    // starting with "-----BEGIN CERTIFICATE-----"
    // and ending with "-----END CERTIFICATE-----"
    // is loaded into an X509 object and added
    // to ctx.cert_store using ctx.addX509(cert : X509?)
  }

  // just verify that this has been called
  method X509_verify_cert() returns (y : bool)
    ensures y == true
  {
    return true;
  }
}