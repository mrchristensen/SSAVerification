include "Structs.dfy"
include "Constants.dfy"

module OpenSSLHelpers {
  import opened Structs
  import opened Constants

  // return X509 object that corresponds to the ssl_ctx obj given
  method SSL_CTX_get0_certificate(ctx : SSL_CTX?) returns (X509_ret : X509?)
    requires ctx != null
    ensures X509_ret == ctx.X509_cert
    ensures X509_ret != null // if SSL_CTX_use_certificate was not used
  {
    // if (ctx->cert != NULL)
    //     return ctx->cert->key->x509;
    // else
    //     return NULL;
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
  // loads a certificate chain from B<file> into B<ctx>.
  // The certificates must be in PEM format and must
  // be sorted starting with the subject's certificate
  // (actual client or server certificate), followed by
  // intermediate CA certificates if applicable, and
  // ending at the highest level (root) CA.
  method SSL_CTX_use_certificate_chain_file(file : string, ctx : SSL_CTX?)
  {
    // OpenSSL Code:
    // while ((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
    //                                 passwd_callback_userdata))
    //         != NULL) {
    //     if (ctx)
    //         r = SSL_CTX_add0_chain_cert(ctx, ca);
    //     else
    //         r = SSL_add0_chain_cert(ssl, ca);
    //     /*
    //       * Note that we must not free ca if it was successfully added to
    //       * the chain (while we must free the main certificate, since its
    //       * reference count is increased by SSL_CTX_use_certificate).
    //       */
    //     if (!r) {
    //         X509_free(ca);
    //         ret = 0;
    //         goto end;
    //     }
    // }

  }

  // just verify that this has been called
  method X509_verify_cert() returns (y : bool)
    ensures y == true
  {
    return true;
  }
}