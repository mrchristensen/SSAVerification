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


      // FIXME - maybe move these assignments to the Init function
      ret.meth := meth;
      ret.min_proto_version := 0;
      ret.max_proto_version := 0;
      ret.mode := SSL_MODE_AUTO_RETRY;
      ret.session_cache_mode := 


    // OPENSSL code:
    // ret->mode = SSL_MODE_AUTO_RETRY;
    // ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
    // ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
    // /* We take the system default. */
    // ret->session_timeout = meth->get_timeout();
    // ret->references = 1;
    // ret->lock = CRYPTO_THREAD_lock_new();
    // if (ret->lock == NULL) {
    //     SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
    //     OPENSSL_free(ret);
    //     return NULL;
    // }
    // ret->max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
    // ret->verify_mode = SSL_VERIFY_NONE;
    // if ((ret->cert = ssl_cert_new()) == NULL)
    //     goto err;

    // ret->sessions = lh_SSL_SESSION_new(ssl_session_hash, ssl_session_cmp);
    // if (ret->sessions == NULL)
    //     goto err;
    // ret->cert_store = X509_STORE_new();
    // if (ret->cert_store == NULL)
    //     goto err;
    // GO BACK TO OPEN SSL CODE, theres more DX

  }
}