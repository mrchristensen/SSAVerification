include "Constants.dfy"

module Structs {
    import opened Constants

    class Socket
  {
    var keySize : int;
    var privateKey : string;
    var remHostname : string;
    var alpnProtos : array<string>;
    var cipherSuites : array<SSL_CIPHER?>;

    method Init(kSize : int, pKey : string, rHostname : string)
      modifies this
      ensures fresh(alpnProtos)
      ensures fresh(cipherSuites)
      ensures keySize == kSize
      ensures privateKey == pKey
      ensures remHostname == rHostname
    {
      keySize := kSize;
      privateKey := pKey;
      remHostname := rHostname;
      alpnProtos := new string[maxSize];
      cipherSuites := new SSL_CIPHER?[maxSize];
    }


    predicate Secure()
      reads this
    {
      1 == 1
    }
  }

    class SSL_CTX {
        //array of certificates in X509 form
        var cert_store : array<X509?>;
        var references : int;
        var meth : string; // method
        var X509_cert : X509?;

        // the session_id_context is used to ensure sessions are only reused in
        // the appropriate context
        var sid_ctx_length : int;
        var sid_ctx : string;

        method Init()
          modifies this
          // ensure that all fields have been set
          ensures fresh(cert_store)
          ensures references == 1
        {
          cert_store := new X509?[maxSize];

          //resources are freed when this is 0
          references := 1;
        }

        predicate Valid()
            reads this
        {
          references != 0
          // FIXME - this predicate is unfinished
        }
    }

    class X509 {

    }

    class X509_STORE_CTX {

    }

    class tls_opts {
        var tls_ctx : SSL_CTX?;
        // char *app_path
        // int custom_validation
        // int is_server
        // char alpn_string[ALPN_STRING_MAXLEN]

        method Init()
          modifies this
          // ensure that all fields have been set
        {
          tls_ctx := new SSL_CTX;
          tls_ctx.Init();
        }
    }

    class tls_opts_seq {
      var opts_list : seq<tls_opts?>;
    }

    class tls_conn_ctx {
      var tls : string; // string holding the filepath to cert chain file
    }

    class SSL_CIPHER {

    }

    class ssa_config_t {

    }
}