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
        var cert_chain : array<string>;
        var X509 : string;
        var reference_count : int;
        var meth : string; // method
        var min_proto_version : int;
        var max_proto_version : int;
        var mode : int; //should be unsigned but idk if that matters
        var session_cache_mode : string;
        var session_cache_size : int;

        method Init()
            // modifies this
            // ensure that all fields have been set
        {
            // FIXME - change these later
            X509 := "";
            cert_chain := new string[maxSize];

            // this is what SSl_CTX_new sets when it is called, resources are freed when this is 0
            reference_count := 1;
        }

        predicate Valid()
            reads this
        {
            reference_count != 0
            // FIXME - this predicate is unfinished
        }
    }

    class tls_opts {
        var tls_ctx : SSL_CTX?;
        var next : tls_opts?;

        // FIXME - not sure if we need the following fields yet
        // char *app_path
        // int custom_validation
        // int is_server
        // char alpn_string[ALPN_STRING_MAXLEN]
        // struct tls_opts* next

        method Init()
            modifies this
            // ensure that all fields have been set
        {
            tls_ctx := new SSL_CTX;
            tls_ctx.Init();
        }
    }

    class tls_conn_ctx {
      var tls : string; // string holding the filepath to cert chain file
    }

    class SSL_CIPHER {

    }

    class ssa_config_t {
      
    }
}