include "Constants.dfy"

module Structs {
    import opened Constants

    class SSL_CTX {
        // cert chain
        // x509
        var cert_chain : array<string>;
        var x509 : string;

        method Init()
            modifies this
            // ensure that all fields have been set
        {
            // FIXME - change this later
            x509 := "";
            cert_chain := new string[maxSize];
        }
    }

    class tls_opts {
        var tls_ctx : SSL_CTX?;
        var next : tls_opts?;
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

    }

    class SSL_CIPHER {

    }
}