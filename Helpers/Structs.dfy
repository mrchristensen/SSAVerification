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
            // verify that all fields have been
        {
            // FIXME - change this later
            x509 := "";
            cert_chain := new string[maxSize];
        }
    }

    class tls_opts {
        var tls_ctx : int; // FIXME - change this later
        // var tls_ctx : SSL_CTX; // come back - not sure how to fix this
        // char *app_path
        // int custom_validation
        // int is_server
        // char alpn_string[ALPN_STRING_MAXLEN]
        // struct tls_opts* next
        var next : tls_opts;

        method Init() {
            // tls_ctx := new SSL_CTX;
            // tls_ctx.Init();
        }
    }

    class tls_conn_ctx {

    }
}