module Structs {
    class SSL_CTX {
        // cert chain
        // x509

        method Init() {

        }
    }

    class tls_opts {
        var tls_ctx : SSL_CTX; // come back - not sure how to fix this
        // char *app_path
        // int custom_validation
        // int is_server
        // char alpn_string[ALPN_STRING_MAXLEN]
        // struct tls_opts* next
    }

    class tls_conn_ctx {

    }
}