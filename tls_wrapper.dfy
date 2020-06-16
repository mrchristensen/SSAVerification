include "Helpers/Structs.dfy"
include "config.dfy"


module tls_wrapper {
    import opened Structs
    // import opened config

    method tls_opts_create(path : string)
    {
        var ssa_config : ssa_config_t;
        var opts;

        ssa_config := get_app_config(path);

        if(ssa_config){
            //if statements with SSL_CTX_set_min_proto_version(tls_ctx, ssa_config->min_version)
        }
    }
}