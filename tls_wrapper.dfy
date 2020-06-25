include "Helpers/Structs.dfy"
include "Helpers/config.dfy"


module tls_wrapper {
    import opened Structs
    import opened config

    method tls_opts_create(path : string)
    {
        var ssa_config : ssa_config_t;
        var opts;

        ssa_config := get_app_config(path);

        if(ssa_config != null) {
            //if statements with SSL_CTX_set_min_proto_version(tls_ctx, ssa_config->min_version)
        }
    }

    method set_certificate_chain(tls_opts : tls_opts, conn_ctx : tls_conn_ctx, filepath : string) returns (y : int)
        requires tls_opts != null
        // requires filepath != null
        // ensures that there is a valid cetificate chain set afterward
        ensures y != 0
      {
        var cur_opts := new tls_opts;
        var new_opts := new tls_opts;

        //If a connection already exists, set the certs on the existing connection
        if conn_ctx != null {
          if(OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_NUMBER_0x10100000L){
            if(SSL_use_certificate_chain_file(conn_ctx.tls, filepath) != 1) {
              return 0; //Get ready for renegotiation
            }
          }
          else {
            if(compat_SSL_use_certificate_chain_file(conn_ctx.tls, filepath) != 1) {
              return 0;
            }
          }

          return 1;
        }

        //If no connection exists, set the certs on the options
        if tls_opts == null {
          return 0;
        }

        cur_opts := tls_opts;
        // There is no cert set yet on the first SSL_CTX so we'll use that
        if (SSL_CTX_get0_certificate(cur_opts.tls_ctx) == NULL) {
        	if (SSL_CTX_use_certificate_chain_file(cur_opts.tls_ctx, filepath) != 1) {
        		return 0; //Error: Unable to assign certificate chain
        	}
        	return 1; //Log: Using cert located at "filepath"
        }

        // Otherwise create a new options struct and use that
        while (cur_opts.next != NULL) {
        	cur_opts := cur_opts.next;
        }

        new_opts := tls_opts_create(NULL);
        if (new_opts == NULL) {
        	return 0;
        }

        if (SSL_CTX_use_certificate_chain_file(new_opts.tls_ctx, filepath) != 1) {
        	return 0; //Error: Unable to assign certificate chain
        }
        // Add new opts to option list
        cur_opts.next := new_opts;
        return 1; //Log: Using cert located at "filepath"
      }

}