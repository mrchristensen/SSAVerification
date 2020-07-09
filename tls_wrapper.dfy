include "Helpers/Structs.dfy"
include "Helpers/Config.dfy"
include "Helpers/Constants.dfy"
include "Helpers/openssl_compat.dfy"
include "Helpers/OpenSSLHelpers.dfy"

module tls_wrapper {
    import opened Structs
    import opened Config
    import opened Constants
    import opened openssl_compat
    import opened OpenSSLHelpers

    // TODO - FINISH THIS
    method tls_opts_create(path : string)
    {
      var ssa_config : ssa_config_t;
      var opts;
      var tls_ctx : SSL_CTX;

      ssa_config := get_app_config(path);

      if(ssa_config != null) {
        //if statements with SSL_CTX_set_min_proto_version(tls_ctx, ssa_config->min_version)
      }
    }

    method set_certificate_chain(tls_opts_seq : tls_opts_seq, conn_ctx : tls_conn_ctx, filepath : string) returns (y : int)
        requires tls_opts_seq != null
        requires filepath != null
        requires tls_opts_seq.opts_list != null
        ensures y != 0
        ensures tls_opts_seq.opts_list != null
        ensures tls_opts_seq != null
        ensures |tls_opts_seq.opts_list| >= old(|tls_opts_seq.opts_list|)
        // ensure the length of tls_opts_seq.opts_list either increases or stays the same
      {
        var cur_opts := new tls_opts_seq;
        var new_opts := new tls_opts;

        // if a connection already exists, set the certs on the existing connection
        if conn_ctx != null {
          // FIXME - for now, OPENSSL_VERSION_NUMBER == 0x10100000, 
          // but we need to test on other version numbers as well
          if(OPENSSL_VERSION_NUMBER >= 0x10100000) {
            // SSL_use_certificate_chain_file here loads 
            // contents of filepath into conn_ctx.tls
            conn_ctx.tls := filepath;
            assert conn_ctx.tls != null;
          }
          else {
            // compat_SSL_use_certificate_chain_file here 
            // calls this openssl_compat method
            if (use_certificate_chain_file(null, conn_ctx.tls, filepath) != 1) {
              y := 0;
              return;
            }
          }
          return 1;
        }

        // if no connection exists, set the certs on the options
        if tls_opts_seq == null {
          return 0;
        }

        cur_opts := tls_opts_seq.opts_list[0];
        // There is no cert set yet on the first SSL_CTX so we'll use that
        if (SSL_CTX_get0_certificate(cur_opts.tls_ctx) == "") { // called from OpenSSLHelpers
        	if (SSL_CTX_use_certificate_chain_file(cur_opts.tls_ctx, filepath) != 1) {
        		return 0; //Error: Unable to assign certificate chain
        	}
        	return 1; //Log: Using cert located at "filepath"
        }

        cur_opts := tls_opts_seq.opts_list[|tls_opts_seq.opts_list| - 1];

        new_opts := tls_opts_create(NULL);
        assert new_opts != null;
        assert new_opts.tls_ctx != null;

        if (SSL_CTX_use_certificate_chain_file(new_opts.tls_ctx, filepath) != 1) {
        	return 0; //Error: Unable to assign certificate chain
        }
        // Add new opts to option list
        tls_opts_seq.opts_list := tls_opts_seq.opts_list + [new_opts];
        return 1; //Log: Using cert located at "filepath"
      }

    // this is called in SSA in every TLS handshake and this callback
    // should be set in the accept() entry point
    method client_verify(store : X509_STORE_CTX, arg : array<string>) returns (y : int)
    {
      // TODO - create state diagram and model for this function from SSA
      // then implement it in predicate that determines the
      // security of the current SSL_CTX object
    }
}