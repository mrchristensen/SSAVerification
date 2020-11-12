include "Helpers/Structs.dfy"
include "Helpers/Config.dfy"
include "Helpers/Constants.dfy"
include "Helpers/OpenSSLHelpers.dfy"

module tls_wrapper {
    import opened Structs
    import opened Config
    import opened Constants
    import opened OpenSSLHelpers

    method tls_opts_create(path : string) returns (opts : tls_opts?)
      requires path != ""
      //modifies this; //'this' is not allowed in a 'static' context
      ensures opts != null
      ensures opts.tls_ctx != null
      ensures opts.tls_ctx.meth == "SSLv23_method"
      ensures opts.tls_ctx.references == 1
      ensures fresh(opts.tls_ctx.cert_store)
      ensures opts.tls_ctx.sid_ctx_length == 1
      ensures opts.tls_ctx.cipher_list_set == true
      ensures opts.tls_ctx.app_path == path
      ensures opts.tls_ctx.CA_locations_set == true
    {
      var ssa_config : ssa_config_t;
      var tls_ctx : SSL_CTX;
      var store_file : string; // trust store

      opts := new tls_opts;

      // initialized with SSL_CTX_new
      tls_ctx.Init();
      tls_ctx.meth := "SSLv23_method";
      assert fresh(tls_ctx.cert_store);
      assert tls_ctx.references == 1;
      assert tls_ctx.num_certs == 0;
      assert tls_ctx.meth == "";
      assert tls_ctx.cipher_list_set == false;

      // state changes from SSL_CTX_set_session_id_context
      tls_ctx.sid_ctx_length := 1;
      tls_ctx.sid_ctx := "1"; //This is a string, not an int

      ssa_config := get_app_config(path); // must set trust_store or error
      assert ssa_config != null;
      assert ssa_config.trust_store != "";

      // set min/max proto versions
      tls_ctx.min_proto_set := true;
      tls_ctx.max_proto_set := true;

      // sets things on tls_ctx
      tls_ctx.cipher_list_set := true; // ensure SSL_CTX_set_cipher_list is called
      store_file := ssa_config.trust_store;

      // SSL_CTX_load_verify_locations - set default locations for trusted CA certificates
      tls_ctx.CA_locations_set := true;

      // to do later - ensure that ssa_config.randseed_path is set

      opts.tls_ctx := tls_ctx;
      opts.app_path := path;
      return opts;
    }

    method set_certificate_chain(tls_opts_seq : tls_opts_seq, conn_ctx : tls_conn_ctx, filepath : string) returns (y : int)
        requires tls_opts_seq != null
        requires filepath != ""
        requires |tls_opts_seq.opts_list| != 0
        modifies conn_ctx;
        ensures conn_ctx.tls == ""
        ensures y != 0
        ensures |tls_opts_seq.opts_list| != 0
        ensures tls_opts_seq != null
        ensures |tls_opts_seq.opts_list| >= old(|tls_opts_seq.opts_list|)
      {
        var cur_opts := new tls_opts;
        var new_opts := new tls_opts;

        // if a connection already exists, set the certs on the existing connection
        if conn_ctx != null {
          // SSL_use_certificate_chain_file here loads
          // contents of filepath into conn_ctx.tls
          conn_ctx.setTLS(filepath);
          assert conn_ctx.tls != "";
          return 1;
        }

        // if no connection exists, set the certs on the options
        if tls_opts_seq == null {
          return 0;
        }

        cur_opts := tls_opts_seq.opts_list[0];
        // There is no cert set yet on the first SSL_CTX so we'll use that
        var get_cert:X509?;
        get_cert := SSL_CTX_get0_certificate(cur_opts.tls_ctx);

        if (get_cert == null) { // called from OpenSSLHelpers
          var use_chain_file:int;
          use_chain_file := SSL_CTX_use_certificate_chain_file(filepath, cur_opts.tls_ctx);
        	if (use_chain_file != 1) {
        		return 0; //Error: Unable to assign certificate chain
        	}
        	return 1; //Log: Using cert located at "filepath"
        }

        cur_opts := tls_opts_seq.opts_list[|tls_opts_seq.opts_list| - 1];

        new_opts := tls_opts_create("");
        assert new_opts != null;
        assert new_opts.tls_ctx != null;

        var use_chain_file:int;
        use_chain_file := SSL_CTX_use_certificate_chain_file(filepath, new_opts.tls_ctx);
        if (use_chain_file != 1) {
        	return 0; //Error: Unable to assign certificate chain
        }
        // Add new opts to option list
        tls_opts_seq.opts_list := tls_opts_seq.opts_list + [new_opts];
        return 1; //Log: Using cert located at "filepath"
      }

    // this is called in SSA in every TLS handshake and this callback
    // should be set in the accept() entry point
    method client_verify(store : X509_STORE_CTX?) returns (y : int)
      requires store != null
      ensures y == 1
    {
      // just verify that this function is called, might come back
      // and further model this
      var verified:bool;
      verified := X509_verify_cert();
      if(verified) {
        return 1;
      }
      return 0;
    }
}