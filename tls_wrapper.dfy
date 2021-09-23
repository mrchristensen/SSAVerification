include "Helpers/Structs.dfy"
include "Helpers/Config.dfy"
include "Helpers/Constants.dfy"
include "Helpers/OpenSSLHelpers.dfy"

module tls_wrapper {
    import opened Structs
    import opened Config
    import opened Constants
    import opened OpenSSLHelpers

    method tls_opts_client_setup(tls_opts : tls_opts?)
      returns (ret : int)

      requires tls_opts != null
      requires tls_opts.tls_ctx != null

      modifies tls_opts
      // modifies tls_opts`is_server
      modifies tls_opts.tls_ctx

      ensures ret == 1
      ensures tls_opts.tls_ctx != null
    {
      // tls_opts.is_server := 0;

      // Temporarily disable validation
      ret := SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_NONE);
      // ret := 1;
    }

    method tls_opts_create(path : string)
      returns (opts : tls_opts)
      requires path != ""
      //modifies this; //'this' is not allowed in a 'static' context
      // ensures opts != null
      ensures opts.tls_ctx != null
      ensures opts.tls_ctx.meth == "SSLv23_method"
      ensures opts.tls_ctx.references == 1
      ensures opts.tls_ctx.sid_ctx_length == 1
      ensures opts.tls_ctx.cipher_list_set == true
      ensures opts.tls_ctx.app_path == path
      ensures opts.tls_ctx.CA_locations_set == true
      ensures opts.tls_ctx.X509_cert != null
      ensures 0 <= opts.tls_ctx.num_certs < opts.tls_ctx.cert_store.Length - 1
      ensures opts.tls_ctx.num_certs == 0; //todo: also add top cap (and less than len of cert list?)

      // ensures opts.tls_ctx == 0;
      ensures fresh(opts)
      ensures fresh(opts.tls_ctx)
      ensures fresh(opts.tls_ctx.cert_store)
      // ensures fresh(tls_ctx)
    {
      var ssa_config : ssa_config_t;
      var tls_ctx : SSL_CTX;
      var store_file : string; // trust store

      opts := new tls_opts.Init();
      assert fresh(opts);

      tls_ctx := new SSL_CTX.Init();
      assert fresh(tls_ctx);

      // initialized with SSL_CTX_new
      tls_ctx.meth := "SSLv23_method";
      assert fresh(tls_ctx.cert_store);
      assert tls_ctx.references == 1;
      assert tls_ctx.num_certs == 0;
      assert tls_ctx.meth == "SSLv23_method";
      assert tls_ctx.cipher_list_set == false;

      // state changes from SSL_CTX_set_session_id_context
      tls_ctx.sid_ctx_length := 1;
      tls_ctx.sid_ctx := "1"; //This is a string, not an int

      ssa_config := get_app_config(path); // must set trust_store or error
      // assert ssa_config != null; //Not necessary on an object type that can't be null
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
      opts.tls_ctx.app_path := path;
      return opts;
    }

    method set_certificate_chain(tls_opts : tls_opts?, conn_ctx : tls_conn_ctx?, filepath : string)
        returns (ret : int)
        requires tls_opts != null
        requires filepath != ""
        requires tls_opts.tls_ctx != null
        requires tls_opts.tls_ctx.X509_cert != null
        requires 0 <= tls_opts.tls_ctx.num_certs < tls_opts.tls_ctx.cert_store.Length
        modifies conn_ctx
        modifies tls_opts
        modifies tls_opts.tls_ctx
        // modifies tls_opts.tls_ctx`num_certs
        modifies tls_opts.tls_ctx.cert_store
        ensures ret != 0
        ensures tls_opts != null
        //TODO: require/ensure that the SSL_CTX_get0_certificate don't move such that num_certs > cert_store.Length - 1
      {
        var cur_opts := new tls_opts.Init();
        var new_opts := new tls_opts.Init();
        assert fresh(cur_opts);
        assert fresh(new_opts);

        // if a connection already exists, set the certs on the existing connection
        if conn_ctx != null {
          var x := SSL_CTX_use_certificate_chain_file(filepath, tls_opts.tls_ctx);
          assert x == 1;
          // SSL_use_certificate_chain_file here loads
          // contents of filepath into conn_ctx.tls
          conn_ctx.setTLS(filepath);
          assert conn_ctx.tls != "";

          return 1;
        }

        // if no connection exists, set the certs on the options
        if tls_opts == null {
          return 0;
        }

        assert tls_opts != null;

        // cur_opts := tls_opts;

        // There is no cert set yet on the first SSL_CTX so we'll use that
        var get_cert : X509?;

        assert tls_opts.tls_ctx != null;
        assert tls_opts.tls_ctx.X509_cert != null;

        get_cert := SSL_CTX_get0_certificate(tls_opts.tls_ctx); //Matt todo

        if (get_cert == null) { // called from OpenSSLHelpers
          var use_chain_file:int;
          use_chain_file := SSL_CTX_use_certificate_chain_file(filepath, tls_opts.tls_ctx); //Matt todo
        	if (use_chain_file != 1) {
            return 0; //Error: Unable to assign certificate chain
        	}

        	return 1; //Log: Using cert located at "filepath"
        }

        new_opts := tls_opts_create(filepath);
        assert new_opts.tls_ctx != null;
        assert new_opts.tls_ctx.X509_cert != null;
        assert filepath != "";

        var use_chain_file := SSL_CTX_use_certificate_chain_file(filepath, new_opts.tls_ctx);

        if (use_chain_file != 1) {
        	ret := 0;
          return ret; //Error: Unable to assign certificate chain
        }

        // Add new opts to option list
        // tls_opts_seq.opts_list := tls_opts_seq.opts_list + [new_opts];

        // FIXME - what to do with new opts??

        return 1; //Log: Using cert located at "filepath"
      }

    // this is called in SSA in every TLS handshake and this callback
    // should be set in the accept() entry point
    method client_verify(ctx : SSL_CTX?) // changed from x509 store ctx to ssl ctx
      returns (ret : int)
      // requires ctx.cert_store != null - FIXME, this should be here
      ensures ret == 1
    {
      // just verify that this function is called, might come back
      // and further model this
      var verified:bool;
      verified := X509_verify_cert();
      if(verified) {
        ret := 1;
        return ret;
      }

      ret := 0;
      return ret;
    }

    method socket_cb(sock : Socket?)
      returns (ret : int)

      requires sock != null
      requires sock.app_path != ""
      requires sock.tls_opts != null
      requires sock.tls_opts.tls_ctx != null

      modifies sock

      ensures ret == 1
      ensures sock != null
      ensures sock.tls_opts != null
      ensures sock.tls_opts.tls_ctx != null
      ensures sock.tls_opts.tls_ctx.X509_cert != null
      ensures 0 <= sock.tls_opts.tls_ctx.num_certs < sock.tls_opts.tls_ctx.cert_store.Length

      ensures sock == old(sock)
      ensures fresh(sock.tls_opts)
      ensures fresh(sock.tls_opts.tls_ctx)
      ensures sock.app_path != ""
    {
      var opts := tls_opts_create(sock.app_path);
      assert opts.tls_ctx.X509_cert != null;

      assert(opts.tls_ctx != null);
      assert(opts.tls_ctx.num_certs == 0);

      sock.tls_opts := opts;

      // sock.tls_opts.is_server := 0;
      // sock.tls_opts.tls_ctx.verify_mode := SSL_VERIFY_NONE;
      // sock.tls_opts.tls_ctx.set_verify := true;

      // assert(sock.tls_opts.is_server == 0);
      // assert(sock.tls_opts.tls_ctx.verify_mode == SSL_VERIFY_NONE);
      // assert(sock.tls_opts.tls_ctx.set_verify == true);

      ret := 1;
    }

    method connect_cb(sock : Socket?)
      returns (ret : int)

      requires sock != null
      requires sock.tls_opts != null
      requires sock.tls_opts.tls_ctx != null
      requires sock.tls_opts.tls_ctx.X509_cert != null
      requires 0 <= sock.tls_opts.tls_ctx.num_certs < sock.tls_opts.tls_ctx.cert_store.Length

      // modifies sock
      // modifies sock.tls_opts
      // modifies sock.tls_opts.tls_ctx
      // modifies sock.tls_opts`is_server
      // modifies sock.cipherSuites
      // modifies sock.alpnProtos
      // modifies sock`privateKey
      // modifies sock`publicKey
      // modifies sock`remHostname
      // modifies sock.alpnProtos
      // modifies sock.cipherSuites
      // modifies sock.tls_opts
      // modifies sock`app_path

      // modifies sock.tls_opts.tls_ctx
      // modifies sock.tls_opts`app_path
      // modifies sock.tls_opts`is_server

      // modifies sock.tls_opts.tls_ctx.cert_store
      // modifies sock.tls_opts.tls_ctx`num_certs
      // modifies sock.tls_opts.tls_ctx`references
      // modifies sock.tls_opts.tls_ctx`meth

      // modifies sock.tls_opts.tls_ctx.X509_cert
      // // modifies sock.tls_opts.tls_ctx.X509_cert`cert

      // modifies sock.tls_opts.tls_ctx`sid_ctx_length
      // modifies sock.tls_opts.tls_ctx`sid_ctx
      // modifies sock.tls_opts.tls_ctx`cipher_list_set
      // modifies sock.tls_opts.tls_ctx`app_path
      // modifies sock.tls_opts.tls_ctx`CA_locations_set
      // modifies sock.tls_opts.tls_ctx`min_proto_set
      // modifies sock.tls_opts.tls_ctx`max_proto_set
      // modifies sock.tls_opts.tls_ctx`called_new_ctx
      // modifies sock.tls_opts.tls_ctx`verify_mode
      // modifies sock.tls_opts.tls_ctx`set_verify

      // modifies sock
      modifies sock.tls_opts
      modifies sock.tls_opts.tls_ctx

      // ensures sock.tls_opts != null
      // ensures sock.tls_opts.tls_ctx != null
      ensures ret == 1


      ensures sock.tls_opts == old(sock.tls_opts)
      ensures sock.tls_opts.tls_ctx == old(sock.tls_opts.tls_ctx)
      ensures sock.tls_opts.tls_ctx.X509_cert == old(sock.tls_opts.tls_ctx.X509_cert)
      ensures sock.tls_opts.tls_ctx.X509_cert != null
      ensures 0 <= sock.tls_opts.tls_ctx.num_certs < sock.tls_opts.tls_ctx.cert_store.Length
      // ensures fresh(sock)
      // ensures fresh(sock.tls_opts)
      // ensures fresh(sock.tls_opts.tls_ctx)
    {
      // ret := tls_opts_client_setup(sock.tls_opts);
      // call tls_client_wrapper_setup

      sock.tls_opts.is_server := 0;
      sock.tls_opts.tls_ctx.verify_mode := SSL_VERIFY_NONE;
      sock.tls_opts.tls_ctx.set_verify := true;

      assert(sock.tls_opts.is_server == 0);
      assert(sock.tls_opts.tls_ctx.verify_mode == SSL_VERIFY_NONE);
      assert(sock.tls_opts.tls_ctx.set_verify == true);

      ret := 1;
    }
}