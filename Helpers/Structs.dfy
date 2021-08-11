include "Constants.dfy"

module Structs
{
  import opened Constants

  class Socket
  {
    var privateKey : string;
    var publicKey : string;
    var remHostname : string;
    var alpnProtos : array<string>;
    var cipherSuites : array<SSL_CIPHER?>;
    var tls_opts : tls_opts?;
    var app_path : string; // FIXME - app path should be in tls_opts struct

    constructor Init(kSize : int, pKey : string, rHostname : string)
      ensures fresh(alpnProtos)
      ensures fresh(cipherSuites)
      ensures fresh(tls_opts)
      ensures privateKey == pKey
      ensures remHostname == rHostname
      ensures app_path == "path"
      ensures tls_opts != null
      ensures tls_opts.tls_ctx != null
    {
      privateKey := pKey;
      remHostname := rHostname;
      alpnProtos := new string[MAX_SIZE];
      cipherSuites := new SSL_CIPHER?[MAX_SIZE];
      tls_opts := new tls_opts.Init();
      app_path := "path";
    }

    predicate Secure()
      reads this
      reads this.cipherSuites
      reads this.alpnProtos
      reads this.tls_opts
      reads this.tls_opts.tls_ctx
      requires tls_opts != null
      // reads optsSeq.opts_list
      reads set m | 0 <= m < cipherSuites.Length :: cipherSuites[m]
      // reads set l | 0 <= l < |optsSeq.opts_list| :: (optsSeq.opts_list[l])
      // reads set n | 0 <= n < |optsSeq.opts_list| :: (optsSeq.opts_list[n]).tls_ctx
    {
      remHostname != ""
      && tls_opts != null
      && tls_opts.Secure()
      && cipherSuites.Length != 0
      && (forall k :: 0 <= k < cipherSuites.Length
        ==> cipherSuites[k] != null && cipherSuites[k].Secure())
      && (forall j :: 0 <= j < alpnProtos.Length ==> alpnProtos[j] != "")
    }
  }

  class SSL_CTX
  {
    var cert_store : array<X509?>; // FIXME - might be better to make this seq
    var num_certs : int;
    var references : int;
    var meth : string; // method
    var X509_cert : X509?;
    var sid_ctx_length : int;
    var sid_ctx : string; // session id ctx - ensure sessions are only resused in correct context
    var cipher_list_set : bool;
    var app_path : string;
    var CA_locations_set : bool;
    var min_proto_set : bool;
    var max_proto_set : bool;
    var called_new_ctx : bool;
    var verify_mode : int; // FIXME - ctx is valid if this is set to either SSL_VERIFY_NONE or SSL_VERIFY_PEER
    var set_verify : bool;

    constructor Init()
      // modifies cert_store
      ensures fresh(cert_store)
      ensures fresh(X509_cert)
      ensures references == 1
      ensures cipher_list_set == false
      ensures cert_store.Length == MAX_SIZE
      ensures num_certs == 0
      ensures meth == ""
    {
      cert_store := new X509?[MAX_SIZE];
      num_certs := 0;
      meth := "";

      //resources are freed when this is 0
      references := 1;
      cipher_list_set := false;
      X509_cert := new X509.Init("cert");
    }

    method addX509(cert : X509)
    //Todo Look into modifies a`[j] (pg 37)
      modifies `num_certs //Back tick for primatives - FrameFields
      modifies cert_store
      requires 0 <= num_certs < cert_store.Length
      ensures num_certs == old(num_certs) + 1
      // ensures num_certs < cert_store.Length
      ensures forall i : int :: 0 <= i < old(num_certs) ==> cert_store[i] == old(cert_store[i]) //Todo look into triggers
      ensures if num_certs < cert_store.Length then cert_store[old(num_certs)] == cert else cert_store == old(cert_store)
    {
      if(num_certs >= cert_store.Length) {
        return;
      }
      cert_store[num_certs] := cert;
      num_certs := num_certs + 1;
    }

    predicate Secure()
        reads this
    {
      references != 0
      && cert_store.Length > 0
      && CA_locations_set == true
      && min_proto_set == true
      && max_proto_set == true
      && called_new_ctx == true
      && set_verify == true
    }
  }

  class X509
  {
    var cert : string;

    constructor Init(file : string)
      requires file != ""
      ensures cert == file //Todo make this meaningful
      ensures cert != ""
    {
      cert := file;
    }
  }

  class tls_opts {
    var tls_ctx : SSL_CTX?;
    var app_path : string;
    var is_server : int;
    // int custom_validation
    // char alpn_string[ALPN_STRING_MAXLEN]

    constructor Init()
      ensures tls_ctx != null
      ensures fresh(tls_ctx)
    {
      tls_ctx := new SSL_CTX.Init();
      app_path := ""; // todo does this need to be meaningful?
      is_server := -1;
    }

    predicate Secure()
      reads this
      reads this.tls_ctx
    {
      is_server == 0
      && tls_ctx != null
      && tls_ctx.Secure()
    }
  }

  // class tls_opts_seq
  // {
  //   var opts_list : seq<tls_opts>;

  //   constructor Init()
  //     ensures fresh(opts_list)
  //     // ensures opts_list != null
  //   {
  //     opts_list := [];
  //   }

  //   predicate Secure()
  //     reads this
  //     reads this.opts_list
  //     reads set m | 0 <= m < |this.opts_list| :: (this.opts_list[m])
  //     reads set n | 0 <= n < |this.opts_list| :: (this.opts_list[n]).tls_ctx
  //   {
  //     |opts_list| == 0 || forall i : int :: 0 <= i < |opts_list| ==> opts_list[i].Secure()
  //   }
  // }

  class tls_conn_ctx
  {
    var tls : string; // filepath to cert chain file

    constructor Init()
      ensures tls == ""
    {
      tls := "";
    }

    method setTLS(tls : string)
      modifies this
      ensures this.tls == tls;
    {
      this.tls := tls;
    }
  }

  class SSL_CIPHER
  {
    var valid : int;
    var name : string;
    // uint32_t algorithm_mkey;    /* key exchange algorithm */
    // uint32_t algorithm_auth;    /* server authentication */
    // uint32_t algorithm_enc;     /* symmetric encryption */
    // uint32_t algorithm_mac;     /* symmetric authentication */
    // int min_tls;                /* minimum SSL/TLS protocol version */
    // int max_tls;                /* maximum SSL/TLS protocol version */
    // int min_dtls;               /* minimum DTLS protocol version */
    // int max_dtls;               /* maximum DTLS protocol version */
    // uint32_t algo_strength;     /* strength and export flags */
    // uint32_t algorithm2;        /* Extra flags */
    // int32_t strength_bits;      /* Number of bits really used */
    // uint32_t alg_bits;          /* Number of bits for algorithm */

    predicate Secure()
      reads `valid  // FIXME - what is valid? what does it mean?
      reads `name
    {
      valid == 1 && name != ""
    }
  }

  class ssa_config_t
  {
    var trust_store : string;

    constructor Init()
    {

    }
  }
}