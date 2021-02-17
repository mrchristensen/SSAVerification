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

    constructor Init(kSize : int, pKey : string, rHostname : string)
      ensures fresh(alpnProtos)
      ensures fresh(cipherSuites)
      ensures privateKey == pKey
      ensures remHostname == rHostname
    {
      privateKey := pKey;
      remHostname := rHostname;
      alpnProtos := new string[maxSize];
      cipherSuites := new SSL_CIPHER?[maxSize];
    }

    predicate Secure()
      reads this
      reads cipherSuites
      reads alpnProtos
      requires forall k :: 0 <= k < cipherSuites.Length
        ==> cipherSuites[k] != null && cipherSuites[k].secure()
      requires remHostname != ""
      requires forall k :: 0 <= k < alpnProtos.Length ==> alpnProtos[k] != ""
    {
      1 == 1
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

    constructor Init()
      // modifies cert_store
      ensures fresh(cert_store)
      ensures references == 1
      ensures cipher_list_set == false
      ensures cert_store.Length == maxSize
      ensures num_certs == 0
      ensures meth == ""
    {
      cert_store := new X509?[maxSize];
      num_certs := 0;
      meth := "";

      //resources are freed when this is 0
      references := 1;
      cipher_list_set := false;
    }

    method addX509(cert : X509?)
    //Todo Look into modifies a`[j] (pg 37)
      modifies `num_certs //Back tick for primatives - FrameFields
      modifies cert_store
      requires cert != null
      requires 0 <= num_certs < cert_store.Length - 1
      ensures num_certs == old(num_certs) + 1
      ensures num_certs < cert_store.Length
      ensures forall i : int :: 0 <= i < old(num_certs) ==> cert_store[i] == old(cert_store[i]) //Todo look into triggers
      ensures cert_store[old(num_certs)] == cert
    {
      cert_store[num_certs] := cert;
      num_certs := num_certs + 1;
    }

    predicate Valid()
        reads this
        requires references != 0
        requires cert_store.Length > 0
        requires CA_locations_set == true
        requires min_proto_set == true
        requires max_proto_set == true
    {
      1 == 1
    }
  }

  class X509
  {
    var cert : string;

    constructor Init()
      ensures cert == "" //Todo make this meaningful
    {
      cert := "";
    }
  }

  class X509_STORE_CTX
  {

  }

  class tls_opts {
    var tls_ctx : SSL_CTX?;
    var app_path : string;
    // int custom_validation
    // int is_server
    // char alpn_string[ALPN_STRING_MAXLEN]

    constructor Init()
      ensures tls_ctx != null
      // ensures app_path != ""
    {
      tls_ctx := new SSL_CTX.Init();
      app_path := ""; // todo does this need to be meaningful?
    }
  }

  class tls_opts_seq
  {
    var opts_list : seq<tls_opts?>;

    constructor Init()
      // modifies opts_list
      ensures fresh(opts_list)
    {
      opts_list := [];
    }
  }

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

    predicate secure()
    {
      1 == 1 // TODO - look into how to verify security of SSL_CIPHER
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