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

    method Init(kSize : int, pKey : string, rHostname : string)
      modifies this
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

    method Init()
      modifies this
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
      modifies this
      modifies cert_store
      requires cert != null
      requires cert_store.Length >= maxSize
      requires num_certs < maxSize
      // ensures forall i | 0 <= i < cert_store.Length :: !(0 <= num_certs < maxSize) ==> cert_store[i] == old(cert_store[num_certs]) //TODO: https://stackoverflow.com/questions/49589887/specifying-modification-of-part-of-an-array-in-dafny
      // ensures cert_store[old(num_certs)] == cert
      // ensures cert_store contains cert
    {
      // cert_store[num_certs] := cert;
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

    method Init()
      modifies this
      // ensures cert == ""
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

    method Init()
      modifies this
      ensures tls_ctx != null
      // ensures app_path != ""
    {
      tls_ctx := new SSL_CTX;
      tls_ctx.Init();
      app_path := "";
    }
  }

  class tls_opts_seq
  {
    var opts_list : seq<tls_opts?>;

    method Init()
      modifies this
      modifies opts_list
      ensures fresh(opts_list)
    {
      opts_list := [];
    }
  }

  class tls_conn_ctx
  {
    var tls : string; // filepath to cert chain file

    method Init()
      modifies this
      ensures tls == ""
    {
      tls := "";
    }

    method setTLS(tls : string)
      modifies this
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
  }
}