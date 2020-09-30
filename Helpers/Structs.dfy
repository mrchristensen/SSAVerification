include "Constants.dfy"

module Structs
{
  import opened Constants

  class Socket
  {
    var keySize : int;
    var privateKey : string;
    var remHostname : string;
    var alpnProtos : array<string>;
    var cipherSuites : array<SSL_CIPHER?>;

    method Init(kSize : int, pKey : string, rHostname : string)
      modifies this
      ensures fresh(alpnProtos)
      ensures fresh(cipherSuites)
      ensures keySize == kSize
      ensures privateKey == pKey
      ensures remHostname == rHostname
    {
      keySize := kSize;
      privateKey := pKey;
      remHostname := rHostname;
      alpnProtos := new string[maxSize];
      cipherSuites := new SSL_CIPHER?[maxSize];
    }


    predicate Secure()
      reads this
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

    method Init()
      modifies this
      ensures fresh(cert_store)
      ensures references == 1
      ensures cipher_list_set == false
      ensures cert_store.Length == maxSize
    {
      cert_store := new X509?[maxSize];
      num_certs := 0;

      //resources are freed when this is 0
      references := 1;
      cipher_list_set := false;
    }

    method addX509(cert : X509?)
      modifies this
      requires cert != null
      requires cert_store.Length >= maxSize
      requires num_certs < maxSize
      ensures forall i | 0 <= i < cert_store.Length :: !(0 <= num_certs < maxSize) ==> cert_store[i] == old(cert_store[num_certs]) //TODO: https://stackoverflow.com/questions/49589887/specifying-modification-of-part-of-an-array-in-dafny
      ensures cert_store[old(num_certs)] == cert
      // ensures cert_store contains cert
    {
      cert_store[num_certs] := cert;
      num_certs := num_certs + 1;
    }

    predicate Valid()
        reads this
    {
      references != 0
      // FIXME - this predicate is unfinished
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
  }

  class tls_conn_ctx
  {
    var tls : string; // filepath to cert chain file
  }

  class SSL_CIPHER
  {
  }

  class ssa_config_t
  {
    var trust_store : string;
  }
}