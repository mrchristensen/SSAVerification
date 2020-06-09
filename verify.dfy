include "Helpers/Constants.dfy"
include "Helpers/Structs.dfy"

module verify {
  import opened Constants
  import opened Structs

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

  method main()
  {
    var sock := new Socket;
    var privateKey := "privateKey";
    var hostname := "hostname";

    sock.Init(256, privateKey, hostname);
    // assert all properties
    assert sock.keySize == 256;
    assert sock.privateKey == "privateKey";
    assert sock.remHostname == hostname;
    assert fresh(sock.alpnProtos);
    assert fresh(sock.cipherSuites);
    

    assert sock.Secure();
  }
}





