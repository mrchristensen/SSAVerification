include "Constants.dfy"
class Socket
{
  var keySize : int;
  var privateKey : string;
  var remHostname : string;
  var alpnProtos : array<string>;
  var cipherSuites : array<string>; // FIXME - should be array of type SSL_CIPHER

  method Init(kSize : int, pKey : string, rHostname : string)
  modifies this;
  ensures fresh(alpnProtos);
  ensures fresh(cipherSuites);
  {
    

    keySize := kSize;
    privateKey := pKey;
    remHostname := rHostname;
    alpnProtos := new string[maxSize];
    cipherSuites := new string[maxSize];
  }


  predicate Secure()
  reads this;
  {
    1 == 1
  }
}

method main()
{
  var sock := new Socket;
  sock.Init(256, "privateKey", "hostname");
  //initialize socket
  assert sock.Secure();
}



