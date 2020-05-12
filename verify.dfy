class Socket 
{
  var maxSize : int;

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
    maxSize := 20;

    keySize := kSize;
    privateKey := pKey;
    remHostname := rHostname;
    alpnProtos := new string[maxSize];
    cipherSuites := new string[maxSize];
  }
  
  predicate isSecure()
  {
    true
  }
}

method main()
{
  var sock := new Socket;
  //initialize socket
  assert sock.isSecure();
}


