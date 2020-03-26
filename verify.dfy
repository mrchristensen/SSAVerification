var maxSize := 20;

class Socket
{
  var keySize : int;
  var privateKey : string;
  var remHostname : string;
  var alpnProtos : array<string>;
  var cipherSuites : array<SSL_CIPHER>; //fix this

  method Init(kSize : int, pKey : string, rHostname : string)
  modifies this;
  {
    keySize := kSize;
    privateKay := pKey;
    remHostname := rHostname;
    alpnProtos := new string[maxSize];
    cipherSuites := new string[maxSize];
  }

  method isSecure()
  {
  }
}

method main()
{
  var sock := new Socket;
  //initialize socket
  assert sock.isSecure();
}


