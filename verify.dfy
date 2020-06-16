include "Helpers/Constants.dfy"
include "Helpers/Structs.dfy"

module verify {
  import opened Constants
  import opened Structs

module main{
  import opened Structs
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
}