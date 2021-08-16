include "Helpers/Constants.dfy"
include "Helpers/Structs.dfy"
include "tls_wrapper.dfy"

module verify {
  import opened Constants
  import opened Structs
  import opened tls_wrapper

  method main() {
    var privateKey := "privateKey";
    var hostname := "hostname";
    var sock := new Socket.Init(256, privateKey, hostname);
    // assert fresh(sock)
    assert sock.tls_opts != null;
    assert sock.tls_opts.tls_ctx != null;

    // assert all properties
    assert sock.privateKey == "privateKey";
    assert sock.remHostname == hostname;
    assert fresh(sock.alpnProtos);
    assert fresh(sock.cipherSuites);

    var conn_ctx := new tls_conn_ctx.Init();
    sock.app_path := "path";

    var x := socket_cb(sock);
    assert(x == 1);

    assert sock.tls_opts != null;
    assert sock.tls_opts.tls_ctx != null;

    var z := connect_cb(sock);
    // assert(z == 1);

    // assert sock.tls_opts != null;
    // assert sock.tls_opts.tls_ctx != null;
    // assert 0 <= sock.tls_opts.tls_ctx.num_certs < sock.tls_opts.tls_ctx.cert_store.Length;
    // var y := set_certificate_chain(sock.tls_opts, conn_ctx, sock.app_path);

    //assert the crap out of it
    // assert(y == 1);
    // assert(conn_ctx.tls == "");
    // assert(tls_opts != null);
    // sock.tls := tls_seq;

    // assert sock.Secure();
  }

}