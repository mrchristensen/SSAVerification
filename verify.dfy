include "Helpers/Constants.dfy"
include "Helpers/Structs.dfy"
include "tls_wrapper.dfy"

module verify {
  import opened Constants
  import opened Structs
  import opened tls_wrapper

  method main() {
    var sock := new Socket;
    var privateKey := "privateKey";
    var hostname := "hostname";

    sock.Init(256, privateKey, hostname);
    // assert all properties
    assert sock.privateKey == "privateKey";
    assert sock.remHostname == hostname;
    assert fresh(sock.alpnProtos);
    assert fresh(sock.cipherSuites);

    //call set_cert_chain
    var conn_ctx := new tls_conn_ctx;
    conn_ctx.Init();
    var tls_seq := new tls_opts_seq;
    tls_seq.Init();
    // add tls_opts_client_setup - in connect cb
    // connect_cb()
    var y := set_certificate_chain(tls_seq, conn_ctx, "filepath");
    //assert the crap out of it
    assert(y == 1);
    assert(conn_ctx.tls == "");
    assert(|tls_opts_seq.opts_list| != 0);
    assert(tls_opts_seq != null)
    // assert(|tls_opts_seq.opts_list| >= old(|tls_opts_seq.opts_list|))

    assert sock.Secure();
  }

}