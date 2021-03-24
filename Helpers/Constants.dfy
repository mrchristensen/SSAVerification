module Constants {
  const maxSize := 20;

  // this can change later
  const OPENSSL_VERSION_NUMBER := 0x10100000; // long long type
  const SSL_MODE_AUTO_RETRY := 0x00000004; // unsigned

  // TODO - ensure that exactly one of these mode flags is set at
  // any time on an SSL_CTX object
  // these are the aactual values used in OpenSSL
  const SSL_VERIFY_NONE := 0x00;
  const SSL_VERIFY_PEER := 0x01;
}