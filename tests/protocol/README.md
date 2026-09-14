The `localhost-test.pem` certificate and `localhost-test.key` private key are
public, disposable test fixtures generated only for loopback integration tests.
They must never be used for a deployed listener. TLS clients in these tests use
an isolated test client that accepts this self-signed certificate; production
certificate verification is unchanged.
