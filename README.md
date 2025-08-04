# JWE JWK Encrypt/Decrypt

A Go example for encrypting and decrypting data using JSON Web Encryption (JWE)  with these JWK (JSON Web Key) types:
- AES keys (A256KW)
- RSA keys (RSA_OAEP_256)
- ECDH keys (ECDH_ES_A256KW)

The implementation uses [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx) for JWE operations.

## Requirements

This project requires:
- Go 1.24+
- github.com/lestrrat-go/jwx/v3
- github.com/google/uuid
- github.com/stretchr/testify (for tests)

## Installation

```bash
git clone https://github.com/justincranford/jwe-encrypt-decrypt.git
cd jwe-encrypt-decrypt
go mod tidy
```

## Running Tests

```bash
go test ./... --count=1
```

### Known Issues

The current implementation has an issue with ECDH-ES+A256KW encryption in the test file. The error occurs because:

```
Error: jwe.Encrypt: failed to create recipient #0: failed to encrypt key: encrypt: unsupported key type for ECDH-ES: *ecdsa.PrivateKey
```

This issue is related to how the ECDH keys are handled by the jwx library. The test file currently includes ECDH tests, but they are expected to fail with the current implementation.

## License

See the [LICENSE](LICENSE) file for details.
