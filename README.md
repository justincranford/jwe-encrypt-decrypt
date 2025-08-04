# JWE Encrypt/Decrypt

A Go library for encrypting and decrypting data using JSON Web Encryption (JWE) with multiple key types.

## Overview

This repository demonstrates how to encrypt and decrypt data using JWE (JSON Web Encryption) with support for multiple key types:
- AES keys (A256KW)
- RSA keys (RSA_OAEP_256)
- ECDH keys (ECDH_ES_A256KW)

The implementation uses [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx) for JWE operations.

## Features

- Encrypt data using JWE with various algorithms
- Decrypt JWE-encrypted data
- Support for multiple key encryption algorithms:
  - AES key wrapping (A256KW)
  - RSA OAEP (RSA_OAEP_256)
  - ECDH key agreement (ECDH_ES_A256KW)
- Content encryption using AES-GCM (A256GCM)
- JWK (JSON Web Key) handling for key management

## Usage

### Examples

The test file `import_encrypt_decrypt_test.go` demonstrates how to:

1. Generate encryption keys (AES, RSA, ECDH)
2. Import keys as JWK (JSON Web Keys)
3. Encrypt data using JWE
4. Decrypt JWE-encrypted data

### Code Overview

The test file contains the following key components:

- `Test_Import_Encrypt`: Main test function that runs encryption/decryption tests for AES, RSA, and ECDH keys
- Key generation functions:
  - `aesTestCase`: Generates AES keys for testing
  - `rsaTestCase`: Generates RSA keys for testing
  - `ecdhTestCase`: Generates ECDH keys for testing
- Core functionality:
  - `importJWK`: Imports keys into JWK format and sets required properties
  - `encrypt`: Encrypts data using JWE with the specified key
  - `decrypt`: Decrypts JWE-encrypted data
  - `extractKidEncAlg`: Helper function to extract key ID, encryption algorithm, and key encryption algorithm from JWK

## Installation

```bash
# Clone the repository
git clone https://github.com/justincranford/jwe-encrypt-decrypt.git
cd jwe-encrypt-decrypt

# Install dependencies
go mod tidy
```

## Requirements

This project requires:
- Go 1.24+
- github.com/lestrrat-go/jwx/v3
- github.com/google/uuid
- github.com/stretchr/testify (for tests)

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
