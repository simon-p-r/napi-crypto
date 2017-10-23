# napi-crypto

[![Windows Build Status](https://img.shields.io/appveyor/ci/simon-p-r/napi-crypto/master.svg?label=windows&style=flat-square&maxAge=2592000)](https://ci.appveyor.com/project/simon-p-r/napi-crypto)
[![Current Version](https://img.shields.io/npm/v/napi-crypto.svg?maxAge=1000)](https://www.npmjs.org/package/napi-crypto)
[![dependency Status](https://img.shields.io/david/simon-p-r/napi-crypto.svg?maxAge=1000)](https://david-dm.org/simon-p-r/napi-crypto)
[![devDependency Status](https://img.shields.io/david/dev/simon-p-r/napi-crypto.svg?maxAge=1000)](https://david-dm.org/simon-p-r/napi-crypto)

This was developed against openssl library of nodejs using n-api, currently only works on Windows

# Install

```bash
$ npm install napi-crypto
```

# Usage

### NapiCrypto.createKeyPair()

Example

```js

const NapiCrypto = require('napi-crypto');

NapiCrypto.createKeyPair();
// returns object with members privateKey and publicKey, there value is a string
```

### NapiCrypto.createCSR(options)

certificate - buffer of certificate
privateKey - buffer of privateKey

Example

```js

const NapiCrypto = require('napi-crypto');

const certificate = require('fs').readFileSync('cert.pem', 'utf8');
const privateKey = require('fs').readFileSync('privateKey.pem', 'utf8');
NapiCrypto.createCSR({certificate, privateKey });
// returns buffer on renewed CSR
```

### NapiCrypto.getFingerprint(cert, digest)

Cert - buffer of certificate
Digest - one of md5, sha1, sha256 or sha512 - defaults to sha1


Example

```js

const NapiCrypto = require('napi-crypto');

const cert = require('fs').readFileSync('someCert.pem', 'utf8');
NapiCrypto.getFingerprint(cert, 'sha512');
// returns fingerprint of cert
```

Todo

* improve tests
* cross-platform builds
* ci with appveyor and travis
* pre-built binaries
* publish to npm
* improve error handling 
* add async method if possible
* generate RSA, DSA and EC key pairs
* add self-sign cert method
* improve createCSR to allow generating new one and not just renwing an existing one