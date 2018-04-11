# Secp256k1
*A Clojure(Script) Cryptography Library*

[![Build Status](https://travis-ci.org/Sepia-Officinalis/secp256k1.svg)](https://travis-ci.org/Sepia-Officinalis/secp256k1)

## Installation

Simply include in your `project.clj` file:

```
:repositories [["jitpack" "https://jitpack.io"]]
:dependencies [[com.github.Sepia-Officinalis/secp256k1 "1.0.3"]]
```

Note that only Java 8+ is support.

## Info

This is a library implements elliptic curve cryptography for [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), the elliptic curve used by BitCoin.

The goals of this project are as follows:

✅ Isomorphic Clojure ⇔ ClojureScript compatibility testing<br/>
✅ Advanced compilation under ClojureScript<br/>
✅ Deterministic ECDSA signatures via [RFC 6979](https://tools.ietf.org/html/rfc6979)<br/>
✅ Public Key recovery via BitCoin's [_recovery id_](https://github.com/bitcoin-core/secp256k1/blob/269d4227038b188128353235a272a8f030c307b1/include/secp256k1_recovery.h#L28) scheme<br/>
½ Access to browser native cryptographic primitives in [`crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)<br/>
❌ [Diffie-Helman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) shared secrets<br/>

## Testing

Testing is carried out at the command line

Clojure:

    lein test


ClojureScript:

    lein test-advanced

