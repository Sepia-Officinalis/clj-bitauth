(ns secp256k1.tester
  (:require [secp256k1.formatting.der-encoding-test]
            [secp256k1.formatting.base-convert-test]
            [secp256k1.math-test]
            [secp256k1.core-test]
            [secp256k1.hashes-test]
            [secp256k1.promise.hashes-test]
            [secp256k1.promise.addresses-test]
            [secp256k1.sjcl-test]
            [doo.runner :refer-macros [doo-tests]]))

(doo-tests
  'secp256k1.core-test
  'secp256k1.math-test
  'secp256k1.sjcl-test
  'secp256k1.promise.hashes-test
  'secp256k1.promise.addresses-test
  'secp256k1.hashes-test
  'secp256k1.formatting.der-encoding-test
  'secp256k1.formatting.base-convert-test)
