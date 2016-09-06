(ns secp256k1.promise.addresses-test
  (:require [secp256k1.promise.addresses :as promise-addresses]
            [secp256k1.hashes :as sync-hashes]
            [secp256k1.formatting.base-convert :refer [byte-array-to-base]]
            [secp256k1.core :as secp256k1]
            [cljs.test :refer-macros [is testing async]]
            [devcards.core :refer-macros [deftest]]))

(defn bitcoin-address
  [data & {:keys [version output-format]
           :or   {version       0x00
                  output-format :base58}}]
  (let [hash     (-> data
                   secp256k1/public-key
                   (secp256k1/x962-encode
                     :output-format :bytes
                     :compressed false)
                   sync-hashes/sha256
                   sync-hashes/ripemd-160)
        checksum (->> hash (cons version) sync-hashes/sha256 sync-hashes/sha256 (take 4))]
    (byte-array-to-base (concat (cons version hash) checksum) output-format)))

(deftest bitcoinaddress-byte-array-test
  (let [pub-key (secp256k1/public-key (secp256k1/private-key "1"))]
    (async done
      (-> (promise-addresses/bitcoinAddressBytes pub-key)
        (.then
          (fn [out]
            (is (= (vec (bitcoin-address pub-key :output-format :bytes)) (vec out))
              "Can asynchronously construct BitCoin address from bytes")
            (done))
          (fn [_]))))))

(deftest bitcoinaddress-byte-array-length-test
  (let [pub-key (secp256k1/public-key (secp256k1/private-key "1"))]
    (async done
      (-> (promise-addresses/bitcoinAddressBytes pub-key)
        (.then (fn [out]
                 (is (= 25 (count out))
                   "Output should have 25 bytes")
                 (done)))))))

(deftest bitcoinaddress-byte-array-bad-pubkey-sadpath-test
  (async done
    (-> (promise-addresses/bitcoinAddressBytes :foo)
      (.then
        (fn [_])
        (fn [err]
          (is (instance? js/Error err)
            "bitcoinAddressBytes Asynchronsly throws an error when handed a keyword argument instead of an ECPoint")
          (done))))))

(deftest bitcoinaddress-byte-array-bad-version-sadpath-test
  (let [pub-key (secp256k1/public-key (secp256k1/private-key
                                        "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"))]
    (async done
      (-> (promise-addresses/bitcoinAddressBytes pub-key :foo)
        (.then
          (fn [_])
          (fn [err]
            (is (instance? js/Error err)
              "bitcoinAddressBytes Asynchronsly throws an error when handed a keyword argument for the version number")
            (done)))))))

(deftest bitcoinaddress-string-test
  (let [pub-key (secp256k1/public-key (secp256k1/private-key
                                        "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"))]
    (async done
      (-> (promise-addresses/bitcoinAddress pub-key)
        (.then (fn [out]
                 (is (= (bitcoin-address pub-key)
                       out
                       "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
                   "Can asynchronously construct a BitCoin address from an ECPoint")
                 (done)))))))

(deftest bitcoinaddress-bad-pubkey-sadpath-test
  (async done
    (-> (promise-addresses/bitcoinAddress :foo)
      (.then
        (fn [_])
        (fn [err]
          (is (instance? js/Error err)
            "bitcoinAddress Asynchronsly throws an error when handed a keyword argument instead of an ECPoint")
          (done))))))

(deftest bitcoinaddress-bad-version-sadpath-test
  (let [pub-key (secp256k1/public-key
                  (secp256k1/private-key
                    "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"))]
    (async done
      (-> (promise-addresses/bitcoinAddress pub-key :foo)
        (.then
          (fn [_])
          (fn [err]
            (is (instance? js/Error err)
              "bitcoinAddress Asynchronsly throws an error when handed a keyword argument for the version number")
            (done)))))))

(deftest bitcoinaddress-byte-array-check-test
  (let [pub-key (secp256k1/public-key
                  (secp256k1/private-key
                    "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"))]
    (async done
      (-> (promise-addresses/bitcoinAddressBytes pub-key)
        (.then promise-addresses/verifyBitcoinAddressBytes)
        (.then (fn [out]
                 (is (= true out)
                   "Can asynchronously construct and correctly verify a BitCoin address as a byte array")
                 (done)))))))

(deftest bitcoinaddress-check-test
  (async done
    (-> (promise-addresses/verifyBitcoinAddress "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
      (.then (fn [out]
               (is (= true out)
                 "Can asynchronously verify a BitCoin address")
               (done))))))