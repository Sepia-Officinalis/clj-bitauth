(ns secp256k1.hashes
  (:require [goog.crypt]
            [secp256k1.formatting.base-convert :refer [bytes?]])
  (:import [goog.crypt Sha256 Hmac]
           [secp256k1.sjcl.hash Ripemd160]))

(defprotocol ByteSerializable
  "Serialize data into a JavaScript array of bytes"
  (to-bytes [this]))

(extend-protocol ByteSerializable
  array (to-bytes [a]
         (assert (bytes? a) "Input must be an array of bytes")
          a)
  string (to-bytes [s] (goog.crypt/stringToUtf8ByteArray s))
  default (to-bytes [x]
            (if (bytes? x)
              (apply array x)
              (throw (ex-info "Cannot convert argument to byte array" x)))))

(defn sha256
  "Get the SHA256 hash and return a byte-array"
  [& data]
  (let [d (Sha256.)]
    (doseq [datum data]
      (.update d (to-bytes datum)))
    (.digest d)))

(defn ripemd-160
  "Get the RIPEMD160 hash and return a byte-array"
  [& data]
  (let [d (Ripemd160.)]
    (doseq [datum data]
      (.update d (to-bytes datum)))
    (.digest d)))

(defn hmac-sha256
  [k data]
  (-> (Hmac. (Sha256.) (to-bytes k))
      (.getHmac (to-bytes data))))
