(ns secp256k1.formatting.der-encoding
  "A (simplified) implementation of the Distinguished Encoding Rules
  for ECDSA signatures, using hexadecimal strings, and other formatting
  utilities.

  https://en.wikipedia.org/wiki/X.690#DER_encoding"
  (:require
   [clojure.string :refer [lower-case]]
   [secp256k1.formatting.base-convert
    :refer [hex?
            add-leading-zero-if-necessary
            base-to-byte-array
            byte-array-to-base
            base-to-base]]))

(defn- encode-asn1-length
  [len]
  (base-to-base len :biginteger :hex))

(defn- decode-asn1-length
  [asn1]
  (let [len (-> asn1 (subs 0 2) (js/parseInt 16))]
    (when-not (zero? (bit-and len 0x80))
      (throw (ex-info "Lengths greater than 0x80 not supported"
                      {:length len
                       :asn1 asn1})))
    {:length len
     :remaining (subs asn1 2)}))

(defn- format-asn1-unsigned-integer
  "Formats a hexadecimal encoding an unsigned integer, dropping left zeros and padding with a left zero if necessary to avoid being confused for a two's complement"
  [n]
  (let [bytes (drop-while zero? (base-to-byte-array n :hex))]
    (-> (if-not (zero? (bit-and (first bytes) 0x80))
          (cons 0 bytes)
          bytes)
        (byte-array-to-base :hex))))

(defn encode-asn1-unsigned-integer
  "Formats a hexadecimal as an unsigned integer, padding and prepending a length"
  [n]
  (if (hex? n)
    (let [formatted-n (format-asn1-unsigned-integer n)
          len         (-> formatted-n count (/ 2)
                          encode-asn1-length)]
      (str "02" len formatted-n))
    (throw (ex-info "Cannot encode argument" {:argument n}))))

(defn decode-asn1-integer
  "Decodes an int from the top of an ASN.1 encoded string"
  [asn1]
  (assert (= (subs asn1 0 2) "02"), "ASN.1 must have a 02 tag for an integer")
  (let [{:keys [length remaining]} (decode-asn1-length (subs asn1 2))]
    {:integer (subs remaining 0 (* 2 length))
     :remaining (subs remaining (* 2 length))}))

(defn- DER-decode-standard
  "Decodes an ordinary encoded list of numbers from a hexadecimal following the distinguished encoding rules"
  [asn1]
  (assert (hex? asn1), "Input must be hex")
  (assert (= "30" (subs asn1 0 2)), "Input must start with the code 30")
  (let [{:keys [:length :remaining]} (decode-asn1-length (subs asn1 2))]
    (when-not (= (* length 2) (count remaining))
      (throw (ex-info "Decoded header length does not match actual length of message"
                      {:decoded-header-length (* 2 length)
                       :actual-length        (count remaining)
                       :message              remaining
                       :full-asn1            asn1})))
    (loop [ret [], remaining remaining]
      (if (empty? remaining)
        ret
        (let [{:keys [:integer :remaining]} (decode-asn1-integer remaining)]
          (recur (conj ret integer) remaining))))))

(defn DER-decode
  "Decodes a list of numbers including an optional recovery byte, following BitCoin's convention"
  [asn1]
  (assert (hex? asn1), "Input must be hex")
  (let [asn1 (lower-case asn1)
        first-byte (subs asn1 0 2)]
    (cond
      (#{ "1b" "1c" "1d" "1e"} first-byte)
      (conj (DER-decode-standard (subs asn1 2))
            first-byte)

      (= "30" first-byte)
      (DER-decode-standard asn1)

      :else
      (throw (ex-info "Input must start with the code 30, or start with a recovery code (either 1b, 1c, 1d, or 1e)"
                      {:argument asn1})))))

(defn DER-encode
  "Formats a list of hexadecimal numbers using the distinguished encoding rules"
  [[R S recover]]
  (->> [R S]
       (map encode-asn1-unsigned-integer)
       (apply str)
       encode-asn1-unsigned-integer
       (#(subs % 2))
       (str recover "30")))

(defn DER-encode-ECDSA-signature
  "Formats an ECDSA signature"
  [{:keys [R S recover]}
   & {:keys [input-format output-format]
      :or {input-format :hex
           output-format :hex}}]
  (-> [R S recover]
      (->> (map #(base-to-base % input-format :hex)))
      DER-encode
      (base-to-base :hex output-format)))

(defn DER-decode-ECDSA-signature
  "Formats an ECDSA signature"
  [ecdsa & {:keys [input-format output-format]
            :or {input-format :hex
                 output-format :hex}}]
  (let [[R S recover]
        (-> ecdsa
            (base-to-base input-format :hex)
            DER-decode
            (->> (map #(base-to-base % :hex output-format))))]
    {:R R
     :S S
     :recover recover}))
