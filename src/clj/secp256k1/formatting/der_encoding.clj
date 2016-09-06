(ns secp256k1.formatting.der-encoding
  (:require [secp256k1.formatting.base-convert
             :refer [byte-array-to-base
                     base-to-byte-array
                     base-to-base]])
  (:import java.io.ByteArrayOutputStream
           org.bouncycastle.asn1.ASN1InputStream
           org.bouncycastle.asn1.ASN1Integer
           org.bouncycastle.asn1.DERSequenceGenerator))

;; TODO: Move to formatting
(defn DER-encode-ECDSA-signature
  "Create a DER encoded signature"
  [{:keys [R S recover]}
   & {:keys [input-format output-format]
      :or   {input-format :hex
             output-format :hex}}]
  (let [bos (ByteArrayOutputStream.)]
    (with-open [der-gen (DERSequenceGenerator. bos)]
      (doto der-gen
        (.addObject (-> R
                        (base-to-base input-format :biginteger)
                        ASN1Integer.))
        (.addObject (-> S
                        (base-to-base input-format :biginteger)
                        ASN1Integer.))))
    (-> bos
        .toByteArray
        (#(if (nil? recover) %
              (cons (base-to-base recover input-format :biginteger) %)))
        (byte-array-to-base output-format))))

;; TODO: Move to formatting
(defn DER-decode-ECDSA-signature
  "Decode a DER encoded signature"
  [ecdsa & {:keys [input-format output-format]
            :or {input-format :hex
                 output-format :hex}}]
  (let [[head & body :as signature-]
        (base-to-byte-array ecdsa input-format)
        [recover signature]
        (if (#{0x1B 0x1C 0x1D 0x1E} head)
          [head (byte-array body)]
          [nil signature-])]
    (with-open [decoder (ASN1InputStream. signature)]
      (let [sequence (.readObject decoder)]
        {:R (-> sequence (.getObjectAt 0) .getValue
                (base-to-base :biginteger output-format))
         :S (-> sequence (.getObjectAt 1) .getValue
                (base-to-base :biginteger output-format))
         :recover (base-to-base recover :biginteger output-format)}))))
