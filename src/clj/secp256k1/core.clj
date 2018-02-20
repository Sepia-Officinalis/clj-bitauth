(ns secp256k1.core
  "ECDSA secp256k1 signatures in Clojure."
  (:require [secp256k1.hashes :refer [sha256 ripemd-160]]
            [secp256k1.formatting.der-encoding
             :refer [DER-decode-ECDSA-signature
                     DER-encode-ECDSA-signature]]
            [secp256k1.formatting.base-convert
             :refer [byte-array-to-base
                     base-to-byte-array
                     base-to-base]])
  (:import clojure.lang.Reflector
           java.security.SecureRandom
           org.bouncycastle.asn1.sec.SECNamedCurves
           org.bouncycastle.crypto.digests.GeneralDigest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.generators.ECKeyPairGenerator
           org.bouncycastle.crypto.params.ECDomainParameters
           org.bouncycastle.crypto.params.ECKeyGenerationParameters
           org.bouncycastle.crypto.params.ECPublicKeyParameters
           org.bouncycastle.crypto.signers.HMacDSAKCalculator
           org.bouncycastle.crypto.signers.ECDSASigner
           org.bouncycastle.math.ec.ECAlgorithms))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by BouncyCastle that is used often"}
  curve
  (let [params (SECNamedCurves/getByName "secp256k1")]
    (ECDomainParameters. (.getCurve params)
                         (.getG params)
                         (.getN params)
                         (.getH params))))

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey
  (Class/forName "[B") ; byte-array
  (private-key
    ([data _] (private-key data))
    ([data] (private-key (BigInteger. 1 data))))

  java.math.BigInteger ; Unboxed
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key]
     (assert (<= 1 priv-key) "Private key should be at least 1")
     (assert (<= priv-key (.getN curve))
             "Private key should be less than curve modulus")
     priv-key))

  clojure.lang.BigInt
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key] (-> priv-key biginteger private-key)))

  java.lang.String
  (private-key
    ([priv-key] (private-key priv-key :hex))
    ([encoded-key base]
     (-> encoded-key
         (base-to-byte-array base)
         private-key))))

(defn valid-point?
  "Determine if an Secp256k1 point is valid"
  [point]
  (and (instance? org.bouncycastle.math.ec.ECPoint point)
       (let [x       (-> point .getXCoord .toBigInteger)
             y       (-> point .getYCoord .toBigInteger)
             ecc     (.getCurve curve)
             a       (-> ecc .getA .toBigInteger)
             b       (-> ecc .getB .toBigInteger)
             p       (-> ecc .getField .getCharacteristic)]
         (= (mod (+ (* x x x) (* a x) b) p)
            (mod (* y y) p)))))

(defprotocol PublicKey
  (public-key [this] [this base]))

(extend-protocol PublicKey
  (Class/forName "[B") ; byte-array
  (public-key
    ([data _] (public-key data))
    ([data] (public-key (.decodePoint (.getCurve curve) data))))

  org.bouncycastle.math.ec.ECPoint ; Unboxed
  (public-key
    ([this _] (public-key this))
    ([this]
     (let [point (.normalize this)]
       (assert (valid-point? point) "Invalid Point")
       point)))

  java.lang.String
  (public-key
    ([encoded-key] (public-key encoded-key :hex))
    ([encoded-key base]
     (public-key (base-to-byte-array encoded-key base))))

  java.math.BigInteger ; Private key
  (public-key
    ([this _] (public-key this))
    ([this] (-> curve
                .getG
                (.multiply (private-key this))
                .normalize))))

(defn x962-decode
  "Decode a X9.62 encoded public key"
  [input & {:keys [input-format]
            :or   {input-format :hex}}]
  (public-key input input-format))

(defn x962-encode
  "Encode a public key using X9.62 compression"
  [pub-key & {:keys [compressed output-format input-format]
              :or   {compressed true
                     input-format :hex
                     output-format :hex}}]
  (let [point (public-key pub-key input-format)
        x (-> point .getXCoord .toBigInteger)
        y (-> point .getYCoord .toBigInteger)]
    (-> curve
        .getCurve
        (.createPoint x y compressed)
        .normalize
        .getEncoded
        (byte-array-to-base output-format))))

;; TODO: Switch this to make BitCoin addresses
(defn get-sin-from-public-key
  "Generate a SIN from a public key"
  [pub-key & {:keys [output-format]
              :or   {output-format :base58}}]
  (let [pub-prefixed (-> pub-key
                         (x962-encode :output-format :bytes)
                         sha256
                         ripemd-160
                         (->> (concat [0x0F 0x02])))
        checksum     (->> pub-prefixed
                          sha256
                          sha256
                          (take 4))]
    (byte-array-to-base (concat pub-prefixed checksum) output-format)))

(defn generate-address-pair
  "Generate a new private key and new public key, along with a timestamp"
  []
  (let [priv-key
        (-> (ECKeyPairGenerator.)
            (doto (.init
                   (ECKeyGenerationParameters.
                    curve
                    (SecureRandom.))))
            .generateKeyPair
            .getPrivate .getD
            private-key)
        pub-key (public-key priv-key)]
    {:created (new java.util.Date),
     :private-key priv-key,
     :public-key pub-key}))

(defonce ^:private digest-params (into-array []))

(defn- deterministic-k-generator
  "Generate random numbers following the specification in RFC 6979, Section 3.2
  See: https://tools.ietf.org/html/rfc6979#section-3.2

  Takes a hash (byte-array), ECCurve, and a GeneralDigest
  If no digest is specified this defaults to SHA256

  Returns an object with a method `.nextK` for getting new random values"
  ([priv-key, ^ECDomainParameters curve, #^bytes hash]
   (deterministic-k-generator priv-key curve hash SHA256Digest))
  ([priv-key, ^ECDomainParameters curve, #^bytes hash, ^GeneralDigest digest]
   (assert (= (count hash)
              (-> curve .getN .bitLength (/ 8)))
           "Hash should have the same number of bytes as the curve")
   (doto (HMacDSAKCalculator. (Reflector/invokeConstructor digest digest-params))
     (.init (.getN curve) (private-key priv-key) hash))))

(defn- compute-recovery-byte
  "Compute a recovery byte for a compressed ECDSA signature given R and S parameters"
  [kp r s]
  (let [n       (.getN curve)
        big-r?  (>= r n)
        big-s?  (>= (+ s s) n)
        y-odd?  (-> kp .getYCoord .toBigInteger (.testBit 0))]
    (-> 0x1B
        (+ (if (not= big-s? y-odd?) 1 0))
        (+ (if big-r? 2 0)))))

;; TODO: Move to deterministic, wrap libsecp256k1 instead
(defn sign-hash
  "Sign some hashed data with a private-key; conforms to RFC 6979"
  [priv-key data & {:keys [input-format
                           output-format
                           private-key-format
                           recovery-byte]
                    :or   {input-format :hex
                           private-key-format :hex
                           output-format :hex
                           recovery-byte true}}]
  (let [input    (base-to-byte-array data input-format)
        priv-key (private-key priv-key private-key-format)
        rng      (deterministic-k-generator priv-key curve input)
        n        (.getN curve)
        z        (BigInteger. 1 input)]
    (assert (= (-> curve .getN .bitLength (/ 8)) (count input))
            "Hash must have the same number of bytes as curve")
    (loop []
      (let [k (.nextK rng)
            kp (-> curve .getG (.multiply k) .normalize)
            r (-> kp .getXCoord .toBigInteger (.mod n))
            s_ (-> k
                   (.modInverse n)
                   (.multiply (-> r
                                  (.multiply priv-key)
                                  (.add z)))
                   (.mod n))
            s (if (< (+ s_ s_) n) s_ (.subtract n s_))]
        (if (or (zero? r) (zero? s))
          (recur)
          (-> {:R r :S s
               :recover (when recovery-byte (compute-recovery-byte kp r s_))}
              (DER-encode-ECDSA-signature :input-format :biginteger
                                          :output-format output-format)))))))

(defn sign
  "Sign some data with a private-key"
  [priv-key data & {:keys [output-format
                           private-key-format
                           recovery-byte]
                    :or   {private-key-format :hex
                           output-format :hex
                           recovery-byte true}}]
  (sign-hash priv-key (sha256 data)
             :input-format :bytes
             :private-key-format private-key-format
             :output-format output-format
             :recovery-byte recovery-byte))

(defn- compute-point
  "Compute an elliptic curve point for a y-coordinate parity and x-coordinate"
  [y-even? x-coordinate]
  (let [raw (->> x-coordinate
                 biginteger
                 .toByteArray)
        l (-> curve .getN .bitLength (/ 8))
        input (cond (= l (count raw)) raw
                    (< l (count raw)) (drop-while zero? raw)
                    (> l (count raw))
                    (let [out (byte-array l)]
                      (System/arraycopy
                       raw 0
                       out (- l (count raw))
                       (count raw))
                      out))]
    (-> (cons (if y-even? 0x02 0x03) input)
        byte-array
        public-key)))

(defn ecrecover
  "Given the components of a signature and a recovery value,
  recover and return the public key that generated the
  signature according to the algorithm in SEC1v2 section 4.1.6"
  [hash recovery-byte r s]
  (assert (= (-> curve .getN .bitLength (/ 8))  (count hash))
          (format "Hash should have %d bits (had %d)"
                  (-> curve .getN .bitLength (/ 8))
                  (count hash)))
  (assert (and (number? recovery-byte)
               (<= 0x1B recovery-byte)
               (<= recovery-byte 0x1E))
          (format
           "Recovery byte should be between 0x1B and 0x1E (was %s)"
           (str recovery-byte)))
  (let [y-even? (even? (- recovery-byte 0x1B))
        is-second-key? (odd? (-> recovery-byte
                                 (- 0x1B)
                                 (bit-shift-right 1)))
        n (.getN curve)
        R (compute-point y-even? (if is-second-key? (.add r n) r))
        e-inv (.subtract n (BigInteger. 1 hash))
        r-inv (.modInverse r n)]
    (-> (ECAlgorithms/sumOfTwoMultiplies (.getG curve) e-inv R s)
        (.multiply r-inv)
        public-key)))

(defn recover-public-key-from-hash
  "Recover a public key from a hash"
  [hash signature & {:keys [input-format]
                     :or   {input-format :hex}}]
  (let [{:keys [recover R S]}
        (DER-decode-ECDSA-signature
         signature
         :input-format input-format
         :output-format :biginteger)
        hash (base-to-byte-array hash input-format)]
    (ecrecover hash recover R S)))

(defn recover-public-key
  "Recover a public key from input and its signed hash"
  [input signature & {:keys [input-format]
                      :or   {input-format :hex}}]

  (recover-public-key-from-hash
   (sha256 input)
   (base-to-byte-array signature input-format)
   :input-format :bytes))

(defn verify-ECDSA-signature-from-hash
  "Verifies the given ASN.1 encoded ECDSA signature against a hash using a specified public key"
  [key hash signature
   & {:keys [input-format public-key-format]
      :or   {input-format      :hex
             public-key-format :hex}}]
  (let [bouncy-pub-key (-> key
                           (public-key public-key-format)
                           (ECPublicKeyParameters. curve))
        verifier (doto (ECDSASigner.) (.init false bouncy-pub-key))
        {r :R, s :S} (DER-decode-ECDSA-signature
                      signature
                      :input-format input-format
                      :output-format :biginteger)]
    (.verifySignature
     verifier
     (base-to-byte-array hash input-format) r s)))

(defn verify-signature-from-hash
  "Verifies the given ASN.1 encoded ECDSA signature against a hash using a specified public key"
  [key hash signature & {:keys [input-format public-key-format]
                         :or   {input-format      :hex
                                public-key-format :hex}}]
  (let [pub-key       (public-key key public-key-format)
        input         (base-to-byte-array hash input-format)
        sig-bytes     (base-to-byte-array signature input-format)
        [head1 head2] (take 2 sig-bytes)]
    (cond (and (#{0x1B 0x1C 0x1D 0x1E} head1) (= head2 0x30))
          (= pub-key
             (recover-public-key-from-hash input sig-bytes
                                           :input-format :bytes))

          (= head1 0x30)
          (verify-ECDSA-signature-from-hash pub-key input sig-bytes
                                            :input-format :bytes)

          :else
          (throw (ex-info "Unknown signature header"
                          {:key key
                           :hash hash
                           :signature signature})))))

(defn verify-signature
  "Verifies that the SHA256 hash of a string of data has been signed"
  [key data signature & {:keys [input-format public-key-format]
                         :or   {input-format      :hex
                                public-key-format :hex}}]
  (verify-signature-from-hash
   (public-key key input-format)
   (byte-array-to-base (sha256 data) :bytes)
   (base-to-base signature input-format :bytes)
   :input-format      :bytes
   :public-key-format public-key-format))

(defn validate-sin
  "Verify that a SIN is valid"
  [sin & {:keys [input-format]
          :or   {input-format :base58}}]
    (let [pub-with-checksum (base-to-byte-array sin input-format)
          len               (count pub-with-checksum)
          expected-checksum (->> pub-with-checksum (drop 22) vec)
          actual-checksum   (->> pub-with-checksum
                                 (take 22)
                                 sha256
                                 sha256
                                 (take 4)
                                 vec)
          prefix            (->> pub-with-checksum
                                 (take 2)
                                 vec)]
      (and
       (= len 26)
       (= prefix [0x0f 0x02])
       (= expected-checksum actual-checksum))))
