(ns secp256k1.core
  "A ClojureScript implementation of ECDSA signatures with secp256k1"

  (:refer-clojure :exclude [even?])
  (:require
   [goog.string]
   [goog.string.format]
   [secp256k1.formatting.der-encoding
    :refer [DER-encode-ECDSA-signature
            DER-decode-ECDSA-signature]]
   [secp256k1.math
    :refer [modular-square-root
            even?
            secure-random]]
   [secp256k1.formatting.base-convert
    :refer [base-to-byte-array
            base-to-base
            byte-array-to-base
            bytes?]]
   [secp256k1.sjcl.ecc.curves :as ecc-curves]
   [secp256k1.sjcl.ecc.ECPoint :as ecc-ecpoint]
   [secp256k1.hashes :refer [sha256 ripemd-160 hmac-sha256]]
   [secp256k1.sjcl.codec.bytes :as bytes]
   [secp256k1.sjcl.codec.hex :as hex])
  (:import [secp256k1.sjcl bn]
           [secp256k1.sjcl.ecc ECPoint]))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
  curve ecc-curves/k256)

(extend-protocol IEquiv
  bn
  (-equiv [a b]
    (and
      (instance? bn b)
      (.equals a b)))

  ECPoint
  (-equiv [a b]
    (and
      (instance? ECPoint b)
      (= (.-curve a) (.-curve b))
      (if (.-isIdentity a)
        (.-isIdentity b)
        (let [ax (-> a .-x)
              bx (-> b .-x)
              ay (-> a .-y)
              by (-> b .-y)]
          (and
            (every? (complement nil?) [ax bx ay by])
            (= ax bx)
            (= ay by)))))))

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey
  bn ; Unboxed
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key]
     (assert
       (.greaterEquals priv-key 1)
       "Private key should be greater than or equal to 1")
     (assert
       (.greaterEquals (.-r curve) priv-key)
       "Private key should be less than or equal to the curve modulus")
     priv-key))

  array ; byte-array
  (private-key
    ([priv-key _]
     (private-key priv-key))
    ([priv-key]
     (private-key (base-to-base priv-key :bytes :biginteger))))

  string
  (private-key
    ([this base]
     (-> this
       (base-to-base base :biginteger)
       private-key))
    ([this]
     (private-key this :hex))))

(defprotocol PublicKey
  (public-key [this] [this base]))

(defn valid-point?
  "Predicate to determine if something is a valid ECC point on our curve"
  [point]
  (and
    (instance? ECPoint point)
    (= (.-curve point) curve)
    (.isValid point)))

(defn- compute-point
  "Compute an elliptic curve point for a y-coordinate parity and x-coordinate"
  [y-even x]
  (let [modulus     (-> curve .-field .-modulus)
        ;; √(x * (a + x**2) + b) % p
        y-candidate (modular-square-root
                     (.add
                      (.multiply x (.add (.-a curve) (.square x)))
                      (.-b curve))
                     modulus)
        y           (if (= y-even (even? y-candidate))
                      y-candidate
                      (.sub modulus y-candidate))]
    (public-key (new ECPoint curve x y))))

(defn- x962-hex-compressed-decode
  [encoded-key]
  (let [x      (-> encoded-key (subs 2) bn.)
        y-even (= (subs encoded-key 0 2) "02")]
    (compute-point y-even x)))

(defn- x962-hex-uncompressed-decode
  [encoded-key]
  (let [l (-> curve .-r .bitLength (/ 4))
        x (subs encoded-key 2 (+ 2 l))
        y (subs encoded-key (+ 2 l))]
    (public-key (new ECPoint curve x y))))

(defn x962-decode
  "Decode a X9.62 encoded public key"
  [input & {:keys [input-format]
            :or   {input-format :hex}}]
  (let [encoded-key (base-to-base input input-format :hex)
        l           (-> curve .-r .bitLength (/ 4))]
    (cond
      (and (#{"02" "03"} (subs encoded-key 0 2))
           (= (+ 2 l) (count encoded-key)))
      (x962-hex-compressed-decode encoded-key)

      (and (= "04" (subs encoded-key 0 2))
           (= (+ 2 (* 2 l)) (count encoded-key)))
      (x962-hex-uncompressed-decode encoded-key)

      :else
      (throw (ex-info "Invalid encoding on public key"
                      {:encoded-key encoded-key})))))

(extend-protocol PublicKey
  ;; Unboxed
  ECPoint
  (public-key
    ([point _]
     (assert (valid-point? point) "Invalid point")
     point)
    ([point]
     (assert (valid-point? point) "Invalid point")
     point))

  array ; byte-array
  (public-key
    ([encoded-key _]
     (x962-decode encoded-key :input-format :bytes))
    ([encoded-key]
     (x962-decode encoded-key :input-format :bytes)))

  string
  (public-key
    ([encoded-key base]
     (x962-decode encoded-key :input-format base))
    ([encoded-key]
     ;; Default to hex
     (x962-decode encoded-key :input-format :hex)))

  bn
  (public-key
    ([priv-key _]
     (.multiply (.-G curve) (private-key priv-key)))
    ([priv-key]
     (.multiply (.-G curve) (private-key priv-key)))))

(defn x962-encode
  "Encode a sjcl.ecc.point as hex using X9.62 compression"
  [pub-key &
   {:keys [compressed output-format input-format]
    :or   {compressed    true
           input-format  :hex
           output-format :hex}}]
  (let [point (public-key pub-key input-format)
        l     (-> point .-curve .-field .-exponent)
        x     (-> point .-x (.toBits l) hex/fromBits)]
    (->
      (if compressed
        (str (if (-> point .-y even?) "02" "03") x)
        (let [y (-> point .-y .toBits hex/fromBits)]
          (str "04" x y)))
      (base-to-base :hex output-format))))

;; TODO: Switch to bitcoin addresses
(defn get-sin-from-public-key
  "Generate a SIN from a public key"
  [pub-key & {:keys [input-format output-format]
              :or   {input-format :hex
                     output-format :base58}}]
  (let [pub-prefixed (-> pub-key
                         (public-key input-format)
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
  (let [priv-key (private-key (secure-random (.-r curve)))]
    {:created (new js/Date),
     :private-key  priv-key,
     :public-key (public-key priv-key)}))


;; TODO: Implement BouncyCastle's Deterministic K generator
(defn deterministic-generate-k
  "Deterministically generate a random number in accordance with RFC 6979"
  [priv-key hash]
  (let [l            (-> curve .-r .bitLength)
        curve-bytes  (/ l 8)
        v            (repeat curve-bytes 0x01)
        k            (repeat curve-bytes 0x00)
        pk           (-> priv-key
                         private-key
                         (.toBits l)
                         bytes/fromBits)
        left-padding (repeat (- curve-bytes (count hash)) 0)
        hash         (concat left-padding hash)
        k            (hmac-sha256 k (concat v [0] pk hash))
        v            (hmac-sha256 k v)
        k            (hmac-sha256 k (concat v [1] pk hash))
        v            (hmac-sha256 k v)]
    (assert (= (count hash) curve-bytes)
            "Hash should have the same number of bytes as the curve modulus")
    (byte-array-to-base (hmac-sha256 k v) :biginteger)))

(defn- compute-recovery-byte
  "Compute a recovery byte (as a hex string) for a compressed ECDSA signature given R and S parameters"
  [kp r s]
  (let [n       (.-r curve)
        big-r?  (.greaterEquals r n)
        big-s?  (.greaterEquals (.add s s) n)
        y-odd?  (-> kp .-y even? not)]
    (-> 0x1B
        (+ (if (not= big-s? y-odd?) 1 0))
        (+ (if big-r? 2 0))
        (.toString 16))))

;; TODO: Add cannonical flag
(defn sign-hash
  "Sign some a hash of some data with a private-key"
  [priv-key hash & {:keys [input-format
                           output-format
                           private-key-format
                           recovery-byte]
                    :or   {input-format :hex
                           private-key-format :hex
                           output-format :hex
                           recovery-byte true}}]
  (let [d     (private-key priv-key private-key-format)
        n     (.-r curve)
        l     (.bitLength n)
        input (base-to-byte-array hash input-format)
        z     (byte-array-to-base input :biginteger)
        k     (deterministic-generate-k d input)
        kp    (-> curve .-G (.multiply k))
        r     (-> kp .-x (.mod n))
        s_    (-> (.multiply r d) (.add z) (.multiply (.modInverse k n)) (.mod n))
        s     (if (.greaterEquals (.add s_ s_) n)
                (.sub n s_)
                s_)]
    (assert (= (count input) (-> curve .-r .bitLength (/ 8)))
            "Hash should have the same number of bytes as the curve modulus")
    (DER-encode-ECDSA-signature
     {:R (-> r (.toBits l) hex/fromBits)
      :S (-> s (.toBits l) hex/fromBits)
      :recover (when recovery-byte (compute-recovery-byte kp r s_))}
     :output-format output-format)))

;; TODO: Add cannonical flag
(defn sign
  "Sign some data with a private-key"
  [priv-key data & {:keys [output-format
                           private-key-format
                           recovery-byte]
                    :or   {private-key-format :hex
                           output-format :hex
                           recovery-byte true}}]
  (sign-hash priv-key
             (sha256 data)
             :input-format :bytes
             :output-format output-format
             :private-key-format private-key-format
             :recovery-byte recovery-byte))

(defn ecrecover
  "Given the components of a signature and a recovery value,
  recover and return the public key that generated the
  signature according to the algorithm in SEC1v2 section 4.1.6"
  [hash recovery-byte r s]
  (assert (= (-> curve .-r .bitLength (/ 8))  (count hash))
          (goog.string/format "Hash should have %d bits (had %d)"
                              (-> curve .-r .bitLength (/ 8))
                              (count hash)))
  (assert (and (instance? bn recovery-byte)
               (.greaterEquals recovery-byte 0x1B)
               (.greaterEquals (bn. 0x1E) recovery-byte))
          (goog.string/format
           "Recovery byte should be between 0x1B and 0x1E (was %s)"
           (str recovery-byte)))
  (let [y-even (even? (- recovery-byte 0x1B))
        is-second-key? (odd? (-> recovery-byte
                                 .toString
                                 js/parseInt
                                 (- 0x1B)
                                 (bit-shift-right 1)))
        n (.-r curve)
        R (compute-point y-even (if is-second-key? (.add r n) r))
        r-inv (.modInverse r n)
        e-inv (.sub n (byte-array-to-base hash :biginteger))]
    (-> (ecc-ecpoint/sumOfTwoMultiplies e-inv (.-G curve) s R)
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
  (let [pub-key (public-key key public-key-format)
        {r :R, s :S} (DER-decode-ECDSA-signature
                      signature
                      :input-format input-format
                      :output-format :biginteger)
        n            (.-r curve)
        r            (.mod r n)
        s-inv        (.modInverse s n)
        z            (.mod (byte-array-to-base hash :biginteger) n)
        u1           (-> z
                         (.multiply s-inv)
                         (.mod n))
        u2           (-> r (.multiply s-inv) (.mod n))
        r2           (-> (ecc-ecpoint/sumOfTwoMultiplies u1 (.-G curve) u2 pub-key)
                         .-x (.mod n))]
    (= r r2)))

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

          :else (throw (ex-info "Unknown signature header"
                          {:key key
                           :hash hash
                           :signature signature})))))

(defn verify-signature
  "Verifies that a string of data has been signed"
  [pub-key data signature
   & {:keys [input-format public-key-format]
      :or   {input-format      :hex
             public-key-format :hex}}]
  (verify-signature-from-hash
   (public-key pub-key public-key-format)
   (sha256 data)
   (base-to-byte-array signature input-format)
   :input-format :bytes))

;; TODO: Switch to BitCoin Addressess
;; TODO: Get rid of try-swallow
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
