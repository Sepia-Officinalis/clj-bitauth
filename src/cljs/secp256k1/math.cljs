(ns secp256k1.math
  (:refer-clojure :exclude [even?])
  (:require [secp256k1.formatting.base-convert
             :refer [add-leading-zero-if-necessary]]
            [goog.array :refer [toArray]]
            [secp256k1.sjcl.codec.bytes :as bytes])
  (:import [secp256k1.math.random Isaac]
           [secp256k1.sjcl bn]))

(defn even?
  "Patch the usual cljs.core/even? to work for sjcl.bn instances"
  [n]
  (if (instance? bn n)
    (.equals (.mod n 2) 0)
    (cljs.core/even? n)))

;; TODO: Move this routine to secp256k1.sjcl.bn.prime
(defn modular-square-root
  "Compute the square root of a number modulo a prime"
  [n modulus]
  (let [modulus (if (instance? bn modulus) modulus (new bn modulus))
        n       (.mod (new bn n) modulus)
        mod8    (-> modulus (.mod 8) .toString js/parseInt)]
    (assert (.greaterEquals modulus 0), "Modulus must be non-negative")
    (cond
      (.equals n 0) n

      (.equals n 1) n

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_equal_to_2
      (.equals modulus 2)
      (.mod n modulus)

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_3_modulo_4
      (or (= mod8 3) (= mod8 7))
      (let [m (-> modulus (.add 1) .normalize .halveM .halveM)]
        (.modPow n m modulus))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_5_modulo_8
      (= mod8 5)
      (let [m (-> modulus (.sub 5) .normalize .halveM .halveM .halveM)
            v (.modPow (.add n n) m modulus)
            i (-> (.multiply v v) (.multiply n) (.multiply 2) (.sub 1) (.mod modulus))]
        (-> n (.multiply v) (.multiply i) (.mod modulus)))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_1_modulo_8
      (= mod8 1)
      (let [q   (-> modulus (.sub 1) .normalize)
            e   (->> q
                     (iterate #(.halveM %))
                     (take-while even?)
                     count)
            two (new bn 2)
            z   (->> (range) rest rest
                     (map #(new bn %))
                     (map #(.modPow % q modulus))
                     (filter
                      #(not
                        (.equals
                         (.modPow % (.pow two (- e 1)) modulus)
                         1)))
                     first)
            x   (.modPow n (-> q (.sub 1) .normalize .halveM) modulus)]
        (loop [y z,
               r e,
               v (-> n (.multiply x) (.mod modulus)),
               w (-> n (.multiply x) (.multiply x) (.mod modulus))]
          (if (.equals w 1)
            v
            (let [k (->> (range)
                         (map #(vector
                                %
                                (.modPow w (.pow two %) modulus)))
                         (filter #(.equals (second %) 1))
                         first first)
                  d (.modPow y (.pow two (- r k 1)) modulus)
                  y (.mod (.multiply d d) modulus)
                  v (.mod (.multiply d v) modulus)
                  w (.mod (.multiply w y) modulus)]
              (recur y k v w)))))

      :else
      (throw (ex-info "Cannot compute a square root for a non-prime modulus"
                      {:argument n,
                       :modulus modulus})))))

(defonce
  ^{:doc "A random number generator to fall back on when crypto.getRandomvalues is not available"}
  isaac-rng
  (new Isaac))

(defn- secure-random-bytes
  "Generate secure random bytes in a platform independent manner"
  ;; http://stackoverflow.com/a/19203948/586893
  [byte-count]
  (assert (integer? byte-count) "Argument must be an integer")
  (assert (pos? byte-count) "Argument must greater than 0")
  (cond
    (and (exists? js/crypto)
         (exists? js/crypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/crypto.getRandomValues)
         toArray)

    ;; IE
    (and (exists? js/msCrypto)
         (exists? js/msCrypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/msCrypto.getRandomValues)
         toArray)

    :else
    ;; Fallback to Isaac.js
    (->>
     (repeatedly (-> byte-count (/ 4) js/Math.ceil) #(.rand isaac-rng))
      (apply array)
      bytes/fromBits
     (take byte-count)
     (apply array))))

(defn secure-random
  "Generate a secure random sjcl.bn, takes a maximal value as an argument"
  [arg]
  (let [n            (new bn arg)
        byte-count   (-> n .bitLength (/ 8) js/Math.ceil)
        random-bytes (secure-random-bytes byte-count)]
    (assert (= (count random-bytes) byte-count)
      "Did not retrieve proper correct number of bytes from random byte generator")
    (-> random-bytes
        (->> (map #(add-leading-zero-if-necessary
                    (.toString % 16)))
             (apply str)
             (new bn))
        (.mod n))))
