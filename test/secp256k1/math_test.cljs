(ns secp256k1.math-test
  (:require [clojure.test :refer-macros [is use-fixtures testing are]]
            [devcards.core :refer-macros [deftest defcard]]
            [secp256k1.sjcl.bn.prime :as prime]
            [secp256k1.math :refer [modular-square-root]])
  (:import [secp256k1.math.random Isaac]
           [secp256k1.sjcl bn]))

(deftest modular-square-root-787
  (testing "Can compute square roots modulo 787 (= 3 mod 8)"
    (is (= 3 (-> 787 bn. (.mod 8) .toString js/parseInt)))
    (let [n (-> (js/Math.random) (* 1000) js/Math.floor (+ 2) (js/Math.pow 2))]
      (is
        (= (mod n 787)
          (-> n
            (modular-square-root 787)
            .square
            (.mod 787)
            .toString
            js/parseInt))
        "For some random n"))))

(deftest modular-square-root-7933
  (testing "Can compute square roots modulo 7933 (= 5 mod 8)"
    (is (= 5 (-> 7933 bn. (.mod 8) .toString js/parseInt)))
    (let [n (-> (js/Math.random) (* 1000) js/Math.floor (+ 2) (js/Math.pow 2))]
      (is
        (= (mod n 7933)
          (-> n
            (modular-square-root 7933)
            .square
            (.mod 7933)
            .toString
            js/parseInt))
        "For some random n"))))


(deftest modular-square-root-7937
  (testing "Can compute square roots modulo 7937 (= 1 mod 8)"
    (is (= 1 (-> 7937 bn. (.mod 8) .toString js/parseInt)))
    (let [n (-> (js/Math.random) (* 1000) js/Math.floor (+ 2) (js/Math.pow 2))]
      (is
        (= (mod n 7937)
          (-> n
            (modular-square-root 7937)
            .square
            (.mod 7937)
            .toString
            js/parseInt))
        "For some random n"))))

(deftest modular-square-root-p256k1
  (testing "Can compute square roots modulo p256k1 (= 1 mod 8)"
    (is (= 7 (-> prime/p256k.modulus (.mod 8) .toString js/parseInt)))
    (let [n (-> (js/Math.random) (* 1000) js/Math.floor (+ 2) (js/Math.pow 2))]
      (is
        (= n
          (-> n
            (modular-square-root prime/p256k.modulus)
            .square
            (.mod prime/p256k.modulus)
            .toString
            js/parseInt))
        "For some random n"))))

(deftest isaac-js
  (testing "Isaac.js has basic functionality"
    (is (integer? (-> (new Isaac) .rand)))
    (is (pos? (-> (new Isaac) .rand)))
    (is (= 3967595742 (-> (new Isaac) (.seed 5) .rand)))))
