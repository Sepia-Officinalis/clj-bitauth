(ns secp256k1.promise.hashes-test
  (:require [secp256k1.promise.hashes :as promise-hashes]
            [secp256k1.hashes :as sync-hashes]
            [cljs.test :refer-macros [is testing async]]
            [devcards.core :refer-macros [deftest]])
  (:import [secp256k1.polyfill Promise]))

(deftest promise-test
  (testing "Can construct a Promise"
    (is (instance? Promise (new Promise (fn [resolve] (resolve 1))))))
  (testing "Can construct a Promise which only rejects stuff"
    (is (instance? Promise (new Promise (fn [_ reject] (reject 1))))))
  (async done
    (-> (new Promise (fn [resolve] (resolve 1)))
      (.then
        (fn [val]
               (is (= 1 val)
                 "Can pull value out in happy `resolve` path.")
               (done)))))
  (async done
    (-> (new Promise (fn [_ reject] (reject 2)))
      (.then
        (fn [_])
        (fn [val]
          (is (= 2 val)
            "Can pull value out in sad `reject` path.")
          (done))))))

(deftest sha256-test
  (async done
    (-> (promise-hashes/sha256 #js [])
      (.then (fn [out]
               (is (= (vec (sync-hashes/sha256 []))
                     (vec out))
                 "Can asynchronously perform a SHA256 hash (empty vector)")
               (is (= (vec (sync-hashes/sha256))
                     (vec out))
                 "Can asynchronously perform a SHA256 hash (no input)")
               (done)))))
  (async done
    (-> (promise-hashes/sha256 #js [1 2 3 4])
      (.then (fn [out]
               (is (= (vec (sync-hashes/sha256 [1 2 3 4]))
                     (vec out))
                 "Can asynchronously perform a SHA256 hash ([1 2 3 4])")
               (done)))))
  (async done
    (-> (promise-hashes/sha256 "foo")
      (.then (fn [out]
               (is (= (vec (sync-hashes/sha256 "foo")) (vec out))
                 "Can asynchronously perform a SHA256 hash (\"foo\")")
               (done)))))
  (async done
    (-> (promise-hashes/sha256 "مولوی")
      (.then (fn [out]
               (is (= (vec (sync-hashes/sha256 "مولوی"))
                     (vec out))
                 "\"Mawlawi\" (Farsi)")
               (done)))))
  (is
    (thrown? js/Error (sync-hashes/sha256 :foo))
    "Synchronously throws an error when handed a keyword as an argument")
  (async done
    (-> (promise-hashes/sha256 :foo)
      (.then
        (fn [_])
        (fn [err]
          (is (instance? js/Error err)
            "Asynchronsly throws an error when handed a keyword argument")
          (done))))))
