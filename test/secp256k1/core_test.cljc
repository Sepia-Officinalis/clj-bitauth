(ns secp256k1.core-test
  (:require [secp256k1.core :as secp256k1]
            [secp256k1.formatting.base-convert :as convert]
            [secp256k1.hashes :refer [to-bytes]]
            #?(:clj  [clojure.test
                      :refer [is use-fixtures
                              testing are run-tests deftest]]
               :cljs [cljs.test
                      :refer-macros [is use-fixtures testing are]])
            #?(:cljs [devcards.core
                      :refer-macros [defcard deftest]]))
  #?(:cljs (:import [secp256k1.sjcl bn]
                    [secp256k1.sjcl.ecc ECPoint])
     :clj  (:import [org.bouncycastle.math.ec ECPoint])))

#?(:cljs
   (defcard x962-encode-performance
     "Parse and x962-encode a private key"
     (with-out-str
       (time (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
                 secp256k1/private-key
                 secp256k1/x962-encode)))))

#?(:cljs
   (defcard x962-decode-performance
     "Decode a compressed x962-encoded public key"
     (with-out-str
       (time (-> "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
                 secp256k1/public-key)))))

(deftest get-public-key-from-private-key-with-leading-zero
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             secp256k1/private-key
             secp256k1/x962-encode))
      "Public key should start with a leading zero")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             secp256k1/private-key
             secp256k1/x962-encode
             secp256k1/public-key
             secp256k1/x962-encode))
      "Public key should be recoverable from encoded key")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             (secp256k1/private-key :hex)
             secp256k1/x962-encode))
      "Public key should start with a leading zero (explicit hex encoding)")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             (secp256k1/private-key :hex)
             secp256k1/public-key
             secp256k1/x962-encode))
      "Public key should start with a leading zero (explicit coercing to public-key)")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             (secp256k1/private-key :hex)
             (secp256k1/public-key :not-used)
             secp256k1/x962-encode))
      "Public key should start with a leading zero (explicit coercion to public key with unused base argument)")
  (is (= "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             secp256k1/private-key
             (secp256k1/x962-encode :compressed false)))
      "Public key should start with a leading zero (uncompressed)")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> [0xc6 0xb7 0xf6 0xbf 0xe5 0xbb 0x19 0xb1 0xe3 0x90 0xe5
              0x5e 0xd4 0xba 0x5d 0xf8 0xaf 0x60 0x68 0xd0 0xeb 0x89
              0x37 0x9a 0x33 0xf9 0xc1 0x9a 0xac 0xf6 0xc0 0x8c]
             to-bytes
             secp256k1/private-key
             secp256k1/x962-encode))
      "From a byte array")
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (-> [0x02 0x00 0xbf 0x0e 0x38 0xb8 0x63 0x29 0xf8 0x4e 0xa9
              0x09 0x72 0xe0 0xf9 0x01 0xd5 0xea 0x01 0x45 0xf1 0xeb
              0xac 0x8c 0x50 0xfd 0xed 0x77 0x79 0x6d 0x7a 0x70 0xe1]
             to-bytes
             secp256k1/x962-encode))
      "From a byte array (compressed public key)")
  #?(:clj
     (is (= "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
            (-> 0xc6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c
                secp256k1/private-key
                (secp256k1/x962-encode :compressed false)))
         "From a clojure.lang.BigInt")))

(deftest x962-encode-different-bases-test
  (is (= "BAC/Dji4Yyn4TqkJcuD5AdXqAUXx66yMUP3td3ltenDhvp4AG37OBx+zmGtelmmf4o297siVZoLaeKX2oRW58Uw="
         (-> "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
             secp256k1/public-key
             (secp256k1/x962-encode :compressed false
                                    :output-format :base64)))
      "Base 64")
  (is (= "BAC/Dji4Yyn4TqkJcuD5AdXqAUXx66yMUP3td3ltenDhvp4AG37OBx+zmGtelmmf4o297siVZoLaeKX2oRW58Uw="
         (-> "BAC/Dji4Yyn4TqkJcuD5AdXqAUXx66yMUP3td3ltenDhvp4AG37OBx+zmGtelmmf4o297siVZoLaeKX2oRW58Uw="
             (secp256k1/public-key :base64)
             (secp256k1/x962-encode :compressed false
                                    :output-format :base64)))
      "Base 64 (input)")
  (is (= "MVJW3Nbw27JppJfCfMVWfi6FWBkrk47rt8vsUTQp8WYM4U7jStxkYLaPCP5YvJ8hphYsVpRQuiXah5uWEi95SVLf"
         (-> "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
             secp256k1/public-key
             (secp256k1/x962-encode :compressed false
                                    :output-format :base58)))
      "Base 58")
  (is (= "MVJW3Nbw27JppJfCfMVWfi6FWBkrk47rt8vsUTQp8WYM4U7jStxkYLaPCP5YvJ8hphYsVpRQuiXah5uWEi95SVLf"
         (-> "MVJW3Nbw27JppJfCfMVWfi6FWBkrk47rt8vsUTQp8WYM4U7jStxkYLaPCP5YvJ8hphYsVpRQuiXah5uWEi95SVLf"
             (secp256k1/public-key :base58)
             (secp256k1/x962-encode :compressed false
                                    :output-format :base58)))
      "Base 58 (input)")
  (is (= "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
         (-> "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
             (convert/base-to-byte-array :hex)
             (secp256k1/public-key :hex)
             (secp256k1/x962-encode :compressed false
                                    :output-format :hex)))))

(deftest public-private-key-equality
  (testing "Checking that equality works for private-keys"
    (is
     (=
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"))
     "Reflexivity")
    (is
     (=
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
      (secp256k1/private-key
       (secp256k1/private-key
        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")))
     "Idempotence for private-key protocol")
    (is
     (not=
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
      (secp256k1/private-key
       "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c"))
     "Sad path for equality (same type)")
    (is
     (not=
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
      :foo)
     "Sad path for equality (keyword type)"))
  (testing "Checking that equality works for public-keys"
    (is
     (=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"))
     "Reflexivity")
    (is
     (=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      (secp256k1/public-key
       (secp256k1/public-key
        "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")))
     "Idempotence for public-key protocol")
    (is
     (not=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      (secp256k1/public-key
       "033142109aba8e415c73defc83339dcec52f40ce762421c622347a7840294b3423"))
     "Sad path for equality (same type)")
    (is
     (not=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      "test")
     "Sad path for equality (string type)")
    (is
     (not=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      (secp256k1/private-key
       "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"))
     "Sad path for equality (other object is a private-key)")
    (is
     (=
      (secp256k1/public-key
       "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")
      (secp256k1/public-key
       "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"))
     "Compressed and uncompressed public keys are equal")))

(deftest get-private-key-sad-path
  (testing "Throws when trying to make a private key that's too big"
    (is
     (thrown?
      #?(:clj java.lang.IllegalArgumentException
         :cljs js/Error)
      (secp256k1/private-key
       "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c9999999999999")))))

(deftest known-results-tests
  (testing "A number of known priv-key, pub-key and SINs as reference"
    (let [priv-key
          "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c",
          pub-key
          "02326209e52f6f17e987ec27c56a1321acf3d68088b8fb634f232f12ccbc9a4575",
          sin "Tf3yr5tYvccKNVrE26BrPs6LWZRh8woHwjR"]
      (is (= pub-key (-> priv-key
                         secp256k1/private-key
                         secp256k1/x962-encode))
          "Public key k1 corresponds to private key")
      (is (= sin (secp256k1/get-sin-from-public-key pub-key))))

    (let [priv-key
          (secp256k1/private-key
           "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"),
          pub-key
          "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58",
          sin "TfJq16yg72aV9PqsZkhmiojuBRghdGWYcmj"]
      (is (= pub-key (secp256k1/x962-encode priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (secp256k1/get-sin-from-public-key
                  (secp256k1/public-key pub-key)))))

    (let [priv-key
          "e9d5516cb0ae45952fa11473a469587d6c0e8aeef3d6b0cca6f4497c725f314c",
          pub-key
          (secp256k1/public-key
           "033142109aba8e415c73defc83339dcec52f40ce762421c622347a7840294b3423"),
          sin "Tewyxwicyc7dyteKAW1i47oFMc72HTtBckc"]
      (is (= pub-key (-> priv-key
                         secp256k1/private-key
                         secp256k1/public-key))
          "Public key k1 corresponds to private key")
      (is (= sin (secp256k1/get-sin-from-public-key pub-key))))

    (let [priv-key
          (secp256k1/private-key
           "9e15c053f17c0991163073a73bc7e4b234c6c55c5f85bb397ed39f14c46a64bd"),
          pub-key
          (secp256k1/public-key
           "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"),
          sin "TfJXKWBfHBSKf4ciN5LFPQTH5FxvsffvqNW"]
      (is (= pub-key (secp256k1/public-key priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (secp256k1/get-sin-from-public-key pub-key))))))

(deftest x962-encode-decode
  (testing "x962-encode is idempotent on compressed keys"
    (letfn [(encode-decode [x]
              (secp256k1/x962-encode x))]
      (are [y] (= y (encode-decode y))
        "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
        "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
        "03816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846"
        "0233bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd1"
        "02e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e"
        "03fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c"
        "033502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9"
        "0387efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5")))


  (testing "Sad path: `secp256k1/public-key` and `secp256k1/x962-encode` throw on bad input"
    (is (thrown? #?(:clj java.lang.IllegalArgumentException
                    :cljs js/Error)
                 (secp256k1/x962-encode
                  "02bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1")))
    (is (thrown? #?(:clj java.lang.IllegalArgumentException
                    :cljs js/Error)
                 (secp256k1/public-key
                  "04bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c")))
    (is (thrown? #?(:clj java.lang.IllegalArgumentException
                    :cljs js/Error)
                 (secp256k1/x962-encode
                  "04bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c")))
    (is (thrown? #?(:clj java.lang.IllegalArgumentException
                    :cljs js/Error)
                 (secp256k1/x962-encode
                  "04bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"))))

  (testing "x962-encode can handle both compressed and uncompressed keys"
    (are [y] (= y (-> y
                      secp256k1/public-key
                      (secp256k1/x962-encode :compressed false)
                      (secp256k1/x962-encode :compressed false)
                      secp256k1/public-key
                      secp256k1/public-key
                      secp256k1/x962-encode
                      secp256k1/x962-decode
                      (secp256k1/x962-encode :output-format :base58)
                      (secp256k1/x962-decode :input-format :base58)
                      secp256k1/x962-encode
                      (secp256k1/x962-encode :compressed false)
                      secp256k1/x962-encode
                      (secp256k1/x962-encode :compressed false)))
      "04256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1ca81c29a7307b6c77182b77ce9699b6b2940610b2306825fd38a475dd3c804c4"
      "0433952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58a002d2f3b46b55c54d1780c176119497cb81b0ace382227f2a6b8b3ba1eccd83"
      "04816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846eea75ae3bd6a053582d362a054129567ff2e0c4877e7b2a4d958913121b099f7"
      "0433bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd11880422a1640df75f9601927e09b6c053e0aef740f52fc4b341e750891294210"
      "04e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e02cd25f31fd29119c7259840b97855156f3a9ac52f7ae0cb69c22695e649d2fc"
      "04fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c07532c7c1481771989377bb0a7820c554c272fd77cdf2dac55f3aa1eca82eaf5"
      "043502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9dd3c65e83963adac704e5782b5f886280a8c4960f1e49152b139bfd05862c7af"
      "0487efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5aa43aaed73348f97b306145ce0544078210f7e587c675805ccc0933d6673c979"))

  (testing "More checks that x962-point-encoding is idempotent"
    (letfn [(encode-decode [x]
              (secp256k1/x962-encode
               (secp256k1/x962-encode
                (secp256k1/public-key x))))]
      (are [y] (= y (encode-decode y))
        "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
        "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
        "03816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846"
        "0233bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd1"
        "02e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e"
        "03fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c"
        "033502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9"
        "0387efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5"))))


#?(:cljs
   (deftest deterministic-generate-k-test
     (testing "Generate a k deterministically"
       (is (= "010497d369b3d525ca15ec29c104a694210bb59ff6cabfc10afe6df0283896df"
              (convert/base-to-base (secp256k1/deterministic-generate-k "1" [])
                                    :biginteger
                                    :hex)))
       (is (= "0ac9323d1d29458f8e0a3a36b0634edadec5c62b38c49995f038a168677538c0"
              (convert/base-to-base (secp256k1/deterministic-generate-k
                                     "111111111111111111111111111111111111111111111111111" [])
                                    :biginteger
                                    :hex))))))


(deftest sign-tests
  (testing "Signed messages can be checked with a proper pub key"
    (let [priv-key (secp256k1/private-key "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c")]
      (are [x] (secp256k1/verify-signature
                priv-key x
                (secp256k1/sign priv-key x))
        "foo"

        "bar"

        "yabba dabba dooo"

        "I wanna hold 'em like they do in Texas, please
         Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)
         Love game intuition play the cards with Spades to start
         And after he's been hooked I'll play the one that's on his heart"

        "☕️   ⓝ  🀤  ⎈  ∲"

        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。")))

  (testing "Bad public-key does not verify"
    (is
     (secp256k1/verify-signature
      "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
      "foo"
      "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567")
     "Happy path")
    (is
     (thrown? #?(:clj Throwable :cljs js/Error)
              (secp256k1/verify-signature
               "0333952d51e42f7eb05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
               "foo"
               "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567")))
    "Corrupted bit")

  (testing "Reference signatures"
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
          pub-key (-> priv-key
                      secp256k1/private-key
                      secp256k1/x962-encode)]
      (are [x y] (secp256k1/verify-signature pub-key x y)
        "foo"
        "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567",

        "baz"
        "304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae",

        "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!",
        "304402204c818a10380ba42b3be0a293d47922469c4ae7ad6277e0e62bf32700c79c32210220102b673477ee13877b4b7f8f9a2e4c2004553948fbe5e7fd95d7e23b4cd9f8e3",

        "☕️   ⓝ  🀤  ⎈  ∲"
        "304502204d78e57e9bce7fc6d3dd61bcd1baaceff2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1",

        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"
        "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c",

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "3044022030e9acbd8f0f3328bd059296092824a38216a222d04ac7e1f3de89d4270f3e18022014386f61154177111fe1da0eee9874e612990d3ce663e6f2b4c44828b4c7072f",

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。",
        "3046022100b286833ddce1537e12f56ae63fbbd6db25ac0dfab659d342a323b764765b60c0022100d83878b0529bf2cab70e98929faf11d1836d8452ef978aad558e35cce4fb14c4",

        "ဂျူးလိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)"
        "304402206ba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8",

        "རོ་མའི་རང་དབང་འབངས་མི་ཞིག་ལ་མིང་གསུམ་ཡོད་དེ།"
        "304402200e4b0560c42e4de19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c")))

  (testing "Bad signatures"
    (let [priv-key
          (secp256k1/private-key
           "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0")
          pub-key (secp256k1/public-key priv-key)]
      (are [x y] (thrown? #?(:clj Throwable
                             :cljs js/Error)
                          (secp256k1/verify-signature pub-key x y))
        5
        "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567",

        "baz"
        "XXX304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae",

        "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!",
        :foo,

        nil
        "304502204d78e57f2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1",

        (constantly :foo)
        "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c",

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "I should fail",

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"
        7,

        "ဂျူးလိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)"
        "304402206བང་འབངས་མི་ཞིག་ལ་མba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8",

        "རོ་མའི་རང་དབང་འབངས་མི་ཞིག་ལ་མིང་གསུམ་ཡོད་དེ།"
        "304402200e4b0560c42e4d1e19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c"))))

(deftest deterministic-signatures
  (testing "Can verify a deterministic signature"
    (is (= true
           (let [pk (secp256k1/private-key
                     "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0")
                 input "foo"
                 sig "3045022100927247ae8b1d692d99096ea0a352ca99a4af84377af8152ccca671f24bc6169702206c3d28b9025d618c20612c4fdde67f052abf0e5e08c471c5c88baa96ce9538e1"]
             (secp256k1/verify-signature pk input sig)))))
  (testing "Can make a signature in accordance with RFC 6979"
    (is (= "1c3045022100927247ae8b1d692d99096ea0a352ca99a4af84377af8152ccca671f24bc6169702206c3d28b9025d618c20612c4fdde67f052abf0e5e08c471c5c88baa96ce9538e1"
           (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
               secp256k1/private-key
               (secp256k1/sign "foo" :recovery-byte true)))
        "Recovery byte present (signing \"foo\")")
              (is (= "1b3045022100c738f07424690873da0afadd04a9afd4aedb3abe6db7cea6daed06a211c6dd6f02201c386378ab4e9438af27601a9887c361dd3c9661d04322c94393edb7cd8cd512"
                (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
                    secp256k1/private-key
                    (secp256k1/sign "barr" :recovery-byte true)))
             "Recovery byte present (signing \"bar\")")
         (is (= "3045022100c738f07424690873da0afadd04a9afd4aedb3abe6db7cea6daed06a211c6dd6f02201c386378ab4e9438af27601a9887c361dd3c9661d04322c94393edb7cd8cd512"
                (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
                    secp256k1/private-key
                    (secp256k1/sign "barr" :recovery-byte false)))
             "Recovery byte *NOT* present (signing \"bar\")")
         (is (= "3045022100927247ae8b1d692d99096ea0a352ca99a4af84377af8152ccca671f24bc6169702206c3d28b9025d618c20612c4fdde67f052abf0e5e08c471c5c88baa96ce9538e1"
                (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
                    secp256k1/private-key
                    (secp256k1/sign "foo" :recovery-byte false)))
             "Recovery byte *NOT* present (signing \"foo\")")
         (is (= "1b30440220459b7817cf2f9162c35b5c5adf6db0d6c605fe417705e5772371b9cb6d7af57e022044795b40b916727a020113cfcb3312088d9fcd617cfead0cb7ff7307d56c83cf"
                (secp256k1/sign
                 (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9")
                 "trololololol"
                 :recovery-byte true)))
         (is (= "1b30440220459b7817cf2f9162c35b5c5adf6db0d6c605fe417705e5772371b9cb6d7af57e022044795b40b916727a020113cfcb3312088d9fcd617cfead0cb7ff7307d56c83cf"
                (secp256k1/sign
                 (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9")
                 "trololololol")))
         (is (= "GzBEAiBFm3gXzy+RYsNbXFrfbbDWxgX+QXcF5XcjcbnLbXr1fgIgRHlbQLkWcnoCARPPyzMSCI2fzWF8/q0Mt/9zB9Vsg88="
                (secp256k1/sign
                 (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9")
                 "trololololol"
                 :output-format :base64)))
         (is (= "1c304402202db8497f44aa119b7a5bdbb4ea75c0f3c0365ea07c1668b86182aac44f5767c1022041ee99d08138b26ce69af7a2de9ebff09cee5724b765576031ea4322b724f2e7"
                (secp256k1/sign-hash
                 (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9")
                 "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
                 :output-format :hex)))
         (is (= "HDBEAiAtuEl/RKoRm3pb27TqdcDzwDZeoHwWaLhhgqrET1dnwQIgQe6Z0IE4smzmmvei3p6/8JzuVyS3ZVdgMepDIrck8uc="
                (secp256k1/sign-hash
                 (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9")
                 "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
                 :output-format :base64)))))

(deftest recovery-byte-tests
  (testing "Can recover a public key from a signature with a recovery byte"
    (is (= (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0" secp256k1/private-key secp256k1/public-key)
           (-> "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
               secp256k1/private-key
               (secp256k1/sign "foo" :recovery-byte true)
               (->> (secp256k1/recover-public-key "foo")))))
    (is (= (secp256k1/public-key (secp256k1/private-key "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9"))
           (secp256k1/recover-public-key
            "trololololol"
            "GzBEAiBFm3gXzy+RYsNbXFrfbbDWxgX+QXcF5XcjcbnLbXr1fgIgRHlbQLkWcnoCARPPyzMSCI2fzWF8/q0Mt/9zB9Vsg88="
            :input-format :base64)))
    (is (= (secp256k1/public-key
            (secp256k1/private-key
             "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9"))
           (secp256k1/recover-public-key
            "trololololol"
            "1b30440220459b7817cf2f9162c35b5c5adf6db0d6c605fe417705e5772371b9cb6d7af57e022044795b40b916727a020113cfcb3312088d9fcd617cfead0cb7ff7307d56c83cf")))
    (is (= (secp256k1/public-key
            (secp256k1/private-key
             "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9"))
           (secp256k1/recover-public-key-from-hash
            "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
            "1c304402202db8497f44aa119b7a5bdbb4ea75c0f3c0365ea07c1668b86182aac44f5767c1022041ee99d08138b26ce69af7a2de9ebff09cee5724b765576031ea4322b724f2e7")))
    ))

;; TODO: test different input formats
(deftest sin-tests
  (testing "Reference sins are valid"
    (are [x] (= (secp256k1/validate-sin x) true)
      "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
      "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
      "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
      "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
      "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
      "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
      "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X"))

  (testing "Sad Path: Invalid Sins"
    (are [x] (= (secp256k1/validate-sin x) false)
      ""
      "TfGVzWqwft6fFdLzyvR7qFTT77N7aTqa4n"
      "Tf4Lo9zAezP7LKc3njaK5pez7oVhzH2H"
      "1111TfFc5NFFY6EsGcY6xe6vSct2hCWzk25X"))
  (testing "Sad Path: Checking sins throws"
    (are [x] (thrown? #?(:clj Throwable :cljs js/Error)
                      (secp256k1/validate-sin x))
      7
      (constantly :foo)
      :bar
      "\"\""
      "/TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
      "%Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
      "&TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
      "TfBZ3DacgxVbem&&ggEXZtHxoNXgD5FWi2cLD")))

(deftest full-test
  (testing "Can generate a private key, public key, and SIN"
    (let [{priv      :private-key
           pub       :public-key
           timestamp :created} (secp256k1/generate-address-pair)
           sin (secp256k1/get-sin-from-public-key pub)]
      #?(:cljs (is (inst? timestamp))
         :clj (is (instance? java.util.Date timestamp)))
      (is (= pub (secp256k1/public-key priv)))
      (is (= (secp256k1/x962-encode pub)
             (secp256k1/x962-encode priv)))
      (is (= sin (secp256k1/get-sin-from-public-key priv)))
      (is (secp256k1/validate-sin sin))
      (is (instance? ECPoint pub))
      (is (instance? #?(:cljs bn
                        :clj  java.math.BigInteger) priv))
      (are [x] (secp256k1/verify-signature
                pub x
                (secp256k1/sign priv x))
        "trololololol"
        "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
        "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
        "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
        "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
        "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
        "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
        "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X"))))

(comment (run-tests))
