(ns secp256k1.formatting.der-encoding-test
  (:require [clojure.test
             #?(:clj :refer
                :cljs :refer-macros)
             [is use-fixtures testing are run-tests]]
            #?(:clj [clojure.test :refer [deftest]]
               :cljs [devcards.core :refer-macros [deftest]])
            [secp256k1.formatting.der-encoding :as der-encoding]))

#?(:cljs
   (deftest integer-encoding-tests
     (testing "Can encode some known integers"
       (is (= "0220657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
              (der-encoding/encode-asn1-unsigned-integer
               "657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c")))
       (is (= "022100ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
              (der-encoding/encode-asn1-unsigned-integer
               "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e")))
       (is (= "0241049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"
              (der-encoding/encode-asn1-unsigned-integer
               "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"))))

     (testing "Can decode integers"
       (is (= {:integer "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"
               :remaining ""}
              (der-encoding/decode-asn1-integer
               "0241049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"))))

     (testing "Can encode and decode integers"
       (are [x] (= x (-> x
                         der-encoding/encode-asn1-unsigned-integer
                         der-encoding/decode-asn1-integer
                         :integer))
         "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
         "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"))))

#?(:cljs
   (deftest DER-tests
     (testing "Can encode a pair of known integers"
       (is (= "30450220657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c022100ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
              (der-encoding/DER-encode
               ["657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
                "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"])))
       (is (= "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
              (der-encoding/DER-encode
               ["45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"]))))
     (testing "Can encode and decode integers"
       (are [x] (= x (-> x der-encoding/DER-encode der-encoding/DER-decode))
         ["45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
          "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"]
         ["657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
          "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"]))))

(deftest signature-tests
  (testing "Can encode a signature"
       (is (= "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
              (der-encoding/DER-encode-ECDSA-signature
               {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"}))))
     (testing "Can decode a signature"
       (is (= {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
               :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
               :recover nil}
              (der-encoding/DER-decode-ECDSA-signature
               (der-encoding/DER-encode-ECDSA-signature
                {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                 :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"})))))
     (testing "Can decode a signature (output in base 64, input in hex)"
       (is (= {:R "RbxaujU/lzFrkplsAeum4LDLY6dj0miYpWHHSKlUXHU="
               :S "TcA3TI1MpInBYbIf9eJXFPEEbXWeya35RAIzBp1YRWc="
               :recover nil}
              (der-encoding/DER-decode-ECDSA-signature
               (der-encoding/DER-encode-ECDSA-signature
                {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                 :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"})
               :output-format :base64))))
     (testing "Can encode and decode a signature in base 64"
       (is (= {:R "RbxaujU/lzFrkplsAeum4LDLY6dj0miYpWHHSKlUXHU="
               :S "TcA3TI1MpInBYbIf9eJXFPEEbXWeya35RAIzBp1YRWc="
               :recover nil}
              (der-encoding/DER-decode-ECDSA-signature
               (der-encoding/DER-encode-ECDSA-signature
                {:R "RbxaujU/lzFrkplsAeum4LDLY6dj0miYpWHHSKlUXHU="
                 :S "TcA3TI1MpInBYbIf9eJXFPEEbXWeya35RAIzBp1YRWc="}
                :input-format :base64)
               :output-format :base64))))
     (testing "Can encode and decode a signature using base 58"
       (is (= {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
               :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
               :recover nil}
              (der-encoding/DER-decode-ECDSA-signature
               (der-encoding/DER-encode-ECDSA-signature
                {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                 :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"}
                :output-format :base58)
               :input-format :base58))))
     (testing "Can encode and decode a signature with a recovery byte"
       (is (= {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
               :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
               :recover "1b"}
              (der-encoding/DER-decode-ECDSA-signature
               (der-encoding/DER-encode-ECDSA-signature
                {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
                 :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
                 :recover "1b"}))))))
