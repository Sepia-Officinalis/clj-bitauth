(ns secp256k1.hashes-test
  (:require [secp256k1.hashes :as hashes]
            [secp256k1.formatting.base-convert
             :refer [byte-array-to-base]]
            #?(:clj  [clojure.test
                      :refer [is use-fixtures
                              testing are run-tests deftest]]
               :cljs [cljs.test
                      :refer-macros [is use-fixtures testing are]])
            #?(:cljs [devcards.core
                      :refer-macros [defcard deftest]])))


(deftest hmac-SHA256
  (testing "Returns the right result for reference HMAC-SHA256 values from wikipedia: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples"
    (is (= "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
           (-> (hashes/hmac-sha256 "" "")
               (byte-array-to-base :hex))))
    (is (= "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
           (-> (hashes/hmac-sha256
                "key"
                "The quick brown fox jumps over the lazy dog")
               (byte-array-to-base :hex))))))

(deftest sha256-test
  (is
   (= (byte-array-to-base (hashes/sha256) :hex)
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
   "Empty")
  (is
   (= (-> "ನೆಪೋಲಿಯನ್ ಬೋನಪಾರ್ತ್ (ಅಥವಾ) ನೆಪೋಲಿಯನ್ ಬೊನಪಾರ್ಟೆ"
          hashes/sha256
          (byte-array-to-base :hex))
      "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4")
   "Kannada")
  (is
   (= (-> (hashes/sha256
            "Римска република (на латински: Res Pvblica Romana) е период в развитието на древната римска цивилизация, характеризиращ се в републиканска форма на управление."
            "ജൂലിയസ് സീസർ റോമൻ രാഷ്ട്ര തന്ത്രജ്ഞനും ഭരണകർത്താവുമായിരുന്നു. റോമൻ റിപ്പബ്ലിക്കിനെ സാമ്രാജ്യമാക്കുന്നതിൽ മുഖ്യപങ്കുവഹിച്ചു.")
          (byte-array-to-base :hex))
      "7fc1e1859b91bde5be83718c484517a485c54f2b7e2bcdcd91352ff620f7cbac")
   "Bulgarian and Malayalam"))

(deftest ripemd-160-test
  (is
   (= (byte-array-to-base (hashes/ripemd-160) :hex)
      "9c1185a5c5e9fc54612808977ee8f548b2258d31")
   "Empty")
  (is
   (= (-> "ನೆಪೋಲಿಯನ್ ಬೋನಪಾರ್ತ್ (ಅಥವಾ) ನೆಪೋಲಿಯನ್ ಬೊನಪಾರ್ಟೆ"
          hashes/ripemd-160
          (byte-array-to-base :hex))
      "c3e1b617d68bfe0fbbd5eec829d5e7a274c2f175")
   "Kannada")
  (is
   (= (-> (hashes/ripemd-160
            "Римска република (на латински: Res Pvblica Romana) е период в развитието на древната римска цивилизация, характеризиращ се в републиканска форма на управление."
            "ജൂലിയസ് സീസർ റോമൻ രാഷ്ട്ര തന്ത്രജ്ഞനും ഭരണകർത്താവുമായിരുന്നു. റോമൻ റിപ്പബ്ലിക്കിനെ സാമ്രാജ്യമാക്കുന്നതിൽ മുഖ്യപങ്കുവഹിച്ചു.")
          (byte-array-to-base :hex))
      "01c88fa45381aa088197547a1144a4118cd1c522")
   "Bulgarian and Malayalam"))

(comment (run-tests))
