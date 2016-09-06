(ns secp256k1.formatting.base-convert-test
  (:require [secp256k1.formatting.base-convert
             :refer [base-to-byte-array
                     byte-array-to-base
                     hex-to-base58
                     base58-to-hex]]
            #?(:clj  [clojure.test
                      :refer [is use-fixtures
                              testing are run-tests deftest]]
               :cljs [cljs.test
                      :refer-macros [is use-fixtures testing are]])
            #?(:cljs [devcards.core :refer-macros [deftest]]))
  #?(:cljs (:import [secp256k1.sjcl bn])))

(deftest hex-test
  (is (= "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
         (-> "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
             (base-to-byte-array :hex)
             (byte-array-to-base :hex)))
      "`byte-array-to-base` is the left inverse of `base-to-byte-array`")
  (is (empty? (base-to-byte-array "" :hex))
      "Empty string translates to empty array")
  (is (= "" (byte-array-to-base [] :hex))
      "Empty array translates to empty string")
  (is (= "deadbeef" (byte-array-to-base [0xDE 0xAD 0xBE 0xEF] :hex))
      "DEADBEEF array")
  (is (= "deadbeef" (-> []
                        (->> (cons 0xEF)
                             (cons 0xBE)
                             (cons 0xAD)
                             (cons 0xDE))
                        (byte-array-to-base  :hex)))
      "DEADBEEF array (constructed)")
  (is (thrown? #?(:clj Exception
                  :cljs js/Error)
               (base-to-byte-array
                "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
                :hex))
      "Sad path for parsing bytes from hexadecimal"))

(deftest base58-test
  (is (= "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
         (-> "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
             (base-to-byte-array :hex)
             (byte-array-to-base :base58)))
      "Can compose array conversions to convert hexadecimal to base 58")
  (is (= "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
         (hex-to-base58 "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"))
      "Can convert hexadecimal to base 58 directly")
  (is (= "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
         (-> "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
             (base-to-byte-array :base58)
             (byte-array-to-base :base58)))
      "`byte-array-to-base` is the left inverse of `base-to-byte-array`")
  (is (= "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
         (base58-to-hex "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"))
      "Special function for converting base 58 to hexadecimal")
  (is (let [input "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"]
        (= "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
           (base58-to-hex input)
           (-> input
               (base-to-byte-array :base58)
               (byte-array-to-base :hex))))
      "Direct and indirect conversion agree")
  (is (thrown?
       #?(:clj java.lang.AssertionError
          :cljs js/Error)
       (hex-to-base58 "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"))
      "Sad path for hex to base 58")
  (is (thrown?
       #?(:clj java.lang.AssertionError
          :cljs js/Error)
       (base58-to-hex "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"))
      "Sad path for converting from base 58 to hexadecimal")
  (is (thrown? #?(:clj java.lang.AssertionError
                  :cljs js/Error)
               (base-to-byte-array
                "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
                :base58))
      "Sad path for parsing bytes from base 58"))

(deftest base64-test
  (is (= "3q2+7w=="
         (byte-array-to-base [0xDE 0xAD 0xBE 0xEF] :base64))
      "deadbeef conversion")
  (is
   (= "AAAAAHGk9DrmasI1RLh0SbYLu0h00YsycOuinFwFfHgFpA=="
      (-> "AAAAAHGk9DrmasI1RLh0SbYLu0h00YsycOuinFwFfHgFpA=="
          (base-to-byte-array :base64)
          (byte-array-to-base :base64)))
   "Can convert to an array and back")
  (is (let [result "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"]
        (=
         result
         (-> result
             (base-to-byte-array :hex)
             (byte-array-to-base :base64)
             (base-to-byte-array :base64)
             (byte-array-to-base :hex))))
      "Elaborate conversion path")
  (is (thrown? #?(:clj Exception
                  :cljs js/Error)
               (base-to-byte-array
                "ගේම් ඔෆ් ත්‍රෝන්ස්"
                :base64))
      "Sad path for parsing bytes from base 64 when the input is in Sinhala"))

(deftest biginteger-test
  (is (instance?
       #?(:clj BigInteger
          :cljs bn)
       (byte-array-to-base [0xDE 0xAD 0xBE 0xEF] :biginteger)))
  (is (= "deadbeef"
         (-> 0xDEADBEEF
             (base-to-byte-array :biginteger)
             (byte-array-to-base :hex)))))

(comment (run-tests))
