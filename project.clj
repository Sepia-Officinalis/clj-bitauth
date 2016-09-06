(defproject secp256k1 "1.0.3"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure(Script) implementation of ECDSA with the secp256k1 elliptic curve"
  :url "https://github.com/Sepia-Officinalis/secp256k1"
  :min-lein-version "2.3.4"
  :jar-exclusions [#"\.DS_Store"]
  :source-paths ["src/clj" "src/cljs" "src/cljc" "src/js"]
  :test-paths ["test"]
  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.55"]
                 [org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.9.229"]]


  :clean-targets ^{:protect false}
  [:target-path
   "dev-resources/public/js/compiled/"
   "out/"]

  ;; See profiles.clj for more details
  :profiles {:dev [~(if (= (System/getProperty "os.name") "Mac OS X")
                      :profiles/osx
                      :profiles/linux)
                   :profiles/dev]}

  ;; figwheel and devcards need this here
  :cljsbuild
  {:builds
   [{:id "devcards"
     :source-paths ["src/cljs" "src/cljc" "src/js" "test"]
     :figwheel {:devcards true}
     :compiler
     {:main       secp256k1.tester
      :preloads   [devtools.preload]
      :asset-path "js/compiled/devcards_out"
      :output-to "dev-resources/public/js/compiled/secp256k1_devcards.js"
      :output-dir "dev-resources/public/js/compiled/devcards_out"
      :source-map-timestamp true}}]}

  :scm
  {:name "git"
   :url "https://github.com/Sepia-Officinalis/secp256k1.git"}

  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]])
