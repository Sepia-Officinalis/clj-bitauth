{:profiles/dev
 {:dependencies [[binaryage/devtools "0.8.1"]
                 [cljsjs/react-dom-server "15.3.0-0"]
                 [cljsjs/react-dom "15.3.0-0"]
                 [cljsjs/react "15.3.0-0"]
                 [devcards "0.2.1-7"
                  :exclusions
                  [[cljsjs/react-dom-server]
                   [cljsjs/react-dom]
                   [cljsjs/react]]]
                 [doo "0.1.7"]]

  :plugins [[lein-npm "0.6.2"]
            [lein-shell "0.5.0"]
            [lein-figwheel "0.5.4-7"]
            [lein-cljsbuild "1.1.3"
             :exclusions
             [[org.apache.commons/commons-compress]
              [org.clojure/clojure]]]
            [lein-doo "0.1.7"]]

  :npm {:dependencies [[slimerjs "0.906.2"
                        phantomjs-prebuilt "2.1.12"
                        karma-cljs-test "0.1.0"
                        karma-firefox-launcher "1.0.0"
                        karma-chrome-launcher "2.0.0"
                        karma "1.2.0"]]}

  :doo {:paths {:slimer    "./node_modules/.bin/slimerjs"
                :phantom   "./node_modules/.bin/phantomjs"
                :karma     "./node_modules/.bin/karma"}
        :alias {:headless [:slimer :phantom :nashorn]
                :all      [:browsers :headless]}}

  :cljsbuild
  {:builds
   [{:id           "test"
     :source-paths ["src/cljs" "src/cljc" "src/js" "test"]
     :compiler
     {:output-to     "target/js/compiled/testable.js"
      :main          "secp256k1.tester"
      :optimizations :whitespace}}
    {:id           "test-advanced"
     :source-paths ["src/cljs" "src/cljc" "src/js" "test"]
     :compiler
     {:output-to     "target/js/compiled/testable.min.js"
      :main          "secp256k1.tester"
      :optimizations :advanced
      :pretty-print  false}}]}

  :aliases
  {"test-advanced"       ["do"
                          "clean,"
                          "test,"
                          "npm" "install,"
                          "doo" "all" "test" "once,"
                          "clean,"
                          "doo" "all" "test-advanced" "once,"]
   "advanced-test"       ["test-advanced"]
   "devcards"            ["do"
                          "clean,"
                          "figwheel,"]
   "deep-clean"          ["do"
                          "shell" "rm" "-rf" "figwheel_server.log" "node_modules,"
                          "clean"]}}

 :profiles/linux {:doo {:alias {:browsers [#_:chrome :firefox]}}}
 :profiles/osx {:doo {:alias {:browsers [:chrome :firefox :safari]}}
                :npm {:dependencies [[karma-safari-launcher "1.0.0"]]}}}
