# BitAuth (in Clojure/ClojureScript)

[![Clojars Project](http://clojars.org/bitauth/latest-version.svg)](http://clojars.org/bitauth)

This is a Clojure/ClojureScript port of BitPay's bitauth protocol: https://github.com/bitpay/bitauth

The goals of this project are as follows:

✅ Provide a 100% API compatible Clojure implementation of BitPay's BitAuth <br/>
✅ Wrap BitPay's BitAuth [npm module](https://www.npmjs.com/package/bitauth) in ClojureScript (well, their derived browser bundle anyway), replete isomorphic Clojure/ClojureScript compatibility testing <br/>
✅ Provide [compojure](https://github.com/weavejester/compojure) middleware for checking BitAuth headers <br/>

## Installation

Simply include in your `project.clj` file:

```clj
:dependencies [[bitauth "0.0.2"]]
```

(or whatever is the latest version according to clojars...)

# Testing

Clojure:

```bash
lein test bitauth.core-test bitauth.middleware-test
```

ClojureScript:

```bash
# test once
lein cljsbuild test

# test continuously
lein cljsbuild auto
```

# Deploying

```bash
lein deploy clojars
```
