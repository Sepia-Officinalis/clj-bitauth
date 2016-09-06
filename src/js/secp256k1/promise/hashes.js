/**
 * @fileoverview Asynchronous hashes via `crypto.subtle` (when available).
 *
 * This file provides an API for accessing built-in hashing functions via `crypto.subtle`
 *
 * Hashing functions return `Promise`s, either built-in or `goog.Promise` polyfills if built-in implementations
 * are not available.
 *
 * If `crypto.subtle` is not available, this code falls back on synchronous implementations of hashing functions.
 */

goog.provide('secp256k1.promise.hashes');
goog.require('goog.array');
goog.require('goog.asserts');
goog.require('goog.crypt');
goog.require('goog.crypt.Sha256');
goog.require('secp256k1.Promise');
goog.require('secp256k1.sjcl.codec.bytes');

var crypto = typeof window === "object" ?
        (typeof window['crypto'] !== "undefined" ? window['crypto'] :
            (typeof window['msCrypto'] !== "undefined" ? window['msCrypto'] : undefined)) : undefined,
    subtleCrypto = typeof crypto === "object" ?
        (typeof crypto['subtle'] === "object" ? crypto['subtle'] :
            (typeof crypto['webkitSubtle'] === "object" ? crypto['webkitSubtle'] : undefined)) : undefined;

/**
 * Take the SHA256 hash of an array of bytes or string.
 * @param {Array<number>|string} data An array of bytes (or a UTF-8 string) to be hashed.
 * @returns {secp256k1.Promise<Array<number>>} A promise containing the hashed result as an array of bytes.
 */
function unliftedSha256(data) {
    data = typeof data === "string" ? goog.crypt.stringToUtf8ByteArray(data) : data;
    if (!secp256k1.sjcl.codec.bytes.isByteArrayLike(data)) {
        return secp256k1.Promise.reject(new Error("Data must be a string or array of bytes"));
    } else if (typeof subtleCrypto !== "undefined") {
        var buffer = new ArrayBuffer(data.length);
        (new Uint8Array(buffer)).set(new Uint8Array(data));
        return subtleCrypto.digest("SHA-256", buffer).then(
            function (outputBuffer) {
                //noinspection JSCheckFunctionSignatures
                return goog.array.toArray(new Uint8Array(outputBuffer));
            });
    } else {
        var h = new goog.crypt.Sha256();
        h.update(data);
        return secp256k1.Promise.resolve(h.digest());
    }
}

/**
 * Take the SHA256 hash of an array of bytes, string, or promise of an array of bytes.
 * @param {secp256k1.Promise<Array<number>>|Array<number>|string} data An array of bytes (or a UTF-8 string) to be hashed
 * @returns {secp256k1.Promise<Array<number>>} A promise containing the hashed result as an array of bytes.
 */
secp256k1.promise.hashes.sha256 = function (data) {
    if (typeof data === "string"
        || secp256k1.sjcl.codec.bytes.isByteArrayLike(data)) {
        return unliftedSha256(data);
    } else {
        try {
            //noinspection JSUnresolvedFunction
            return data.then(unliftedSha256);
        } catch (e) {
            return secp256k1.Promise.reject(e);
        }
    }
};
