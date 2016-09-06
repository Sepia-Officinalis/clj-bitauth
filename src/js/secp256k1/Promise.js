/**
 * @fileoverview If native promises exist, make use of them.  Otherwise, fall back to polyfill.
 */

goog.provide('secp256k1.Promise');
goog.require('secp256k1.polyfill.Promise');

// TODO: Make sure that Safari is really using native promises in advanced compilation, because I don't believe it.

/**
 * @const
 * @type {boolean}
 */
var nativePromise = typeof window === "object" && typeof window['Promise'] === "function";

/**
 * Promise/A+ with fallback to a polyfill
 * @param {Function} fn Function to run over result when the promise is resolved
 * @constructor
 * @struct
 * @final
 */
secp256k1.Promise = nativePromise ? window['Promise'] : secp256k1.polyfill.Promise;


/**
 * @param {Array<Function|secp256k1.Promise>} arr
 * @returns {secp256k1.polyfill.Promise}
 */
secp256k1.Promise.all = nativePromise && typeof window['Promise']['all'] === "function" ?
    window['Promise']['all'] : secp256k1.polyfill.Promise.all;

/**
 * @param {*} value
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.resolve = nativePromise && typeof window['Promise']['resolve'] === "function" ?
    window['Promise']['resolve'] : secp256k1.polyfill.Promise.resolve;

/**
 * @param {*} value
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.reject = nativePromise && typeof window['Promise']['reject'] === "function" ?
    window['Promise']['reject'] : secp256k1.polyfill.Promise.reject;

/**
 * @param {Array<secp256k1.Promise>} values
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.race = nativePromise && typeof window['Promise']['race'] === "function" ?
    window['Promise']['race'] : secp256k1.polyfill.Promise.race;