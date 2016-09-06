// SJCL is open. You can use, modify and redistribute it under a BSD
// license or under the GNU GPL, version 2.0.
//
// ---------------------------------------------------------------------
//
// http://opensource.org/licenses/BSD-2-Clause
//
// Copyright (c) 2009-2015, Emily Stark, Mike Hamburg and Dan Boneh at
// Stanford University. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/**
 * @fileoverview Utility for converting arrays of bytes to arrays of signed 32 bit words
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.codec.bytes');
goog.require('secp256k1.sjcl.bitArray');

/**
 * Determines if something is a integer or not.
 * @param {*} n
 * @returns {boolean}
 */
function isInt(n) {
    return (n % 1 === 0);
}

/**
 * Determines if something is a byte or not.
 * @param {*} n
 * @returns {boolean}
 */
secp256k1.sjcl.codec.bytes.isByte = function (n) {
    return isInt(n) && (0 <= n) && (n <= 255);
};

/**
 * Determines if something is an array of bytes or not.
 * @param {*} data
 * @returns {boolean}
 */
secp256k1.sjcl.codec.bytes.isByteArrayLike = function(data) {
    if (typeof data === "undefined"
        || typeof (data.length) !== "number"
        || !isInt(data.length)) {
        return false;
    }
    for (var i in data) {
        if (!data.hasOwnProperty(i)) {
            continue;
        }
        if (!isInt(i) || !secp256k1.sjcl.codec.bytes.isByte(data[i])) {
            return false;
        }
    }
    return true;
};

/**
 * Convert an array of signed 32 bit words to an array of bytes.
 * @param {Array<number>} arr Signed 32 bit array of numbers to convert.
 * @return {Array<number>} A byte array with the same data as the input.
 */
secp256k1.sjcl.codec.bytes.fromBits = function (arr) {
    var bl = secp256k1.sjcl.bitArray.bitLength(arr),
        out = new Array(bl / 8), i, tmp;
    for (i = 0; i < bl / 8; i++) {
        if ((i & 3) === 0) {
            tmp = arr[i / 4];
        }
        out[i] = tmp >>> 24;
        tmp <<= 8;
    }
    return out;
};

/**
 * Convert from a byte array to an array of 32 bit words.
 * @param {Array<number>} bytes An array of bytes.
 * @return {Array<number>} An array of signed 32 bit words representing the input.
 */
secp256k1.sjcl.codec.bytes.toBits = function (bytes) {
    var out = new Array(Math.ceil(bytes.length / 4)), i, j = 0, tmp = 0;
    for (i = 0; i < bytes.length; i++) {
        tmp = tmp << 8 | bytes[i];
        if ((i & 3) === 3) {
            out[j++] = tmp;
            tmp = 0;
        }
    }
    //noinspection JSBitwiseOperatorUsage
    if (i & 3) {
        out[j] = secp256k1.sjcl.bitArray.partial(8 * (i & 3), tmp);
    }
    return out;
};
