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
// met=
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
 * @fileoverview (PseudoMersenne) Prime fields and prime field reduction.
 *
 * The purpose of this is to provide fast routines for calculating remainders (is, moduli)
 * for specified primes commonly used in cryptography.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.bn.prime');
goog.require('secp256k1.sjcl.bn.prime.Field');
goog.require('secp256k1.sjcl.bn');

/**
 * Approximate in-place reduction modulo a prime field.
 * May leave a number which is negative or slightly larger than p.
 * @param {!secp256k1.sjcl.bn.prime.Field} field The field to reduce by
 * @param {!secp256k1.sjcl.bn} x Number to be reduced
 * @returns {!secp256k1.sjcl.bn} Argument updated in place
 */
secp256k1.sjcl.bn.prime.reduce = function (x, field) {
    var i, k, l, ll;
    if (secp256k1.sjcl.bn.ZERO.greaterEquals(x)) {
        x.addM(field.modulus);
    }
    i = field.minOffset;
    while (x.limbs.length > field.modOffset) {
        l = x.limbs.pop();
        ll = x.limbs.length;
        for (k = 0; k < field.offset.length; k++) {
            x.limbs[ll + field.offset[k]] -= field.factor[k] * l;
        }

        i--;
        if (!i) {
            x.limbs.push(0);
            x.cnormalize();
            i = field.minOffset;
        }
    }
    x.cnormalize();
    return x;
};

/**
 * Mostly constant-time, very expensive full reduction mod p (in place).
 * @param {!secp256k1.sjcl.bn} x BigNum to reduce mod p
 * @param {!secp256k1.sjcl.bn.prime.Field} p The field to reduce by
 * @return {secp256k1.sjcl.bn} Reduced value
 */
secp256k1.sjcl.bn.prime.fullReduce = function (x, p) {
    var greater, i, reduce = (p.fullMask === -1) ?
        secp256k1.sjcl.bn.prime.reduce :
        function (x) {
            secp256k1.sjcl.bn.prime.reduce(x, p);
            var limbs = x.limbs, i = limbs.length - 1, k, l;

            if (i === p.modOffset - 1) {
                l = limbs[i] & p.fullMask;
                limbs[i] -= l;
                for (k = 0; k < p.fullOffset.length; k++) {
                    limbs[i + p.fullOffset[k]] -= p.fullFactor[k] * l;
                }
                x.normalize();
            }
        };

    // massively above the modulus, may be negative
    reduce(x);

    // less than twice the modulus, may be negative
    x.addM(p.modulus);
    x.addM(p.modulus);
    x.normalize();

    // probably 2-3x the modulus

    reduce(x);

    // less than the power of 2.  still may be more than
    // the modulus

    // HACK: pad out to this length
    for (i = x.limbs.length; i < p.modOffset; i++) {
        x.limbs[i] = 0;
    }

    // constant-time subtract modulus
    greater = x.greaterEquals(p.modulus) ? 1 : 0;
    for (i = 0; i < x.limbs.length; i++) {
        x.limbs[i] -= p.modulus.limbs[i] * greater;
    }
    x.cnormalize();

    return x;
};

// Various field definitions

/**
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p127 =
    new secp256k1.sjcl.bn.prime.Field(127,
        [[0, -1]]);


/**
 * Bernstein's prime for Curve25519
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p25519 =
    new secp256k1.sjcl.bn.prime.Field(255,
        [[0, -19]]);

/**
 * Koblitz prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p192k =
    new secp256k1.sjcl.bn.prime.Field(192,
        [[32, -1], [12, -1], [8, -1], [7, -1], [6, -1], [3, -1], [0, -1]]);

/**
 * Koblitz prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p224k =
    new secp256k1.sjcl.bn.prime.Field(224,
        [[32, -1], [12, -1], [11, -1], [9, -1], [7, -1], [4, -1], [1, -1], [0, -1]]);

/**
 * Koblitz prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p256k =
    new secp256k1.sjcl.bn.prime.Field(256,
        [[32, -1], [9, -1], [8, -1], [7, -1], [6, -1], [4, -1], [0, -1]]);

/**
 * NIST prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p192 =
    new secp256k1.sjcl.bn.prime.Field(192,
        [[0, -1], [64, -1]]);

/**
 * NIST prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p224 =
    new secp256k1.sjcl.bn.prime.Field(224,
        [[0, 1], [96, -1]]);

/**
 * NIST prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p256 =
    new secp256k1.sjcl.bn.prime.Field(256,
        [[0, -1], [96, 1], [192, 1], [224, -1]]);

/**
 * NIST prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p384 =
    new secp256k1.sjcl.bn.prime.Field(384,
        [[0, -1], [32, 1], [96, -1], [128, -1]]);

/**
 * NIST prime
 * @type {!secp256k1.sjcl.bn.prime.Field}
 * @final
 */
secp256k1.sjcl.bn.prime.p521 =
    new secp256k1.sjcl.bn.prime.Field(521,
        [[0, -1]]);