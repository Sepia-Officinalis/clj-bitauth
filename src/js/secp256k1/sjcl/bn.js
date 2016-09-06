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
 * @fileoverview Big Numbers for SJCL.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.bn');
goog.require('secp256k1.sjcl.bitArray');

/**
 * Constructs a new BigNum from another BigNum, a number or a hex string.
 * @constructor
 * @struct
 * @final
 * @param {string|number|secp256k1.sjcl.bn} it Object to initialize into a big-num
 */
secp256k1.sjcl.bn = function (it) {
    var i = 0, k;
    if ((it === null) || (it === undefined)) {
        this.limbs = [0];
    } else if (typeof it === "number") {
        this.limbs = [it];
        //noinspection JSUnresolvedFunction
        this.normalize();
    } else if (typeof it === "string") {
        it = it.replace(/^0x/, '');
        this.limbs = [];
        // hack
        k = secp256k1.sjcl.bn.radix / 4;
        for (i = 0; i < it.length; i += k) {
            this.limbs.push(parseInt(it.substring(Math.max(it.length - i - k, 0), it.length - i), 16));
        }
    } else if (it instanceof secp256k1.sjcl.bn) {
      this.limbs = it.limbs.slice(0);
    } else {
        throw new Error("Could not construct bn from argument");
    }
};

/**
 * The maximum number of multiplications that can be performed before propagating carries
 * @const
 * @type {number}
 */
secp256k1.sjcl.bn.maxMul = 8;

/**
 * Radix class constant.
 * @const
 * @type {number}
 */
secp256k1.sjcl.bn.radix = 24;

/**
 * Radix Mask class constant.
 * @const
 * @type {number}
 */
secp256k1.sjcl.bn.radixMask = (1 << secp256k1.sjcl.bn.radix) - 1;

/**
 * Place value class constant.
 * @const
 * @type {number}
 */
secp256k1.sjcl.bn.placeVal = Math.pow(2, secp256k1.sjcl.bn.radix);

/**
 * IPV class constant.
 * @const
 * @type {number}
 */
secp256k1.sjcl.bn.ipv = 1 / secp256k1.sjcl.bn.placeVal;


/**
 * this ^ n.  Uses square-and-multiply.  Normalizes.
 * @param {string|number|secp256k1.sjcl.bn} n Exponent to raise to
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.pow = function (n) {
    var l = new secp256k1.sjcl.bn(n).normalize().trim().limbs;
    var i, j, out = new secp256k1.sjcl.bn(1), pow = this;

    for (i = 0; i < l.length; i++) {
        for (j = 0; j < secp256k1.sjcl.bn.radix; j++) {
            //noinspection JSBitwiseOperatorUsage
            if (l[i] & (1 << j)) {
                out = out.multiply(pow);
            }
            if (i == (l.length - 1) && l[i] >> (j + 1) == 0) {
                break;
            }

            pow = pow.square();
        }
    }

    return out;
};

//noinspection JSUnusedGlobalSymbols
/**
 * this ^ x mod N
 * @param {string|number|secp256k1.sjcl.bn} x Exponent to raise to
 * @param {string|number|secp256k1.sjcl.bn} N Modulus
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.modPow= function (x, N) {
    x = new secp256k1.sjcl.bn(x);
    N = new secp256k1.sjcl.bn(N);

    // Jump to montgomeryModPow if possible.
    if ((N.limbs[0] & 1) == 1) {
        var montOut = this.montgomeryModPow(x, N);

        if (montOut != false) {
            return montOut;
        } // else go to slow modPow
    }

    var i, j, l = x.normalize().trim().limbs, out = new secp256k1.sjcl.bn(1), pow = this;

    for (i = 0; i < l.length; i++) {
        for (j = 0; j < secp256k1.sjcl.bn.radix; j++) {
            //noinspection JSBitwiseOperatorUsage
            if (l[i] & (1 << j)) {
                out = out.multiply(pow).mod(N);
            }
            if (i == (l.length - 1) && l[i] >> (j + 1) == 0) {
                break;
            }

            pow = pow.multiply(pow).mod(N);
        }
    }

    return out;
};

/**
 * this ^ x mod N with Montgomery reduction
 * @param {string|number|secp256k1.sjcl.bn} x Exponent to raise to
 * @param {string|number|secp256k1.sjcl.bn} N Modulus
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.montgomeryModPow = function (x, N) {
    x = new secp256k1.sjcl.bn(x).normalize().trim();
    N = new secp256k1.sjcl.bn(N);

    var i, j,
        radix = secp256k1.sjcl.bn.radix,
        out = new secp256k1.sjcl.bn(1),
        pow = this.copy();

    // Generate R as a cap of N.
    var R, s, wind, bitsize = x.bitLength();

    R = N.copy().normalize().trim();
    for (i = 0 ; i < R.limbs.length ; i++) {
        R.limbs[i] = 0;
    }

    for (s = secp256k1.sjcl.bn.radix; s > 0; s--) {
        if (((N.limbs[N.limbs.length - 1] >> s) & 1) == 1) {
            R.limbs[R.limbs.length - 1] = 1 << s;
            break;
        }
    }

    // Calculate window size as a function of the exponent's size.
    if (bitsize == 0) {
        return this;
    } else if (bitsize < 18) {
        wind = 1;
    } else if (bitsize < 48) {
        wind = 3;
    } else if (bitsize < 144) {
        wind = 4;
    } else if (bitsize < 768) {
        wind = 5;
    } else {
        wind = 6;
    }

    // Find R' and N' such that R * R' - N * N' = 1.
    var RR = R.copy(), NN = N.copy(), RP = new secp256k1.sjcl.bn(1), NP = new secp256k1.sjcl.bn(0), RT = R.copy();

    while (RT.greaterEquals(1)) {
        RT.halveM();

        if ((RP.limbs[0] & 1) == 0) {
            RP.halveM();
            NP.halveM();
        } else {
            RP.addM(NN);
            RP.halveM();

            NP.halveM();
            NP.addM(RR);
        }
    }

    RP = RP.normalize();
    NP = NP.normalize();

    RR.doubleM();
    var R2 = RR.square().mod(N);


    if (!RR.multiply(RP).sub(N.multiply(NP)).equals(1)) {
        throw new Error("Cannot perform Montgomery reduction on this modulus.");
    }

    var montIn = function (c) {
            return montMul(c, R2);
        },
        montMul = function (a, b) {
            // Standard Montgomery reduction
            var k, ab, right, abBar, mask = (1 << (s + 1)) - 1;
            ab = a.multiply(b);

            right = ab.multiply(NP);
            right.limbs = right.limbs.slice(0, R.limbs.length);

            if (right.limbs.length == R.limbs.length) {
                right.limbs[R.limbs.length - 1] &= mask;
            }

            right = right.multiply(N);

            abBar = ab.add(right).normalize().trim();
            abBar.limbs = abBar.limbs.slice(R.limbs.length - 1);

            // Division.  Equivelent to calling *.halveM() s times.
            for (k = 0; k < abBar.limbs.length; k++) {
                if (k > 0) {
                    abBar.limbs[k - 1] |= (abBar.limbs[k] & mask) << (radix - s - 1);
                }

                abBar.limbs[k] = abBar.limbs[k] >> (s + 1);
            }

            if (abBar.greaterEquals(N)) {
                abBar.subM(N);
            }

            return abBar;
        },
        montOut = function (c) {
            return montMul(c, 1);
        };

    pow = montIn(pow);
    out = montIn(out);

    // Sliding-Window Exponentiation (HAC 14.85)
    var h, precomp = {}, cap = (1 << (wind - 1)) - 1;

    precomp[1] = pow.copy();
    precomp[2] = montMul(pow, pow);

    for (h = 1; h <= cap; h++) {
        precomp[(2 * h) + 1] = montMul(precomp[(2 * h) - 1], precomp[2]);
    }

    var getBit = function (exp, i) { // Gets ith bit of exp.
        var off = i % secp256k1.sjcl.bn.radix;

        return (exp.limbs[Math.floor(i / secp256k1.sjcl.bn.radix)] & (1 << off)) >> off;
    };

    for (i = x.bitLength() - 1; i >= 0;) {
        if (getBit(x, i) == 0) {
            // If the next bit is zero:
            //   Square, move forward one bit.
            out = montMul(out, out);
            i = i - 1;
        } else {
            // If the next bit is one:
            //   Find the longest sequence of bits after this one, less than `wind`
            //   bits long, that ends with a 1.  Convert the sequence into an
            //   integer and look up the pre-computed value to add.
            var l = i - wind + 1;

            while (getBit(x, l) == 0) {
                l++;
            }

            var indx = 0;
            for (j = l; j <= i; j++) {
                indx += getBit(x, j) << (j - l);
                out = montMul(out, out);
            }

            out = montMul(out, precomp[indx]);

            i = l - 1;
        }
    }

    return montOut(out);
};

/**
 * Normalize a bn by propogating its carries.
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.normalize = function () {
    var carry = 0, i,
        pv = secp256k1.sjcl.bn.placeVal,
        ipv = secp256k1.sjcl.bn.ipv, l, m,
        limbs = this.limbs,
        ll = limbs.length,
        mask = secp256k1.sjcl.bn.radixMask;
    for (i = 0; i < ll || (carry !== 0 && carry !== -1); i++) {
        l = (limbs[i] || 0) + carry;
        m = limbs[i] = l & mask;
        carry = (l - m) * ipv;
    }
    if (carry === -1) {
        limbs[i - 1] -= pv;
    }
    this.trim();
    return this;
};

/**
 * Serialize to a bit array
 * @param {number=} length Optional length to specify (defaults to the bitLength of this object)
 * @returns {Array<number>}
 */
secp256k1.sjcl.bn.prototype.toBits = function (length) {
    this.normalize();
    var len = length ? length : this.bitLength();
    var i = Math.floor((len - 1) / 24), w = secp256k1.sjcl.bitArray,
        e = (len + 7 & -8) % secp256k1.sjcl.bn.radix || secp256k1.sjcl.bn.radix,
        out = [w.partial(e, this.getLimb(i))];
    for (i--; i >= 0; i--) {
        out = w.concat(out, [w.partial(Math.min(secp256k1.sjcl.bn.radix, len), this.getLimb(i))]);
        len -= secp256k1.sjcl.bn.radix;
    }
    return out;
};

/**
 * Trim 0s in the limbs of a BigNum
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.trim = function () {
    var l = this.limbs, p;
    do {
        p = l.pop();
    } while (l.length && p === 0);
    l.push(p);
    return this;
};

/**
 * Return the length in bits, rounded up to the nearest byte.
 * @returns {!number}
 */
secp256k1.sjcl.bn.prototype.bitLength = function () {
    this.normalize();
    var out = secp256k1.sjcl.bn.radix * (this.limbs.length - 1),
        b = this.limbs[this.limbs.length - 1];
    for (; b; b >>>= 1) {
        out++;
    }
    return out + 7 & -8;
};

/**
 * Return inverse mod prime p.  p must be odd. Uses the binary extended Euclidean algorithm.
 * @param {string|number|secp256k1.sjcl.bn} p A prime to take the modular multiplicative inverse by.
 * @returns {secp256k1.sjcl.bn} The multiplicative inverse of this big-num modulo the specified prime.
 */
secp256k1.sjcl.bn.prototype.modInverse = function (p) {
    var a = secp256k1.sjcl.bn.ONE.copy(),
        b = secp256k1.sjcl.bn.ZERO.copy(),
        x = this.copy(),
        y = new secp256k1.sjcl.bn(p),
        tmp, i, nz = 1;

    //noinspection JSBitwiseOperatorUsage
    if (!(y.limbs[0] & 1)) {
        throw new Error("modInverse: modulus must be odd");
    }

    // Invariant: y is odd
    do {
        //noinspection JSBitwiseOperatorUsage
        if (x.limbs[0] & 1) {
            if (!x.greaterEquals(y)) {
                // x < y; swap everything
                tmp = x;
                //noinspection JSSuspiciousNameCombination
                x = y;
                y = tmp;
                tmp = a;
                a = b;
                b = tmp;
            }
            x.subM(y);
            x.normalize();

            if (!a.greaterEquals(b)) {
                a.addM(p);
            }
            a.subM(b);
        }

        // cut everything in half
        x.halveM();
        //noinspection JSBitwiseOperatorUsage
        if (a.limbs[0] & 1) {
            a.addM(p);
        }
        a.normalize();
        a.halveM();

        // check for termination: x ?= 0
        for (i = nz = 0; i < x.limbs.length; i++) {
            nz |= x.limbs[i];
        }
    } while (nz);

    if (!y.equals(1)) {
        throw (new Error("modInverse: modulus and argument must be relatively prime"));
    }

    return b;
};

/**
 * this + that.  Does not normalize.
 * @param {string|number|secp256k1.sjcl.bn} that
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.add = function (that) {
    return this.copy().addM(that);
};

/**
 * this - that.  Does not normalize.
 * @param {string|number|secp256k1.sjcl.bn} that
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.sub = function (that) {
    return this.copy().subM(that);
};

/**
 * this * that. Normalizes.
 * @param {string|number|secp256k1.sjcl.bn} that
 * @returns {!secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.multiply = function (that) {
    if (!(that instanceof secp256k1.sjcl.bn)) {
        that = new secp256k1.sjcl.bn(that);
    }
    var i, j,
        a = this.limbs,
        b = that.limbs,
        al = a.length,
        bl = b.length,
        out = new secp256k1.sjcl.bn(null),
        c = out.limbs, ai,
        ii = secp256k1.sjcl.bn.maxMul;

    for (i = 0; i < this.limbs.length + that.limbs.length + 1; i++) {
        c[i] = 0;
    }
    for (i = 0; i < al; i++) {
        ai = a[i];
        for (j = 0; j < bl; j++) {
            c[i + j] += ai * b[j];
        }

        if (!--ii) {
            ii = secp256k1.sjcl.bn.maxMul;
            out.cnormalize();
        }
    }
    return out.cnormalize();
};

/** this ^ 2.  Normalizes and reduces. */
secp256k1.sjcl.bn.prototype.square = function () {
    return this.multiply(this);
};

/**
 * this += that.  Does not normalize.
 * @param {string|number|secp256k1.sjcl.bn} that
 * @returns {secp256k1.sjcl.bn} This value added to the other
 */
secp256k1.sjcl.bn.prototype.addM = function (that) {
    if (!(that instanceof secp256k1.sjcl.bn)) {
        that = new secp256k1.sjcl.bn(that);
    }
    var i, l = this.limbs, ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
        l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
        l[i] += ll[i];
    }
    return this;
};

/**
 * Double this value in place, does not require normalized
 * @returns {secp256k1.sjcl.bn} This value, doubled
 */
secp256k1.sjcl.bn.prototype.doubleM = function () {
    var i, carry = 0,
        tmp,
        r = secp256k1.sjcl.bn.radix,
        m = secp256k1.sjcl.bn.radixMask,
        l = this.limbs;
    for (i = 0; i < l.length; i++) {
        tmp = l[i];
        tmp = tmp + tmp + carry;
        l[i] = tmp & m;
        carry = tmp >> r;
    }
    if (carry) {
        l.push(carry);
    }
    return this;
};

/**
 * this /= 2, rounded down.  Requires normalized; ends up normalized.
 * @returns {secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.halveM = function () {
    var i, carry = 0, tmp,
        r = secp256k1.sjcl.bn.radix,
        l = this.limbs;
    for (i = l.length - 1; i >= 0; i--) {
        tmp = l[i];
        l[i] = (tmp + carry) >> 1;
        carry = (tmp & 1) << r;
    }
    if (!l[l.length - 1]) {
        l.pop();
    }
    return this;
};

/**
 * this -= that.  Does not normalize.
 * @param {string|number|secp256k1.sjcl.bn} that Value to subtract
 * @returns {secp256k1.sjcl.bn} This updated value
 */
secp256k1.sjcl.bn.prototype.subM = function (that) {
    if (typeof(that) !== "object") {
        that = new secp256k1.sjcl.bn(that);
    }
    var i, l = this.limbs, ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
        l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
        l[i] -= ll[i];
    }
    return this;
};

/**
 * Compute the remainder of this value divided by another.
 * @param {string|number|secp256k1.sjcl.bn} that Value to divide through.
 * @returns {secp256k1.sjcl.bn} The remainder (modulus)
 */
secp256k1.sjcl.bn.prototype.mod = function (that) {
    var neg = !this.greaterEquals(new secp256k1.sjcl.bn(0));
    var modulus = new secp256k1.sjcl.bn(that).normalize(); // copy before we begin
    var out = new secp256k1.sjcl.bn(this).normalize(), ci = 0;

    if (neg) out = (new secp256k1.sjcl.bn(0)).subM(out).normalize();

    for (; out.greaterEquals(modulus); ci++) {
        modulus.doubleM();
    }

    if (neg) out = modulus.sub(out).normalize();

    for (; ci > 0; ci--) {
        modulus.halveM();
        if (out.greaterEquals(modulus)) {
            out.subM(modulus).normalize();
        }
    }
    return out.trim();
};

/**
 * Make a copy of this BigNum.
 * @returns {!secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.prototype.copy = function () {
    return new secp256k1.sjcl.bn(this);
};

/**
 * Returns true if "this" and "that" are equal.  Calls normalize().
 * @param {string|number|secp256k1.sjcl.bn} that Thing to compare to
 * @param {boolean=} normalize Whether to normalize, defaults to true
 * @returns {!boolean} Whether the values are equal.
 */
secp256k1.sjcl.bn.prototype.equals = function (that, normalize) {
    var normalize_ = typeof normalize === 'boolean' ? normalize : true;
    if (!(that instanceof secp256k1.sjcl.bn)) {
        that = new secp256k1.sjcl.bn(that);
    } else if (normalize_) {
        that.normalize();
    }
    if (normalize_) {
        this.normalize();
    }
    var i;
    for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
        if ((this.getLimb(i) ^ that.getLimb(i)) !== 0) {
            return false;
        }
    }
    return true;
};

/**
 * Get the ith limb of this, zero if i is too large.
 * @param {number} i Index of the limb to get
 * @returns {!number} The value of the limb or zero if it does not exist.
 */
secp256k1.sjcl.bn.prototype.getLimb = function (i) {
    return (i >= this.limbs.length) ? 0 : this.limbs[i];
};

/**
 * Constant time comparison function.
 * Returns true if this >= that, or false otherwise.
 * @param {string|number|secp256k1.sjcl.bn} that Value to compare to
 * @returns {!boolean} Whether this is greater than the argument
 */
secp256k1.sjcl.bn.prototype.greaterEquals = function (that) {
    if (!(that instanceof secp256k1.sjcl.bn)) {
        that = new secp256k1.sjcl.bn(that);
    }
    var less = 0, greater = 0, i, a, b;
    i = Math.max(this.limbs.length, that.limbs.length) - 1;
    for (; i >= 0; i--) {
        a = this.getLimb(i);
        b = that.getLimb(i);
        greater |= (b - a) & ~less;
        less |= (a - b) & ~greater;
    }
    return ((greater | ~less) >>> 31) !== 0;
};

/**
 * Constant time normalize.
 * @returns {!secp256k1.sjcl.bn} Normalized value
 */
secp256k1.sjcl.bn.prototype.cnormalize = function () {
    var carry = 0, i,
        ipv = secp256k1.sjcl.bn.ipv, l, m,
        limbs = this.limbs,
        ll = limbs.length,
        mask = secp256k1.sjcl.bn.radixMask;
    for (i = 0; i < ll - 1; i++) {
        l = limbs[i] + carry;
        m = limbs[i] = l & mask;
        carry = (l - m) * ipv;
    }
    limbs[i] += carry;
    return this;
};

/**
 * Convert to a hex string.
 * @return {string} A hexadecimal representing this number.
 */
secp256k1.sjcl.bn.prototype.toString = function () {
    this.normalize();
    var out = "", i, s, l = this.limbs;
    for (i = 0; i < this.limbs.length; i++) {
        s = l[i].toString(16);
        while (i < this.limbs.length - 1 && s.length < 6) {
            s = "0" + s;
        }
        out = s + out;
    }
    return "0x" + out;
};

/**
 * The constant ONE
 * @const
 * @type {!secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.ONE = new secp256k1.sjcl.bn(1);

/**
 * The constant ZERO
 * @const
 * @type {!secp256k1.sjcl.bn}
 */
secp256k1.sjcl.bn.ZERO = new secp256k1.sjcl.bn(0);

/**
 * Coerce an array of 32 bit words into a BigNum
 * @param {Array<number>} bits An array of 32 bit words
 * @returns {!secp256k1.sjcl.bn} BigNum representing input
 */
secp256k1.sjcl.bn.fromBits = function (bits) {
    var out = new secp256k1.sjcl.bn(null),
        words = [],
        w = secp256k1.sjcl.bitArray,
        radix = secp256k1.sjcl.bn.radix,
        l = Math.min(0x100000000, w.bitLength(bits)), e = l % radix || radix;

    words[0] = w.extract(bits, 0, e);
    for (; e < l; e += radix) {
        words.unshift(w.extract(bits, e, radix));
    }

    out.limbs = words;
    return out;
};

