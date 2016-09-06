/**
 * @fileoverview Asynchronous BitCoin addresses via `crypto.subtle`
 */

goog.provide('secp256k1.promise.addresses');
goog.require('goog.asserts');
goog.require('goog.math.Integer');
goog.require('secp256k1.Promise');
goog.require('secp256k1.promise.hashes');
goog.require('secp256k1.sjcl.bn');
goog.require('secp256k1.sjcl.codec.bytes');
goog.require('secp256k1.sjcl.codec.hex');
goog.require('secp256k1.sjcl.ecc.ECPoint');
goog.require('secp256k1.sjcl.hash.Ripemd160');

// TODO: Handle byte arrays, async
/**
 * Compute the BitCoin address for an elliptic curve point as an array of bytes.
 * @param {!secp256k1.sjcl.ecc.ECPoint} publicKey Public Key to convert to a BitCoin address
 * @param {number=} version A byte indicating the version
 * @returns {!secp256k1.Promise<Array<number>>} A promise containing the BitCoin address as an array of bytes
 */
secp256k1.promise.addresses.bitcoinAddressBytes = function (publicKey, version) {
    if (typeof version === "undefined") {
        version = 0x00;
    }
    if (!secp256k1.sjcl.codec.bytes.isByte(version)) {
        return secp256k1.Promise.reject(new Error("Specified version must be a byte"));
    } else if (!(publicKey instanceof secp256k1.sjcl.ecc.ECPoint)) {
        return secp256k1.Promise.reject(new Error("Argument must be a public key"));
    } else {
        return secp256k1.promise.hashes.sha256([0x04].concat(
            secp256k1.sjcl.codec.bytes.fromBits(
                publicKey.x.toBits(publicKey.curve.field.exponent).concat(
                    publicKey.y.toBits(publicKey.curve.field.exponent)))))
            .then(function (data) {
                var h = new secp256k1.sjcl.hash.Ripemd160();
                h.update(data);
                return h.digest();
            }).then(function (hash) {
                hash.unshift(version);
                return secp256k1.promise.hashes.sha256(
                    secp256k1.promise.hashes.sha256(hash))
                    .then(function (checksum_data) {
                        return hash.concat(checksum_data.slice(0, 4));
                    })
            });
    }
};

/**
 * @const
 * @type {!goog.math.Integer}
 */
var fiftyEight = goog.math.Integer.fromInt(58);

/**
 * @const
 * @type {!string}
 */
var baseFiftyEightChars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Convert a byte array into a Base 58 encoded string.
 * @param {!Array<number>} data
 * @returns {!string}
 */
function bytesToBase58(data) {
    var out = [];
    var zeros = -1;
    while (data[++zeros] === 0) {
    }
    var n = goog.math.Integer.fromString(
        secp256k1.sjcl.codec.hex.fromBits(
            secp256k1.sjcl.codec.bytes.toBits(data)), 16);
    while (!n.isZero()) {
        out.unshift(baseFiftyEightChars[n.modulo(fiftyEight).toInt()]);
        n = n.divide(fiftyEight);
    }
    while (zeros-- != 0) {
        out.unshift(baseFiftyEightChars[0]);
    }
    return out.join("");
}

// TODO: Support multiple output formats, handle async
/**
 * Compute the BitCoin address for an elliptic curve point as a Base58 encoded string.
 * @param {!secp256k1.sjcl.ecc.ECPoint} publicKey Public key to convert to a BitCoin address
 * @param {number=} version A byte indicating the version
 * @returns {Promise<String>} A promise containing the BitCoin address as an array of bytes
 */
secp256k1.promise.addresses.bitcoinAddress = function (publicKey, version) {
    if (typeof version === "undefined") {
        version = 0x00;
    }
    return secp256k1.promise.addresses.bitcoinAddressBytes(publicKey, version).then(bytesToBase58);
};

// TODO: Support multiple input formats, handle async
/**
 * Verify the checksum on of a BitCoin address, taken as an array of bytes.
 * @param {!Array<number>} data BitCoin address to check, as an array of bytes
 * @returns {!Promise<boolean>} Whether the address was valid or not
 */
secp256k1.promise.addresses.verifyBitcoinAddressBytes = function (data) {
    if (!secp256k1.sjcl.codec.bytes.isByteArrayLike(data)) {
        return secp256k1.Promise.reject(new Error("Data must be byte array-like"));
    }
    var expectedChecksum = data.slice(-4);
    return secp256k1.promise.hashes.sha256(data.slice(0, -4))
        .then(secp256k1.promise.hashes.sha256)
        .then(function (checksum_data) {
            var actualChecksum = checksum_data.slice(0, 4);
            for (var i = 0; i < 4; ++i) {
                if (expectedChecksum[i] != actualChecksum[i]) {
                    return false;
                }
            }
            return true;
        });
};

/**
 * @const
 * @type {!secp256k1.sjcl.bn}
 */
var fiftyEightBN = new secp256k1.sjcl.bn(58);

/**
 * Convert a Base 58 encoded string to an array of bytes.
 * @param {!string} data
 * @returns {!Array<number>}
 */
function base58ToByteArray(data) {
    var zeros = -1;
    while (data[++zeros] === baseFiftyEightChars[0]) {
    }
    var n = secp256k1.sjcl.bn.ZERO;
    for (var i = zeros; i < data.length; ++i) {
        n = n.multiply(fiftyEightBN).addM(baseFiftyEightChars.indexOf(data[i]));
    }
    var out = secp256k1.sjcl.codec.bytes.fromBits(n.toBits());
    while (zeros-- != 0) {
        out.unshift(0);
    }
    return out;
}

// TODO: Handle async, multiple input formats
/**
 * Verify the checksum on of a BitCoin address, taken as a string.
 * @param {!string} data BitCoin address to check, as an array of bytes
 * @returns {!Promise<boolean>} Whether the address was valid or not
 */
secp256k1.promise.addresses.verifyBitcoinAddress = function (data) {
    var input = base58ToByteArray(data);
    return secp256k1.promise.addresses.verifyBitcoinAddressBytes(input);
};