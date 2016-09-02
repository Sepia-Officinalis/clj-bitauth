// Copyright (c) 2014 Taylor Hakes
// Copyright (c) 2014 Forbes Lindesay
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

goog.provide('secp256k1.Promise');

/**
 * Use polyfill for setImmediate for performance gains
 * @param {Function} fn
 */
var _immediateFn = typeof setImmediate === 'function' ? setImmediate : function (fn) {
    setTimeout(fn, 0);
};

/**
 * @param err
 */
function _unhandledRejectionFn(err) {
    if (typeof console !== 'undefined' && typeof console.warn === 'function') {
        console.warn('Possible Unhandled Promise Rejection:', err); // eslint-disable-line no-console
    }
}

function noop() {}

/**
 * Polyfill for Function.prototype.bind
 * @param {Function} fn
 * @param {*} thisArg
 * @returns {Function}
 * @private
 */
function bind(fn, thisArg) {
    return function () {
        fn.apply(thisArg, arguments);
    };
}

/**
 * A simple ES6 Promise polyfill
 * @param {Function} fn Function to run over result when the promise is resolved
 * @constructor
 * @struct
 * @final
 */
secp256k1.Promise = function (fn) {
    if (typeof this !== 'object') throw new TypeError('Promises must be constructed via new');
    if (typeof fn !== 'function') throw new TypeError('Not a function');

    /**
     * @type {number}
     * @public
     */
    this._state = 0;

    /**
     * @type {boolean}
     * @public
     */
    this._handled = false;

    /**
     * @type {*}
     * @public
     */
    this._value = undefined;

    /**
     * @type {Array}
     * @public
     */
    this._deferreds = [];

    doResolve(fn, this);
};



/**
 * @param {secp256k1.Promise} promise
 * @param {Function=} onFulfilled
 * @param {Function=} onRejected
 * @private
 * @constructor
 * @struct
 * @final
 */
function Handler(promise, onFulfilled, onRejected) {
    this.onFulfilled = typeof onFulfilled === 'function' ? onFulfilled : null;
    this.onRejected = typeof onRejected === 'function' ? onRejected : null;
    this.promise = promise;
}

/**
 * @param {secp256k1.Promise} self
 * @param {Handler} deferred
 * @private
 */
function handle(self, deferred) {
    while (self._state === 3) {
        self = self._value;
    }
    if (self._state === 0) {
        self._deferreds.push(deferred);
        return;
    }
    self._handled = true;
    _immediateFn(function () {
        var cb = self._state === 1 ? deferred.onFulfilled : deferred.onRejected;
        if (cb === null) {
            (self._state === 1 ? resolve : reject)(deferred.promise, self._value);
            return;
        }
        var ret;
        try {
            ret = cb(self._value);
        } catch (e) {
            reject(deferred.promise, e);
            return;
        }
        resolve(deferred.promise, ret);
    });
}

/**
 * @param {secp256k1.Promise} self
 * @param {*} newValue
 * @private
 */
function resolve(self, newValue) {
    try {
        // Promise Resolution Procedure: https://github.com/promises-aplus/promises-spec#the-promise-resolution-procedure
        if (newValue === self) { //noinspection ExceptionCaughtLocallyJS
            throw new TypeError('A promise cannot be resolved with itself.');
        }
        if (newValue && (typeof newValue === 'object' || typeof newValue === 'function')) {
            var then = newValue.then;
            if (newValue instanceof secp256k1.Promise) {
                self._state = 3;
                self._value = newValue;
                finale(self);
                return;
            } else if (typeof then === 'function') {
                doResolve(bind(then, newValue), self);
                return;
            }
        }
        self._state = 1;
        self._value = newValue;
        finale(self);
    } catch (e) {
        reject(self, e);
    }
}

/**
 * @param {secp256k1.Promise} self
 * @param {*} newValue
 * @private
 */
function reject(self, newValue) {
    self._state = 2;
    self._value = newValue;
    finale(self);
}

/**
 * @param {secp256k1.Promise} self
 * @private
 */
function finale(self) {
    if (self._state === 2 && self._deferreds.length === 0) {
        _immediateFn(function() {
            if (!self._handled) {
                _unhandledRejectionFn(self._value);
            }
        });
    }

    for (var i = 0, len = self._deferreds.length; i < len; i++) {
        handle(self, self._deferreds[i]);
    }
    self._deferreds = null;
}

/**
 * Take a potentially misbehaving resolver function and make sure
 * onFulfilled and onRejected are only called once.
 *
 * Makes no guarantees about asynchrony.
 * 
 * @param {Function} fn Function to be called when the promise is resolved
 * @param {secp256k1.Promise} self
 */
function doResolve(fn, self) {
    var done = false;
    try {
        fn(function (value) {
            if (done) return;
            done = true;
            resolve(self, value);
        }, function (reason) {
            if (done) return;
            done = true;
            reject(self, reason);
        });
    } catch (ex) {
        if (done) return;
        done = true;
        reject(self, ex);
    }
}

/**
 * @param {Function} onFulfilled
 * @param {Function=} onRejected
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.prototype.then = function (onFulfilled, onRejected) {
    var prom = new (secp256k1.Promise)(noop);

    handle(this, new Handler(prom, onFulfilled, onRejected));
    return prom;
};

/**
 * @param {Function} onRejected
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.prototype['catch'] = function (onRejected) {
    return this.then(null, onRejected);
};

/**
 * @param {Array<Function|secp256k1.Promise>} arr
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.all = function (arr) {
    var args = Array.prototype.slice.call(arr);

    return new secp256k1.Promise(function (resolve, reject) {
        if (args.length === 0) return resolve([]);
        var remaining = args.length;

        function res(i, val) {
            try {
                if (val && (typeof val === 'object' || typeof val === 'function')) {
                    var then = val.then;
                    if (typeof then === 'function') {
                        then.call(val, function (val) {
                            res(i, val);
                        }, reject);
                        return;
                    }
                }
                args[i] = val;
                if (--remaining === 0) {
                    resolve(args);
                }
            } catch (ex) {
                reject(ex);
            }
        }

        for (var i = 0; i < args.length; i++) {
            res(i, args[i]);
        }
    });
};

/**
 * @param {*} value
 * @returns {*}
 */
secp256k1.Promise.resolve = function (value) {
    if (value && typeof value === 'object' && value instanceof secp256k1.Promise) {
        return value;
    }

    return new secp256k1.Promise(function (resolve) {
        resolve(value);
    });
};

/**
 * @param {*} value
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.reject = function (value) {
    return new secp256k1.Promise(function (resolve, reject) {
        reject(value);
    });
};

/**
 * @param {Array<secp256k1.Promise>} values
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.race = function (values) {
    return new secp256k1.Promise(function (resolve, reject) {
        for (var i = 0, len = values.length; i < len; i++) {
            values[i].then(resolve, reject);
        }
    });
};

