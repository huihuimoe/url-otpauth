(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){

/*!
* https://github.com/huihuimoe/url-otpauth-ng
* Released under the MIT license
*/

/** @module url-otpauth */

var _URL = URL || global.require('url').URL

//
// Exception types
//

var ErrorType = {
    INVALID_ISSUER: 0,
    INVALID_LABEL: 1,
    INVALID_PROTOCOL: 2,
    MISSING_ACCOUNT_NAME: 3,
    MISSING_COUNTER: 4,
    MISSING_ISSUER: 5,
    MISSING_SECRET_KEY: 6,
    UNKNOWN_OTP: 7,
    INVALID_DIGITS: 8,
    UNKNOWN_ALGORITHM: 9
};

var PossibleDigits = [6, 8];

var PossibleAlgorithms = ["SHA1", "SHA256", "SHA512", "MD5"];

function OtpauthInvalidURL(errorType) {
    this.name = 'OtpauthInvalidURL';
    this.message = 'Given otpauth:// URL is invalid. (Error ' + errorType + ')';
    this.errorType = errorType;
}

OtpauthInvalidURL.prototype = new Error();
OtpauthInvalidURL.prototype.constructor = OtpauthInvalidURL;

//
// Code
//

module.exports = {
    /**
     * Parses an OTPAuth URI.
     *
     * Parses an URL as described in Google Authenticator's "KeyUriFormat" document (see:
     * [https://code.google.com/p/google-authenticator/wiki/KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat))
     * and returns an object that contains the following properties:
     *
     * - `account`: The account name.
     * - `digits`: The number of digits of the resulting OTP. Default is 6 (six).
     * - `key`: The shared key in Base32 encoding.
     * - `issuer`: Provider or service this account is associated with. The default is the empty
     *   string.
     * - `type`: Either the string `hotp` or `totp`.
     *
     * OTP of type `hotp` have an additional `counter` field which contains the start value for the
     * HOTP counter. In all other cases this field is missing from the resulting object.
     *
     * @typedef {Object} Result
     * @prop {string} type
     * @prop {string} account
     * @prop {string} key
     * @prop {string} [issuer]
     * @prop {string} digits
     * @prop {string} [algorithm]
     * @prop {string} [period]
     * @prop {string} [counter]
     * @param rawUrl {string} The URI to parse.
     * @returns {Result} An object with properties described above.
     */
    parse: function parse(rawUrl) {
        var ret = {};

        //
        // Protocol
        //

        try {
            var parsed = new _URL(rawUrl);
        } catch (error) {
            throw error instanceof TypeError ? new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL) : error;
        }

        if (parsed.protocol !== 'otpauth:') {
            throw new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL);
        }

        parsed.protocol = 'http';
        parsed = new _URL(parsed);

        //
        // Type
        //

        var otpAlgo = decodeURIComponent(parsed.host);

        if (otpAlgo !== 'hotp' && otpAlgo !== 'totp') {
            throw new OtpauthInvalidURL(ErrorType.UNKNOWN_OTP);
        }

        ret.type = otpAlgo;

        //
        // Label (contains account name, may contain issuer)
        //

        var label = decodeURIComponent(parsed.pathname.substring(1));
        var labelComponents = label.split(':');
        var issuer = '';
        var account = '';

        if (labelComponents.length === 1) {
            account = labelComponents[0];
        } else if (labelComponents.length === 2) {
            issuer = labelComponents[0];
            account = labelComponents[1];
        } else {
            throw new OtpauthInvalidURL(ErrorType.INVALID_LABEL);
        }

        if (account.length < 1) {
            throw new OtpauthInvalidURL(ErrorType.MISSING_ACCOUNT_NAME);
        }

        if ((labelComponents.length === 2) && (issuer.length < 1)) {
            throw new OtpauthInvalidURL(ErrorType.INVALID_ISSUER);
        }

        ret.account = account;

        //
        // Parameters
        //

        var parameters = parsed.searchParams;

        // Secret key
        if (!parameters.has('secret')) {
            throw new OtpauthInvalidURL(ErrorType.MISSING_SECRET_KEY);
        }

        ret.key = parameters.get('secret');

        // Issuer
        if (parameters.has('issuer') && issuer && (parameters.get('issuer') !== issuer)) {
            // If present, it must be equal to the "issuer" specified in the label.
            throw new OtpauthInvalidURL(ErrorType.INVALID_ISSUER);
        }

        ret.issuer = issuer || parameters.get('issuer') || '';

        // OTP digits
        ret.digits = 6;  // Default is 6

        if (parameters.has('digits')) {
            var parsedDigits = parseInt(parameters.get('digits'), 10);
            if (PossibleDigits.indexOf(parsedDigits) == -1) {
                throw new OtpauthInvalidURL(ErrorType.INVALID_DIGITS);
            } else {
                ret.digits = parsedDigits;
            }
        }

        // Algorithm to create hash
        if (parameters.has('algorithm')) {
            if (PossibleAlgorithms.indexOf(parameters.get('algorithm')) == -1) {
                throw new OtpauthInvalidURL(ErrorType.UNKNOWN_ALGORITHM);
            } else {
                // Optional 'algorithm' parameter.
                ret.algorithm = parameters.get('algorithm');
            }
        }

        // Period (only for TOTP)
        if (otpAlgo === 'totp') {
            // Optional 'period' parameter for TOTP.
            if (parameters.has('period')) {
                ret.period = parseFloat(parameters.get('period'));
            }
        }

        // Counter (only for HOTP)
        if (otpAlgo === 'hotp') {
            if (!parameters.has('counter')) {
                // We require the 'counter' parameter for HOTP.
                throw new OtpauthInvalidURL(ErrorType.MISSING_COUNTER);
            } else {
                ret.counter = parseInt(parameters.get('counter'), 10);
            }
        }

        return ret;
    },

    /**
     * Enumeration of all error types raised by `OtpauthInvalidURL`.
     */
    ErrorType: ErrorType,

    /**
     * Exception thrown whenever there's an error deconstructing an 'otpauth://' URI.
     *
     * You can query the `errorType` attribute to obtain the exact reason for failure. The
     * `errorType` attributes contains a value from the `ErrorType` enumeration.
     */
    OtpauthInvalidURL: OtpauthInvalidURL
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24oKXtmdW5jdGlvbiByKGUsbix0KXtmdW5jdGlvbiBvKGksZil7aWYoIW5baV0pe2lmKCFlW2ldKXt2YXIgYz1cImZ1bmN0aW9uXCI9PXR5cGVvZiByZXF1aXJlJiZyZXF1aXJlO2lmKCFmJiZjKXJldHVybiBjKGksITApO2lmKHUpcmV0dXJuIHUoaSwhMCk7dmFyIGE9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitpK1wiJ1wiKTt0aHJvdyBhLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsYX12YXIgcD1uW2ldPXtleHBvcnRzOnt9fTtlW2ldWzBdLmNhbGwocC5leHBvcnRzLGZ1bmN0aW9uKHIpe3ZhciBuPWVbaV1bMV1bcl07cmV0dXJuIG8obnx8cil9LHAscC5leHBvcnRzLHIsZSxuLHQpfXJldHVybiBuW2ldLmV4cG9ydHN9Zm9yKHZhciB1PVwiZnVuY3Rpb25cIj09dHlwZW9mIHJlcXVpcmUmJnJlcXVpcmUsaT0wO2k8dC5sZW5ndGg7aSsrKW8odFtpXSk7cmV0dXJuIG99cmV0dXJuIHJ9KSgpIiwiXG4vKiFcbiogaHR0cHM6Ly9naXRodWIuY29tL2h1aWh1aW1vZS91cmwtb3RwYXV0aC1uZ1xuKiBSZWxlYXNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2VcbiovXG5cbi8qKiBAbW9kdWxlIHVybC1vdHBhdXRoICovXG5cbnZhciBfVVJMID0gVVJMIHx8IGdsb2JhbC5yZXF1aXJlKCd1cmwnKS5VUkxcblxuLy9cbi8vIEV4Y2VwdGlvbiB0eXBlc1xuLy9cblxudmFyIEVycm9yVHlwZSA9IHtcbiAgICBJTlZBTElEX0lTU1VFUjogMCxcbiAgICBJTlZBTElEX0xBQkVMOiAxLFxuICAgIElOVkFMSURfUFJPVE9DT0w6IDIsXG4gICAgTUlTU0lOR19BQ0NPVU5UX05BTUU6IDMsXG4gICAgTUlTU0lOR19DT1VOVEVSOiA0LFxuICAgIE1JU1NJTkdfSVNTVUVSOiA1LFxuICAgIE1JU1NJTkdfU0VDUkVUX0tFWTogNixcbiAgICBVTktOT1dOX09UUDogNyxcbiAgICBJTlZBTElEX0RJR0lUUzogOCxcbiAgICBVTktOT1dOX0FMR09SSVRITTogOVxufTtcblxudmFyIFBvc3NpYmxlRGlnaXRzID0gWzYsIDhdO1xuXG52YXIgUG9zc2libGVBbGdvcml0aG1zID0gW1wiU0hBMVwiLCBcIlNIQTI1NlwiLCBcIlNIQTUxMlwiLCBcIk1ENVwiXTtcblxuZnVuY3Rpb24gT3RwYXV0aEludmFsaWRVUkwoZXJyb3JUeXBlKSB7XG4gICAgdGhpcy5uYW1lID0gJ090cGF1dGhJbnZhbGlkVVJMJztcbiAgICB0aGlzLm1lc3NhZ2UgPSAnR2l2ZW4gb3RwYXV0aDovLyBVUkwgaXMgaW52YWxpZC4gKEVycm9yICcgKyBlcnJvclR5cGUgKyAnKSc7XG4gICAgdGhpcy5lcnJvclR5cGUgPSBlcnJvclR5cGU7XG59XG5cbk90cGF1dGhJbnZhbGlkVVJMLnByb3RvdHlwZSA9IG5ldyBFcnJvcigpO1xuT3RwYXV0aEludmFsaWRVUkwucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gT3RwYXV0aEludmFsaWRVUkw7XG5cbi8vXG4vLyBDb2RlXG4vL1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICAvKipcbiAgICAgKiBQYXJzZXMgYW4gT1RQQXV0aCBVUkkuXG4gICAgICpcbiAgICAgKiBQYXJzZXMgYW4gVVJMIGFzIGRlc2NyaWJlZCBpbiBHb29nbGUgQXV0aGVudGljYXRvcidzIFwiS2V5VXJpRm9ybWF0XCIgZG9jdW1lbnQgKHNlZTpcbiAgICAgKiBbaHR0cHM6Ly9jb2RlLmdvb2dsZS5jb20vcC9nb29nbGUtYXV0aGVudGljYXRvci93aWtpL0tleVVyaUZvcm1hdF0oaHR0cHM6Ly9jb2RlLmdvb2dsZS5jb20vcC9nb29nbGUtYXV0aGVudGljYXRvci93aWtpL0tleVVyaUZvcm1hdCkpXG4gICAgICogYW5kIHJldHVybnMgYW4gb2JqZWN0IHRoYXQgY29udGFpbnMgdGhlIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICAgICAqXG4gICAgICogLSBgYWNjb3VudGA6IFRoZSBhY2NvdW50IG5hbWUuXG4gICAgICogLSBgZGlnaXRzYDogVGhlIG51bWJlciBvZiBkaWdpdHMgb2YgdGhlIHJlc3VsdGluZyBPVFAuIERlZmF1bHQgaXMgNiAoc2l4KS5cbiAgICAgKiAtIGBrZXlgOiBUaGUgc2hhcmVkIGtleSBpbiBCYXNlMzIgZW5jb2RpbmcuXG4gICAgICogLSBgaXNzdWVyYDogUHJvdmlkZXIgb3Igc2VydmljZSB0aGlzIGFjY291bnQgaXMgYXNzb2NpYXRlZCB3aXRoLiBUaGUgZGVmYXVsdCBpcyB0aGUgZW1wdHlcbiAgICAgKiAgIHN0cmluZy5cbiAgICAgKiAtIGB0eXBlYDogRWl0aGVyIHRoZSBzdHJpbmcgYGhvdHBgIG9yIGB0b3RwYC5cbiAgICAgKlxuICAgICAqIE9UUCBvZiB0eXBlIGBob3RwYCBoYXZlIGFuIGFkZGl0aW9uYWwgYGNvdW50ZXJgIGZpZWxkIHdoaWNoIGNvbnRhaW5zIHRoZSBzdGFydCB2YWx1ZSBmb3IgdGhlXG4gICAgICogSE9UUCBjb3VudGVyLiBJbiBhbGwgb3RoZXIgY2FzZXMgdGhpcyBmaWVsZCBpcyBtaXNzaW5nIGZyb20gdGhlIHJlc3VsdGluZyBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAdHlwZWRlZiB7T2JqZWN0fSBSZXN1bHRcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSB0eXBlXG4gICAgICogQHByb3Age3N0cmluZ30gYWNjb3VudFxuICAgICAqIEBwcm9wIHtzdHJpbmd9IGtleVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IFtpc3N1ZXJdXG4gICAgICogQHByb3Age3N0cmluZ30gZGlnaXRzXG4gICAgICogQHByb3Age3N0cmluZ30gW2FsZ29yaXRobV1cbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBbcGVyaW9kXVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IFtjb3VudGVyXVxuICAgICAqIEBwYXJhbSByYXdVcmwge3N0cmluZ30gVGhlIFVSSSB0byBwYXJzZS5cbiAgICAgKiBAcmV0dXJucyB7UmVzdWx0fSBBbiBvYmplY3Qgd2l0aCBwcm9wZXJ0aWVzIGRlc2NyaWJlZCBhYm92ZS5cbiAgICAgKi9cbiAgICBwYXJzZTogZnVuY3Rpb24gcGFyc2UocmF3VXJsKSB7XG4gICAgICAgIHZhciByZXQgPSB7fTtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBQcm90b2NvbFxuICAgICAgICAvL1xuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB2YXIgcGFyc2VkID0gbmV3IF9VUkwocmF3VXJsKTtcbiAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgIHRocm93IGVycm9yIGluc3RhbmNlb2YgVHlwZUVycm9yID8gbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX1BST1RPQ09MKSA6IGVycm9yO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHBhcnNlZC5wcm90b2NvbCAhPT0gJ290cGF1dGg6Jykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX1BST1RPQ09MKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHBhcnNlZC5wcm90b2NvbCA9ICdodHRwJztcbiAgICAgICAgcGFyc2VkID0gbmV3IF9VUkwocGFyc2VkKTtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBUeXBlXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIG90cEFsZ28gPSBkZWNvZGVVUklDb21wb25lbnQocGFyc2VkLmhvc3QpO1xuXG4gICAgICAgIGlmIChvdHBBbGdvICE9PSAnaG90cCcgJiYgb3RwQWxnbyAhPT0gJ3RvdHAnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLlVOS05PV05fT1RQKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC50eXBlID0gb3RwQWxnbztcblxuICAgICAgICAvL1xuICAgICAgICAvLyBMYWJlbCAoY29udGFpbnMgYWNjb3VudCBuYW1lLCBtYXkgY29udGFpbiBpc3N1ZXIpXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIGxhYmVsID0gZGVjb2RlVVJJQ29tcG9uZW50KHBhcnNlZC5wYXRobmFtZS5zdWJzdHJpbmcoMSkpO1xuICAgICAgICB2YXIgbGFiZWxDb21wb25lbnRzID0gbGFiZWwuc3BsaXQoJzonKTtcbiAgICAgICAgdmFyIGlzc3VlciA9ICcnO1xuICAgICAgICB2YXIgYWNjb3VudCA9ICcnO1xuXG4gICAgICAgIGlmIChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgICBhY2NvdW50ID0gbGFiZWxDb21wb25lbnRzWzBdO1xuICAgICAgICB9IGVsc2UgaWYgKGxhYmVsQ29tcG9uZW50cy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIGlzc3VlciA9IGxhYmVsQ29tcG9uZW50c1swXTtcbiAgICAgICAgICAgIGFjY291bnQgPSBsYWJlbENvbXBvbmVudHNbMV07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfTEFCRUwpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGFjY291bnQubGVuZ3RoIDwgMSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX0FDQ09VTlRfTkFNRSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoKGxhYmVsQ29tcG9uZW50cy5sZW5ndGggPT09IDIpICYmIChpc3N1ZXIubGVuZ3RoIDwgMSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9JU1NVRVIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0LmFjY291bnQgPSBhY2NvdW50O1xuXG4gICAgICAgIC8vXG4gICAgICAgIC8vIFBhcmFtZXRlcnNcbiAgICAgICAgLy9cblxuICAgICAgICB2YXIgcGFyYW1ldGVycyA9IHBhcnNlZC5zZWFyY2hQYXJhbXM7XG5cbiAgICAgICAgLy8gU2VjcmV0IGtleVxuICAgICAgICBpZiAoIXBhcmFtZXRlcnMuaGFzKCdzZWNyZXQnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX1NFQ1JFVF9LRVkpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0LmtleSA9IHBhcmFtZXRlcnMuZ2V0KCdzZWNyZXQnKTtcblxuICAgICAgICAvLyBJc3N1ZXJcbiAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdpc3N1ZXInKSAmJiBpc3N1ZXIgJiYgKHBhcmFtZXRlcnMuZ2V0KCdpc3N1ZXInKSAhPT0gaXNzdWVyKSkge1xuICAgICAgICAgICAgLy8gSWYgcHJlc2VudCwgaXQgbXVzdCBiZSBlcXVhbCB0byB0aGUgXCJpc3N1ZXJcIiBzcGVjaWZpZWQgaW4gdGhlIGxhYmVsLlxuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX0lTU1VFUik7XG4gICAgICAgIH1cblxuICAgICAgICByZXQuaXNzdWVyID0gaXNzdWVyIHx8IHBhcmFtZXRlcnMuZ2V0KCdpc3N1ZXInKSB8fCAnJztcblxuICAgICAgICAvLyBPVFAgZGlnaXRzXG4gICAgICAgIHJldC5kaWdpdHMgPSA2OyAgLy8gRGVmYXVsdCBpcyA2XG5cbiAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdkaWdpdHMnKSkge1xuICAgICAgICAgICAgdmFyIHBhcnNlZERpZ2l0cyA9IHBhcnNlSW50KHBhcmFtZXRlcnMuZ2V0KCdkaWdpdHMnKSwgMTApO1xuICAgICAgICAgICAgaWYgKFBvc3NpYmxlRGlnaXRzLmluZGV4T2YocGFyc2VkRGlnaXRzKSA9PSAtMSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9ESUdJVFMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXQuZGlnaXRzID0gcGFyc2VkRGlnaXRzO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gQWxnb3JpdGhtIHRvIGNyZWF0ZSBoYXNoXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnYWxnb3JpdGhtJykpIHtcbiAgICAgICAgICAgIGlmIChQb3NzaWJsZUFsZ29yaXRobXMuaW5kZXhPZihwYXJhbWV0ZXJzLmdldCgnYWxnb3JpdGhtJykpID09IC0xKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5VTktOT1dOX0FMR09SSVRITSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsICdhbGdvcml0aG0nIHBhcmFtZXRlci5cbiAgICAgICAgICAgICAgICByZXQuYWxnb3JpdGhtID0gcGFyYW1ldGVycy5nZXQoJ2FsZ29yaXRobScpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gUGVyaW9kIChvbmx5IGZvciBUT1RQKVxuICAgICAgICBpZiAob3RwQWxnbyA9PT0gJ3RvdHAnKSB7XG4gICAgICAgICAgICAvLyBPcHRpb25hbCAncGVyaW9kJyBwYXJhbWV0ZXIgZm9yIFRPVFAuXG4gICAgICAgICAgICBpZiAocGFyYW1ldGVycy5oYXMoJ3BlcmlvZCcpKSB7XG4gICAgICAgICAgICAgICAgcmV0LnBlcmlvZCA9IHBhcnNlRmxvYXQocGFyYW1ldGVycy5nZXQoJ3BlcmlvZCcpKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENvdW50ZXIgKG9ubHkgZm9yIEhPVFApXG4gICAgICAgIGlmIChvdHBBbGdvID09PSAnaG90cCcpIHtcbiAgICAgICAgICAgIGlmICghcGFyYW1ldGVycy5oYXMoJ2NvdW50ZXInKSkge1xuICAgICAgICAgICAgICAgIC8vIFdlIHJlcXVpcmUgdGhlICdjb3VudGVyJyBwYXJhbWV0ZXIgZm9yIEhPVFAuXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX0NPVU5URVIpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXQuY291bnRlciA9IHBhcnNlSW50KHBhcmFtZXRlcnMuZ2V0KCdjb3VudGVyJyksIDEwKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiByZXQ7XG4gICAgfSxcblxuICAgIC8qKlxuICAgICAqIEVudW1lcmF0aW9uIG9mIGFsbCBlcnJvciB0eXBlcyByYWlzZWQgYnkgYE90cGF1dGhJbnZhbGlkVVJMYC5cbiAgICAgKi9cbiAgICBFcnJvclR5cGU6IEVycm9yVHlwZSxcblxuICAgIC8qKlxuICAgICAqIEV4Y2VwdGlvbiB0aHJvd24gd2hlbmV2ZXIgdGhlcmUncyBhbiBlcnJvciBkZWNvbnN0cnVjdGluZyBhbiAnb3RwYXV0aDovLycgVVJJLlxuICAgICAqXG4gICAgICogWW91IGNhbiBxdWVyeSB0aGUgYGVycm9yVHlwZWAgYXR0cmlidXRlIHRvIG9idGFpbiB0aGUgZXhhY3QgcmVhc29uIGZvciBmYWlsdXJlLiBUaGVcbiAgICAgKiBgZXJyb3JUeXBlYCBhdHRyaWJ1dGVzIGNvbnRhaW5zIGEgdmFsdWUgZnJvbSB0aGUgYEVycm9yVHlwZWAgZW51bWVyYXRpb24uXG4gICAgICovXG4gICAgT3RwYXV0aEludmFsaWRVUkw6IE90cGF1dGhJbnZhbGlkVVJMXG59O1xuIl19
