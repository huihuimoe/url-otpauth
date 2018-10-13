(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.urlOtpauthNg = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){

/*!
* https://github.com/huihuimoe/url-otpauth-ng
* Released under the MIT license
*/

/** @module url-otpauth */

var _URL = typeof URL !== 'undefined' ? URL : require('url').URL

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

},{"url":2}],2:[function(require,module,exports){

},{}]},{},[1])(1)
});

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9icm93c2VyLXJlc29sdmUvZW1wdHkuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25OQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uKCl7ZnVuY3Rpb24gcihlLG4sdCl7ZnVuY3Rpb24gbyhpLGYpe2lmKCFuW2ldKXtpZighZVtpXSl7dmFyIGM9XCJmdW5jdGlvblwiPT10eXBlb2YgcmVxdWlyZSYmcmVxdWlyZTtpZighZiYmYylyZXR1cm4gYyhpLCEwKTtpZih1KXJldHVybiB1KGksITApO3ZhciBhPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIraStcIidcIik7dGhyb3cgYS5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGF9dmFyIHA9bltpXT17ZXhwb3J0czp7fX07ZVtpXVswXS5jYWxsKHAuZXhwb3J0cyxmdW5jdGlvbihyKXt2YXIgbj1lW2ldWzFdW3JdO3JldHVybiBvKG58fHIpfSxwLHAuZXhwb3J0cyxyLGUsbix0KX1yZXR1cm4gbltpXS5leHBvcnRzfWZvcih2YXIgdT1cImZ1bmN0aW9uXCI9PXR5cGVvZiByZXF1aXJlJiZyZXF1aXJlLGk9MDtpPHQubGVuZ3RoO2krKylvKHRbaV0pO3JldHVybiBvfXJldHVybiByfSkoKSIsIlxuLyohXG4qIGh0dHBzOi8vZ2l0aHViLmNvbS9odWlodWltb2UvdXJsLW90cGF1dGgtbmdcbiogUmVsZWFzZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlXG4qL1xuXG4vKiogQG1vZHVsZSB1cmwtb3RwYXV0aCAqL1xuXG52YXIgX1VSTCA9IHR5cGVvZiBVUkwgIT09ICd1bmRlZmluZWQnID8gVVJMIDogcmVxdWlyZSgndXJsJykuVVJMXG5cbi8vXG4vLyBFeGNlcHRpb24gdHlwZXNcbi8vXG5cbnZhciBFcnJvclR5cGUgPSB7XG4gICAgSU5WQUxJRF9JU1NVRVI6IDAsXG4gICAgSU5WQUxJRF9MQUJFTDogMSxcbiAgICBJTlZBTElEX1BST1RPQ09MOiAyLFxuICAgIE1JU1NJTkdfQUNDT1VOVF9OQU1FOiAzLFxuICAgIE1JU1NJTkdfQ09VTlRFUjogNCxcbiAgICBNSVNTSU5HX0lTU1VFUjogNSxcbiAgICBNSVNTSU5HX1NFQ1JFVF9LRVk6IDYsXG4gICAgVU5LTk9XTl9PVFA6IDcsXG4gICAgSU5WQUxJRF9ESUdJVFM6IDgsXG4gICAgVU5LTk9XTl9BTEdPUklUSE06IDlcbn07XG5cbnZhciBQb3NzaWJsZURpZ2l0cyA9IFs2LCA4XTtcblxudmFyIFBvc3NpYmxlQWxnb3JpdGhtcyA9IFtcIlNIQTFcIiwgXCJTSEEyNTZcIiwgXCJTSEE1MTJcIiwgXCJNRDVcIl07XG5cbmZ1bmN0aW9uIE90cGF1dGhJbnZhbGlkVVJMKGVycm9yVHlwZSkge1xuICAgIHRoaXMubmFtZSA9ICdPdHBhdXRoSW52YWxpZFVSTCc7XG4gICAgdGhpcy5tZXNzYWdlID0gJ0dpdmVuIG90cGF1dGg6Ly8gVVJMIGlzIGludmFsaWQuIChFcnJvciAnICsgZXJyb3JUeXBlICsgJyknO1xuICAgIHRoaXMuZXJyb3JUeXBlID0gZXJyb3JUeXBlO1xufVxuXG5PdHBhdXRoSW52YWxpZFVSTC5wcm90b3R5cGUgPSBuZXcgRXJyb3IoKTtcbk90cGF1dGhJbnZhbGlkVVJMLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IE90cGF1dGhJbnZhbGlkVVJMO1xuXG4vL1xuLy8gQ29kZVxuLy9cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gICAgLyoqXG4gICAgICogUGFyc2VzIGFuIE9UUEF1dGggVVJJLlxuICAgICAqXG4gICAgICogUGFyc2VzIGFuIFVSTCBhcyBkZXNjcmliZWQgaW4gR29vZ2xlIEF1dGhlbnRpY2F0b3IncyBcIktleVVyaUZvcm1hdFwiIGRvY3VtZW50IChzZWU6XG4gICAgICogW2h0dHBzOi8vY29kZS5nb29nbGUuY29tL3AvZ29vZ2xlLWF1dGhlbnRpY2F0b3Ivd2lraS9LZXlVcmlGb3JtYXRdKGh0dHBzOi8vY29kZS5nb29nbGUuY29tL3AvZ29vZ2xlLWF1dGhlbnRpY2F0b3Ivd2lraS9LZXlVcmlGb3JtYXQpKVxuICAgICAqIGFuZCByZXR1cm5zIGFuIG9iamVjdCB0aGF0IGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAgICAgKlxuICAgICAqIC0gYGFjY291bnRgOiBUaGUgYWNjb3VudCBuYW1lLlxuICAgICAqIC0gYGRpZ2l0c2A6IFRoZSBudW1iZXIgb2YgZGlnaXRzIG9mIHRoZSByZXN1bHRpbmcgT1RQLiBEZWZhdWx0IGlzIDYgKHNpeCkuXG4gICAgICogLSBga2V5YDogVGhlIHNoYXJlZCBrZXkgaW4gQmFzZTMyIGVuY29kaW5nLlxuICAgICAqIC0gYGlzc3VlcmA6IFByb3ZpZGVyIG9yIHNlcnZpY2UgdGhpcyBhY2NvdW50IGlzIGFzc29jaWF0ZWQgd2l0aC4gVGhlIGRlZmF1bHQgaXMgdGhlIGVtcHR5XG4gICAgICogICBzdHJpbmcuXG4gICAgICogLSBgdHlwZWA6IEVpdGhlciB0aGUgc3RyaW5nIGBob3RwYCBvciBgdG90cGAuXG4gICAgICpcbiAgICAgKiBPVFAgb2YgdHlwZSBgaG90cGAgaGF2ZSBhbiBhZGRpdGlvbmFsIGBjb3VudGVyYCBmaWVsZCB3aGljaCBjb250YWlucyB0aGUgc3RhcnQgdmFsdWUgZm9yIHRoZVxuICAgICAqIEhPVFAgY291bnRlci4gSW4gYWxsIG90aGVyIGNhc2VzIHRoaXMgZmllbGQgaXMgbWlzc2luZyBmcm9tIHRoZSByZXN1bHRpbmcgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHR5cGVkZWYge09iamVjdH0gUmVzdWx0XG4gICAgICogQHByb3Age3N0cmluZ30gdHlwZVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IGFjY291bnRcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBrZXlcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBbaXNzdWVyXVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IGRpZ2l0c1xuICAgICAqIEBwcm9wIHtzdHJpbmd9IFthbGdvcml0aG1dXG4gICAgICogQHByb3Age3N0cmluZ30gW3BlcmlvZF1cbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBbY291bnRlcl1cbiAgICAgKiBAcGFyYW0gcmF3VXJsIHtzdHJpbmd9IFRoZSBVUkkgdG8gcGFyc2UuXG4gICAgICogQHJldHVybnMge1Jlc3VsdH0gQW4gb2JqZWN0IHdpdGggcHJvcGVydGllcyBkZXNjcmliZWQgYWJvdmUuXG4gICAgICovXG4gICAgcGFyc2U6IGZ1bmN0aW9uIHBhcnNlKHJhd1VybCkge1xuICAgICAgICB2YXIgcmV0ID0ge307XG5cbiAgICAgICAgLy9cbiAgICAgICAgLy8gUHJvdG9jb2xcbiAgICAgICAgLy9cblxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgdmFyIHBhcnNlZCA9IG5ldyBfVVJMKHJhd1VybCk7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnJvciBpbnN0YW5jZW9mIFR5cGVFcnJvciA/IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9QUk9UT0NPTCkgOiBlcnJvcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChwYXJzZWQucHJvdG9jb2wgIT09ICdvdHBhdXRoOicpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9QUk9UT0NPTCk7XG4gICAgICAgIH1cblxuICAgICAgICBwYXJzZWQucHJvdG9jb2wgPSAnaHR0cCc7XG4gICAgICAgIHBhcnNlZCA9IG5ldyBfVVJMKHBhcnNlZCk7XG5cbiAgICAgICAgLy9cbiAgICAgICAgLy8gVHlwZVxuICAgICAgICAvL1xuXG4gICAgICAgIHZhciBvdHBBbGdvID0gZGVjb2RlVVJJQ29tcG9uZW50KHBhcnNlZC5ob3N0KTtcblxuICAgICAgICBpZiAob3RwQWxnbyAhPT0gJ2hvdHAnICYmIG90cEFsZ28gIT09ICd0b3RwJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5VTktOT1dOX09UUCk7XG4gICAgICAgIH1cblxuICAgICAgICByZXQudHlwZSA9IG90cEFsZ287XG5cbiAgICAgICAgLy9cbiAgICAgICAgLy8gTGFiZWwgKGNvbnRhaW5zIGFjY291bnQgbmFtZSwgbWF5IGNvbnRhaW4gaXNzdWVyKVxuICAgICAgICAvL1xuXG4gICAgICAgIHZhciBsYWJlbCA9IGRlY29kZVVSSUNvbXBvbmVudChwYXJzZWQucGF0aG5hbWUuc3Vic3RyaW5nKDEpKTtcbiAgICAgICAgdmFyIGxhYmVsQ29tcG9uZW50cyA9IGxhYmVsLnNwbGl0KCc6Jyk7XG4gICAgICAgIHZhciBpc3N1ZXIgPSAnJztcbiAgICAgICAgdmFyIGFjY291bnQgPSAnJztcblxuICAgICAgICBpZiAobGFiZWxDb21wb25lbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgYWNjb3VudCA9IGxhYmVsQ29tcG9uZW50c1swXTtcbiAgICAgICAgfSBlbHNlIGlmIChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgICAgICBpc3N1ZXIgPSBsYWJlbENvbXBvbmVudHNbMF07XG4gICAgICAgICAgICBhY2NvdW50ID0gbGFiZWxDb21wb25lbnRzWzFdO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX0xBQkVMKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChhY2NvdW50Lmxlbmd0aCA8IDEpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19BQ0NPVU5UX05BTUUpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAyKSAmJiAoaXNzdWVyLmxlbmd0aCA8IDEpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfSVNTVUVSKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC5hY2NvdW50ID0gYWNjb3VudDtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBQYXJhbWV0ZXJzXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIHBhcmFtZXRlcnMgPSBwYXJzZWQuc2VhcmNoUGFyYW1zO1xuXG4gICAgICAgIC8vIFNlY3JldCBrZXlcbiAgICAgICAgaWYgKCFwYXJhbWV0ZXJzLmhhcygnc2VjcmV0JykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19TRUNSRVRfS0VZKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC5rZXkgPSBwYXJhbWV0ZXJzLmdldCgnc2VjcmV0Jyk7XG5cbiAgICAgICAgLy8gSXNzdWVyXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnaXNzdWVyJykgJiYgaXNzdWVyICYmIChwYXJhbWV0ZXJzLmdldCgnaXNzdWVyJykgIT09IGlzc3VlcikpIHtcbiAgICAgICAgICAgIC8vIElmIHByZXNlbnQsIGl0IG11c3QgYmUgZXF1YWwgdG8gdGhlIFwiaXNzdWVyXCIgc3BlY2lmaWVkIGluIHRoZSBsYWJlbC5cbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9JU1NVRVIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0Lmlzc3VlciA9IGlzc3VlciB8fCBwYXJhbWV0ZXJzLmdldCgnaXNzdWVyJykgfHwgJyc7XG5cbiAgICAgICAgLy8gT1RQIGRpZ2l0c1xuICAgICAgICByZXQuZGlnaXRzID0gNjsgIC8vIERlZmF1bHQgaXMgNlxuXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnZGlnaXRzJykpIHtcbiAgICAgICAgICAgIHZhciBwYXJzZWREaWdpdHMgPSBwYXJzZUludChwYXJhbWV0ZXJzLmdldCgnZGlnaXRzJyksIDEwKTtcbiAgICAgICAgICAgIGlmIChQb3NzaWJsZURpZ2l0cy5pbmRleE9mKHBhcnNlZERpZ2l0cykgPT0gLTEpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfRElHSVRTKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0LmRpZ2l0cyA9IHBhcnNlZERpZ2l0cztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEFsZ29yaXRobSB0byBjcmVhdGUgaGFzaFxuICAgICAgICBpZiAocGFyYW1ldGVycy5oYXMoJ2FsZ29yaXRobScpKSB7XG4gICAgICAgICAgICBpZiAoUG9zc2libGVBbGdvcml0aG1zLmluZGV4T2YocGFyYW1ldGVycy5nZXQoJ2FsZ29yaXRobScpKSA9PSAtMSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuVU5LTk9XTl9BTEdPUklUSE0pO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBPcHRpb25hbCAnYWxnb3JpdGhtJyBwYXJhbWV0ZXIuXG4gICAgICAgICAgICAgICAgcmV0LmFsZ29yaXRobSA9IHBhcmFtZXRlcnMuZ2V0KCdhbGdvcml0aG0nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFBlcmlvZCAob25seSBmb3IgVE9UUClcbiAgICAgICAgaWYgKG90cEFsZ28gPT09ICd0b3RwJykge1xuICAgICAgICAgICAgLy8gT3B0aW9uYWwgJ3BlcmlvZCcgcGFyYW1ldGVyIGZvciBUT1RQLlxuICAgICAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdwZXJpb2QnKSkge1xuICAgICAgICAgICAgICAgIHJldC5wZXJpb2QgPSBwYXJzZUZsb2F0KHBhcmFtZXRlcnMuZ2V0KCdwZXJpb2QnKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb3VudGVyIChvbmx5IGZvciBIT1RQKVxuICAgICAgICBpZiAob3RwQWxnbyA9PT0gJ2hvdHAnKSB7XG4gICAgICAgICAgICBpZiAoIXBhcmFtZXRlcnMuaGFzKCdjb3VudGVyJykpIHtcbiAgICAgICAgICAgICAgICAvLyBXZSByZXF1aXJlIHRoZSAnY291bnRlcicgcGFyYW1ldGVyIGZvciBIT1RQLlxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19DT1VOVEVSKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0LmNvdW50ZXIgPSBwYXJzZUludChwYXJhbWV0ZXJzLmdldCgnY291bnRlcicpLCAxMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gcmV0O1xuICAgIH0sXG5cbiAgICAvKipcbiAgICAgKiBFbnVtZXJhdGlvbiBvZiBhbGwgZXJyb3IgdHlwZXMgcmFpc2VkIGJ5IGBPdHBhdXRoSW52YWxpZFVSTGAuXG4gICAgICovXG4gICAgRXJyb3JUeXBlOiBFcnJvclR5cGUsXG5cbiAgICAvKipcbiAgICAgKiBFeGNlcHRpb24gdGhyb3duIHdoZW5ldmVyIHRoZXJlJ3MgYW4gZXJyb3IgZGVjb25zdHJ1Y3RpbmcgYW4gJ290cGF1dGg6Ly8nIFVSSS5cbiAgICAgKlxuICAgICAqIFlvdSBjYW4gcXVlcnkgdGhlIGBlcnJvclR5cGVgIGF0dHJpYnV0ZSB0byBvYnRhaW4gdGhlIGV4YWN0IHJlYXNvbiBmb3IgZmFpbHVyZS4gVGhlXG4gICAgICogYGVycm9yVHlwZWAgYXR0cmlidXRlcyBjb250YWlucyBhIHZhbHVlIGZyb20gdGhlIGBFcnJvclR5cGVgIGVudW1lcmF0aW9uLlxuICAgICAqL1xuICAgIE90cGF1dGhJbnZhbGlkVVJMOiBPdHBhdXRoSW52YWxpZFVSTFxufTtcbiIsIiJdfQ==
