(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.urlOtpauth = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){

/*!
* https://github.com/huihuimoe/url-otpauth-ng
* Released under the MIT license
*/

/** @module url-otpauth */

var URL = URL || require('url').URL

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
            var parsed = new URL(rawUrl);
        } catch (error) {
            throw error instanceof TypeError ? new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL) : error;
        }

        if (parsed.protocol !== 'otpauth:') {
            throw new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL);
        }

        parsed.protocol = 'http';
        parsed = new URL(parsed);

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

},{"url":"url"}]},{},[1])(1)
});

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbigpe2Z1bmN0aW9uIHIoZSxuLHQpe2Z1bmN0aW9uIG8oaSxmKXtpZighbltpXSl7aWYoIWVbaV0pe3ZhciBjPVwiZnVuY3Rpb25cIj09dHlwZW9mIHJlcXVpcmUmJnJlcXVpcmU7aWYoIWYmJmMpcmV0dXJuIGMoaSwhMCk7aWYodSlyZXR1cm4gdShpLCEwKTt2YXIgYT1uZXcgRXJyb3IoXCJDYW5ub3QgZmluZCBtb2R1bGUgJ1wiK2krXCInXCIpO3Rocm93IGEuY29kZT1cIk1PRFVMRV9OT1RfRk9VTkRcIixhfXZhciBwPW5baV09e2V4cG9ydHM6e319O2VbaV1bMF0uY2FsbChwLmV4cG9ydHMsZnVuY3Rpb24ocil7dmFyIG49ZVtpXVsxXVtyXTtyZXR1cm4gbyhufHxyKX0scCxwLmV4cG9ydHMscixlLG4sdCl9cmV0dXJuIG5baV0uZXhwb3J0c31mb3IodmFyIHU9XCJmdW5jdGlvblwiPT10eXBlb2YgcmVxdWlyZSYmcmVxdWlyZSxpPTA7aTx0Lmxlbmd0aDtpKyspbyh0W2ldKTtyZXR1cm4gb31yZXR1cm4gcn0pKCkiLCJcbi8qIVxuKiBodHRwczovL2dpdGh1Yi5jb20vaHVpaHVpbW9lL3VybC1vdHBhdXRoLW5nXG4qIFJlbGVhc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZVxuKi9cblxuLyoqIEBtb2R1bGUgdXJsLW90cGF1dGggKi9cblxudmFyIFVSTCA9IFVSTCB8fCByZXF1aXJlKCd1cmwnKS5VUkxcblxuLy9cbi8vIEV4Y2VwdGlvbiB0eXBlc1xuLy9cblxudmFyIEVycm9yVHlwZSA9IHtcbiAgICBJTlZBTElEX0lTU1VFUjogMCxcbiAgICBJTlZBTElEX0xBQkVMOiAxLFxuICAgIElOVkFMSURfUFJPVE9DT0w6IDIsXG4gICAgTUlTU0lOR19BQ0NPVU5UX05BTUU6IDMsXG4gICAgTUlTU0lOR19DT1VOVEVSOiA0LFxuICAgIE1JU1NJTkdfSVNTVUVSOiA1LFxuICAgIE1JU1NJTkdfU0VDUkVUX0tFWTogNixcbiAgICBVTktOT1dOX09UUDogNyxcbiAgICBJTlZBTElEX0RJR0lUUzogOCxcbiAgICBVTktOT1dOX0FMR09SSVRITTogOVxufTtcblxudmFyIFBvc3NpYmxlRGlnaXRzID0gWzYsIDhdO1xuXG52YXIgUG9zc2libGVBbGdvcml0aG1zID0gW1wiU0hBMVwiLCBcIlNIQTI1NlwiLCBcIlNIQTUxMlwiLCBcIk1ENVwiXTtcblxuZnVuY3Rpb24gT3RwYXV0aEludmFsaWRVUkwoZXJyb3JUeXBlKSB7XG4gICAgdGhpcy5uYW1lID0gJ090cGF1dGhJbnZhbGlkVVJMJztcbiAgICB0aGlzLm1lc3NhZ2UgPSAnR2l2ZW4gb3RwYXV0aDovLyBVUkwgaXMgaW52YWxpZC4gKEVycm9yICcgKyBlcnJvclR5cGUgKyAnKSc7XG4gICAgdGhpcy5lcnJvclR5cGUgPSBlcnJvclR5cGU7XG59XG5cbk90cGF1dGhJbnZhbGlkVVJMLnByb3RvdHlwZSA9IG5ldyBFcnJvcigpO1xuT3RwYXV0aEludmFsaWRVUkwucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gT3RwYXV0aEludmFsaWRVUkw7XG5cbi8vXG4vLyBDb2RlXG4vL1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICAvKipcbiAgICAgKiBQYXJzZXMgYW4gT1RQQXV0aCBVUkkuXG4gICAgICpcbiAgICAgKiBQYXJzZXMgYW4gVVJMIGFzIGRlc2NyaWJlZCBpbiBHb29nbGUgQXV0aGVudGljYXRvcidzIFwiS2V5VXJpRm9ybWF0XCIgZG9jdW1lbnQgKHNlZTpcbiAgICAgKiBbaHR0cHM6Ly9jb2RlLmdvb2dsZS5jb20vcC9nb29nbGUtYXV0aGVudGljYXRvci93aWtpL0tleVVyaUZvcm1hdF0oaHR0cHM6Ly9jb2RlLmdvb2dsZS5jb20vcC9nb29nbGUtYXV0aGVudGljYXRvci93aWtpL0tleVVyaUZvcm1hdCkpXG4gICAgICogYW5kIHJldHVybnMgYW4gb2JqZWN0IHRoYXQgY29udGFpbnMgdGhlIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICAgICAqXG4gICAgICogLSBgYWNjb3VudGA6IFRoZSBhY2NvdW50IG5hbWUuXG4gICAgICogLSBgZGlnaXRzYDogVGhlIG51bWJlciBvZiBkaWdpdHMgb2YgdGhlIHJlc3VsdGluZyBPVFAuIERlZmF1bHQgaXMgNiAoc2l4KS5cbiAgICAgKiAtIGBrZXlgOiBUaGUgc2hhcmVkIGtleSBpbiBCYXNlMzIgZW5jb2RpbmcuXG4gICAgICogLSBgaXNzdWVyYDogUHJvdmlkZXIgb3Igc2VydmljZSB0aGlzIGFjY291bnQgaXMgYXNzb2NpYXRlZCB3aXRoLiBUaGUgZGVmYXVsdCBpcyB0aGUgZW1wdHlcbiAgICAgKiAgIHN0cmluZy5cbiAgICAgKiAtIGB0eXBlYDogRWl0aGVyIHRoZSBzdHJpbmcgYGhvdHBgIG9yIGB0b3RwYC5cbiAgICAgKlxuICAgICAqIE9UUCBvZiB0eXBlIGBob3RwYCBoYXZlIGFuIGFkZGl0aW9uYWwgYGNvdW50ZXJgIGZpZWxkIHdoaWNoIGNvbnRhaW5zIHRoZSBzdGFydCB2YWx1ZSBmb3IgdGhlXG4gICAgICogSE9UUCBjb3VudGVyLiBJbiBhbGwgb3RoZXIgY2FzZXMgdGhpcyBmaWVsZCBpcyBtaXNzaW5nIGZyb20gdGhlIHJlc3VsdGluZyBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAdHlwZWRlZiB7T2JqZWN0fSBSZXN1bHRcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSB0eXBlXG4gICAgICogQHByb3Age3N0cmluZ30gYWNjb3VudFxuICAgICAqIEBwcm9wIHtzdHJpbmd9IGtleVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IFtpc3N1ZXJdXG4gICAgICogQHByb3Age3N0cmluZ30gZGlnaXRzXG4gICAgICogQHByb3Age3N0cmluZ30gW2FsZ29yaXRobV1cbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBbcGVyaW9kXVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IFtjb3VudGVyXVxuICAgICAqIEBwYXJhbSByYXdVcmwge3N0cmluZ30gVGhlIFVSSSB0byBwYXJzZS5cbiAgICAgKiBAcmV0dXJucyB7UmVzdWx0fSBBbiBvYmplY3Qgd2l0aCBwcm9wZXJ0aWVzIGRlc2NyaWJlZCBhYm92ZS5cbiAgICAgKi9cbiAgICBwYXJzZTogZnVuY3Rpb24gcGFyc2UocmF3VXJsKSB7XG4gICAgICAgIHZhciByZXQgPSB7fTtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBQcm90b2NvbFxuICAgICAgICAvL1xuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB2YXIgcGFyc2VkID0gbmV3IFVSTChyYXdVcmwpO1xuICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgdGhyb3cgZXJyb3IgaW5zdGFuY2VvZiBUeXBlRXJyb3IgPyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfUFJPVE9DT0wpIDogZXJyb3I7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAocGFyc2VkLnByb3RvY29sICE9PSAnb3RwYXV0aDonKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfUFJPVE9DT0wpO1xuICAgICAgICB9XG5cbiAgICAgICAgcGFyc2VkLnByb3RvY29sID0gJ2h0dHAnO1xuICAgICAgICBwYXJzZWQgPSBuZXcgVVJMKHBhcnNlZCk7XG5cbiAgICAgICAgLy9cbiAgICAgICAgLy8gVHlwZVxuICAgICAgICAvL1xuXG4gICAgICAgIHZhciBvdHBBbGdvID0gZGVjb2RlVVJJQ29tcG9uZW50KHBhcnNlZC5ob3N0KTtcblxuICAgICAgICBpZiAob3RwQWxnbyAhPT0gJ2hvdHAnICYmIG90cEFsZ28gIT09ICd0b3RwJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5VTktOT1dOX09UUCk7XG4gICAgICAgIH1cblxuICAgICAgICByZXQudHlwZSA9IG90cEFsZ287XG5cbiAgICAgICAgLy9cbiAgICAgICAgLy8gTGFiZWwgKGNvbnRhaW5zIGFjY291bnQgbmFtZSwgbWF5IGNvbnRhaW4gaXNzdWVyKVxuICAgICAgICAvL1xuXG4gICAgICAgIHZhciBsYWJlbCA9IGRlY29kZVVSSUNvbXBvbmVudChwYXJzZWQucGF0aG5hbWUuc3Vic3RyaW5nKDEpKTtcbiAgICAgICAgdmFyIGxhYmVsQ29tcG9uZW50cyA9IGxhYmVsLnNwbGl0KCc6Jyk7XG4gICAgICAgIHZhciBpc3N1ZXIgPSAnJztcbiAgICAgICAgdmFyIGFjY291bnQgPSAnJztcblxuICAgICAgICBpZiAobGFiZWxDb21wb25lbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgYWNjb3VudCA9IGxhYmVsQ29tcG9uZW50c1swXTtcbiAgICAgICAgfSBlbHNlIGlmIChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgICAgICBpc3N1ZXIgPSBsYWJlbENvbXBvbmVudHNbMF07XG4gICAgICAgICAgICBhY2NvdW50ID0gbGFiZWxDb21wb25lbnRzWzFdO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX0xBQkVMKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChhY2NvdW50Lmxlbmd0aCA8IDEpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19BQ0NPVU5UX05BTUUpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAyKSAmJiAoaXNzdWVyLmxlbmd0aCA8IDEpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfSVNTVUVSKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC5hY2NvdW50ID0gYWNjb3VudDtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBQYXJhbWV0ZXJzXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIHBhcmFtZXRlcnMgPSBwYXJzZWQuc2VhcmNoUGFyYW1zO1xuXG4gICAgICAgIC8vIFNlY3JldCBrZXlcbiAgICAgICAgaWYgKCFwYXJhbWV0ZXJzLmhhcygnc2VjcmV0JykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19TRUNSRVRfS0VZKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC5rZXkgPSBwYXJhbWV0ZXJzLmdldCgnc2VjcmV0Jyk7XG5cbiAgICAgICAgLy8gSXNzdWVyXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnaXNzdWVyJykgJiYgaXNzdWVyICYmIChwYXJhbWV0ZXJzLmdldCgnaXNzdWVyJykgIT09IGlzc3VlcikpIHtcbiAgICAgICAgICAgIC8vIElmIHByZXNlbnQsIGl0IG11c3QgYmUgZXF1YWwgdG8gdGhlIFwiaXNzdWVyXCIgc3BlY2lmaWVkIGluIHRoZSBsYWJlbC5cbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9JU1NVRVIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0Lmlzc3VlciA9IGlzc3VlciB8fCBwYXJhbWV0ZXJzLmdldCgnaXNzdWVyJykgfHwgJyc7XG5cbiAgICAgICAgLy8gT1RQIGRpZ2l0c1xuICAgICAgICByZXQuZGlnaXRzID0gNjsgIC8vIERlZmF1bHQgaXMgNlxuXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnZGlnaXRzJykpIHtcbiAgICAgICAgICAgIHZhciBwYXJzZWREaWdpdHMgPSBwYXJzZUludChwYXJhbWV0ZXJzLmdldCgnZGlnaXRzJyksIDEwKTtcbiAgICAgICAgICAgIGlmIChQb3NzaWJsZURpZ2l0cy5pbmRleE9mKHBhcnNlZERpZ2l0cykgPT0gLTEpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfRElHSVRTKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0LmRpZ2l0cyA9IHBhcnNlZERpZ2l0cztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEFsZ29yaXRobSB0byBjcmVhdGUgaGFzaFxuICAgICAgICBpZiAocGFyYW1ldGVycy5oYXMoJ2FsZ29yaXRobScpKSB7XG4gICAgICAgICAgICBpZiAoUG9zc2libGVBbGdvcml0aG1zLmluZGV4T2YocGFyYW1ldGVycy5nZXQoJ2FsZ29yaXRobScpKSA9PSAtMSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuVU5LTk9XTl9BTEdPUklUSE0pO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBPcHRpb25hbCAnYWxnb3JpdGhtJyBwYXJhbWV0ZXIuXG4gICAgICAgICAgICAgICAgcmV0LmFsZ29yaXRobSA9IHBhcmFtZXRlcnMuZ2V0KCdhbGdvcml0aG0nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFBlcmlvZCAob25seSBmb3IgVE9UUClcbiAgICAgICAgaWYgKG90cEFsZ28gPT09ICd0b3RwJykge1xuICAgICAgICAgICAgLy8gT3B0aW9uYWwgJ3BlcmlvZCcgcGFyYW1ldGVyIGZvciBUT1RQLlxuICAgICAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdwZXJpb2QnKSkge1xuICAgICAgICAgICAgICAgIHJldC5wZXJpb2QgPSBwYXJzZUZsb2F0KHBhcmFtZXRlcnMuZ2V0KCdwZXJpb2QnKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb3VudGVyIChvbmx5IGZvciBIT1RQKVxuICAgICAgICBpZiAob3RwQWxnbyA9PT0gJ2hvdHAnKSB7XG4gICAgICAgICAgICBpZiAoIXBhcmFtZXRlcnMuaGFzKCdjb3VudGVyJykpIHtcbiAgICAgICAgICAgICAgICAvLyBXZSByZXF1aXJlIHRoZSAnY291bnRlcicgcGFyYW1ldGVyIGZvciBIT1RQLlxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuTUlTU0lOR19DT1VOVEVSKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0LmNvdW50ZXIgPSBwYXJzZUludChwYXJhbWV0ZXJzLmdldCgnY291bnRlcicpLCAxMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gcmV0O1xuICAgIH0sXG5cbiAgICAvKipcbiAgICAgKiBFbnVtZXJhdGlvbiBvZiBhbGwgZXJyb3IgdHlwZXMgcmFpc2VkIGJ5IGBPdHBhdXRoSW52YWxpZFVSTGAuXG4gICAgICovXG4gICAgRXJyb3JUeXBlOiBFcnJvclR5cGUsXG5cbiAgICAvKipcbiAgICAgKiBFeGNlcHRpb24gdGhyb3duIHdoZW5ldmVyIHRoZXJlJ3MgYW4gZXJyb3IgZGVjb25zdHJ1Y3RpbmcgYW4gJ290cGF1dGg6Ly8nIFVSSS5cbiAgICAgKlxuICAgICAqIFlvdSBjYW4gcXVlcnkgdGhlIGBlcnJvclR5cGVgIGF0dHJpYnV0ZSB0byBvYnRhaW4gdGhlIGV4YWN0IHJlYXNvbiBmb3IgZmFpbHVyZS4gVGhlXG4gICAgICogYGVycm9yVHlwZWAgYXR0cmlidXRlcyBjb250YWlucyBhIHZhbHVlIGZyb20gdGhlIGBFcnJvclR5cGVgIGVudW1lcmF0aW9uLlxuICAgICAqL1xuICAgIE90cGF1dGhJbnZhbGlkVVJMOiBPdHBhdXRoSW52YWxpZFVSTFxufTtcbiJdfQ==
