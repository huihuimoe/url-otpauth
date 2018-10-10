(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){

/*!
* https://github.com/huihuimoe/url-otpauth-ng
* Released under the MIT license
*/

/** @module url-otpauth */

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

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uKCl7ZnVuY3Rpb24gcihlLG4sdCl7ZnVuY3Rpb24gbyhpLGYpe2lmKCFuW2ldKXtpZighZVtpXSl7dmFyIGM9XCJmdW5jdGlvblwiPT10eXBlb2YgcmVxdWlyZSYmcmVxdWlyZTtpZighZiYmYylyZXR1cm4gYyhpLCEwKTtpZih1KXJldHVybiB1KGksITApO3ZhciBhPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIraStcIidcIik7dGhyb3cgYS5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGF9dmFyIHA9bltpXT17ZXhwb3J0czp7fX07ZVtpXVswXS5jYWxsKHAuZXhwb3J0cyxmdW5jdGlvbihyKXt2YXIgbj1lW2ldWzFdW3JdO3JldHVybiBvKG58fHIpfSxwLHAuZXhwb3J0cyxyLGUsbix0KX1yZXR1cm4gbltpXS5leHBvcnRzfWZvcih2YXIgdT1cImZ1bmN0aW9uXCI9PXR5cGVvZiByZXF1aXJlJiZyZXF1aXJlLGk9MDtpPHQubGVuZ3RoO2krKylvKHRbaV0pO3JldHVybiBvfXJldHVybiByfSkoKSIsIlxuLyohXG4qIGh0dHBzOi8vZ2l0aHViLmNvbS9odWlodWltb2UvdXJsLW90cGF1dGgtbmdcbiogUmVsZWFzZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlXG4qL1xuXG4vKiogQG1vZHVsZSB1cmwtb3RwYXV0aCAqL1xuXG4vL1xuLy8gRXhjZXB0aW9uIHR5cGVzXG4vL1xuXG52YXIgRXJyb3JUeXBlID0ge1xuICAgIElOVkFMSURfSVNTVUVSOiAwLFxuICAgIElOVkFMSURfTEFCRUw6IDEsXG4gICAgSU5WQUxJRF9QUk9UT0NPTDogMixcbiAgICBNSVNTSU5HX0FDQ09VTlRfTkFNRTogMyxcbiAgICBNSVNTSU5HX0NPVU5URVI6IDQsXG4gICAgTUlTU0lOR19JU1NVRVI6IDUsXG4gICAgTUlTU0lOR19TRUNSRVRfS0VZOiA2LFxuICAgIFVOS05PV05fT1RQOiA3LFxuICAgIElOVkFMSURfRElHSVRTOiA4LFxuICAgIFVOS05PV05fQUxHT1JJVEhNOiA5XG59O1xuXG52YXIgUG9zc2libGVEaWdpdHMgPSBbNiwgOF07XG5cbnZhciBQb3NzaWJsZUFsZ29yaXRobXMgPSBbXCJTSEExXCIsIFwiU0hBMjU2XCIsIFwiU0hBNTEyXCIsIFwiTUQ1XCJdO1xuXG5mdW5jdGlvbiBPdHBhdXRoSW52YWxpZFVSTChlcnJvclR5cGUpIHtcbiAgICB0aGlzLm5hbWUgPSAnT3RwYXV0aEludmFsaWRVUkwnO1xuICAgIHRoaXMubWVzc2FnZSA9ICdHaXZlbiBvdHBhdXRoOi8vIFVSTCBpcyBpbnZhbGlkLiAoRXJyb3IgJyArIGVycm9yVHlwZSArICcpJztcbiAgICB0aGlzLmVycm9yVHlwZSA9IGVycm9yVHlwZTtcbn1cblxuT3RwYXV0aEludmFsaWRVUkwucHJvdG90eXBlID0gbmV3IEVycm9yKCk7XG5PdHBhdXRoSW52YWxpZFVSTC5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBPdHBhdXRoSW52YWxpZFVSTDtcblxuLy9cbi8vIENvZGVcbi8vXG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICAgIC8qKlxuICAgICAqIFBhcnNlcyBhbiBPVFBBdXRoIFVSSS5cbiAgICAgKlxuICAgICAqIFBhcnNlcyBhbiBVUkwgYXMgZGVzY3JpYmVkIGluIEdvb2dsZSBBdXRoZW50aWNhdG9yJ3MgXCJLZXlVcmlGb3JtYXRcIiBkb2N1bWVudCAoc2VlOlxuICAgICAqIFtodHRwczovL2NvZGUuZ29vZ2xlLmNvbS9wL2dvb2dsZS1hdXRoZW50aWNhdG9yL3dpa2kvS2V5VXJpRm9ybWF0XShodHRwczovL2NvZGUuZ29vZ2xlLmNvbS9wL2dvb2dsZS1hdXRoZW50aWNhdG9yL3dpa2kvS2V5VXJpRm9ybWF0KSlcbiAgICAgKiBhbmQgcmV0dXJucyBhbiBvYmplY3QgdGhhdCBjb250YWlucyB0aGUgZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gICAgICpcbiAgICAgKiAtIGBhY2NvdW50YDogVGhlIGFjY291bnQgbmFtZS5cbiAgICAgKiAtIGBkaWdpdHNgOiBUaGUgbnVtYmVyIG9mIGRpZ2l0cyBvZiB0aGUgcmVzdWx0aW5nIE9UUC4gRGVmYXVsdCBpcyA2IChzaXgpLlxuICAgICAqIC0gYGtleWA6IFRoZSBzaGFyZWQga2V5IGluIEJhc2UzMiBlbmNvZGluZy5cbiAgICAgKiAtIGBpc3N1ZXJgOiBQcm92aWRlciBvciBzZXJ2aWNlIHRoaXMgYWNjb3VudCBpcyBhc3NvY2lhdGVkIHdpdGguIFRoZSBkZWZhdWx0IGlzIHRoZSBlbXB0eVxuICAgICAqICAgc3RyaW5nLlxuICAgICAqIC0gYHR5cGVgOiBFaXRoZXIgdGhlIHN0cmluZyBgaG90cGAgb3IgYHRvdHBgLlxuICAgICAqXG4gICAgICogT1RQIG9mIHR5cGUgYGhvdHBgIGhhdmUgYW4gYWRkaXRpb25hbCBgY291bnRlcmAgZmllbGQgd2hpY2ggY29udGFpbnMgdGhlIHN0YXJ0IHZhbHVlIGZvciB0aGVcbiAgICAgKiBIT1RQIGNvdW50ZXIuIEluIGFsbCBvdGhlciBjYXNlcyB0aGlzIGZpZWxkIGlzIG1pc3NpbmcgZnJvbSB0aGUgcmVzdWx0aW5nIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEB0eXBlZGVmIHtPYmplY3R9IFJlc3VsdFxuICAgICAqIEBwcm9wIHtzdHJpbmd9IHR5cGVcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBhY2NvdW50XG4gICAgICogQHByb3Age3N0cmluZ30ga2V5XG4gICAgICogQHByb3Age3N0cmluZ30gW2lzc3Vlcl1cbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBkaWdpdHNcbiAgICAgKiBAcHJvcCB7c3RyaW5nfSBbYWxnb3JpdGhtXVxuICAgICAqIEBwcm9wIHtzdHJpbmd9IFtwZXJpb2RdXG4gICAgICogQHByb3Age3N0cmluZ30gW2NvdW50ZXJdXG4gICAgICogQHBhcmFtIHJhd1VybCB7c3RyaW5nfSBUaGUgVVJJIHRvIHBhcnNlLlxuICAgICAqIEByZXR1cm5zIHtSZXN1bHR9IEFuIG9iamVjdCB3aXRoIHByb3BlcnRpZXMgZGVzY3JpYmVkIGFib3ZlLlxuICAgICAqL1xuICAgIHBhcnNlOiBmdW5jdGlvbiBwYXJzZShyYXdVcmwpIHtcbiAgICAgICAgdmFyIHJldCA9IHt9O1xuXG4gICAgICAgIC8vXG4gICAgICAgIC8vIFByb3RvY29sXG4gICAgICAgIC8vXG5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHZhciBwYXJzZWQgPSBuZXcgVVJMKHJhd1VybCk7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnJvciBpbnN0YW5jZW9mIFR5cGVFcnJvciA/IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9QUk9UT0NPTCkgOiBlcnJvcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChwYXJzZWQucHJvdG9jb2wgIT09ICdvdHBhdXRoOicpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9QUk9UT0NPTCk7XG4gICAgICAgIH1cblxuICAgICAgICBwYXJzZWQucHJvdG9jb2wgPSAnaHR0cCc7XG4gICAgICAgIHBhcnNlZCA9IG5ldyBVUkwocGFyc2VkKTtcblxuICAgICAgICAvL1xuICAgICAgICAvLyBUeXBlXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIG90cEFsZ28gPSBkZWNvZGVVUklDb21wb25lbnQocGFyc2VkLmhvc3QpO1xuXG4gICAgICAgIGlmIChvdHBBbGdvICE9PSAnaG90cCcgJiYgb3RwQWxnbyAhPT0gJ3RvdHAnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLlVOS05PV05fT1RQKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldC50eXBlID0gb3RwQWxnbztcblxuICAgICAgICAvL1xuICAgICAgICAvLyBMYWJlbCAoY29udGFpbnMgYWNjb3VudCBuYW1lLCBtYXkgY29udGFpbiBpc3N1ZXIpXG4gICAgICAgIC8vXG5cbiAgICAgICAgdmFyIGxhYmVsID0gZGVjb2RlVVJJQ29tcG9uZW50KHBhcnNlZC5wYXRobmFtZS5zdWJzdHJpbmcoMSkpO1xuICAgICAgICB2YXIgbGFiZWxDb21wb25lbnRzID0gbGFiZWwuc3BsaXQoJzonKTtcbiAgICAgICAgdmFyIGlzc3VlciA9ICcnO1xuICAgICAgICB2YXIgYWNjb3VudCA9ICcnO1xuXG4gICAgICAgIGlmIChsYWJlbENvbXBvbmVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgICBhY2NvdW50ID0gbGFiZWxDb21wb25lbnRzWzBdO1xuICAgICAgICB9IGVsc2UgaWYgKGxhYmVsQ29tcG9uZW50cy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIGlzc3VlciA9IGxhYmVsQ29tcG9uZW50c1swXTtcbiAgICAgICAgICAgIGFjY291bnQgPSBsYWJlbENvbXBvbmVudHNbMV07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgT3RwYXV0aEludmFsaWRVUkwoRXJyb3JUeXBlLklOVkFMSURfTEFCRUwpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGFjY291bnQubGVuZ3RoIDwgMSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX0FDQ09VTlRfTkFNRSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoKGxhYmVsQ29tcG9uZW50cy5sZW5ndGggPT09IDIpICYmIChpc3N1ZXIubGVuZ3RoIDwgMSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9JU1NVRVIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0LmFjY291bnQgPSBhY2NvdW50O1xuXG4gICAgICAgIC8vXG4gICAgICAgIC8vIFBhcmFtZXRlcnNcbiAgICAgICAgLy9cblxuICAgICAgICB2YXIgcGFyYW1ldGVycyA9IHBhcnNlZC5zZWFyY2hQYXJhbXM7XG5cbiAgICAgICAgLy8gU2VjcmV0IGtleVxuICAgICAgICBpZiAoIXBhcmFtZXRlcnMuaGFzKCdzZWNyZXQnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX1NFQ1JFVF9LRVkpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0LmtleSA9IHBhcmFtZXRlcnMuZ2V0KCdzZWNyZXQnKTtcblxuICAgICAgICAvLyBJc3N1ZXJcbiAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdpc3N1ZXInKSAmJiBpc3N1ZXIgJiYgKHBhcmFtZXRlcnMuZ2V0KCdpc3N1ZXInKSAhPT0gaXNzdWVyKSkge1xuICAgICAgICAgICAgLy8gSWYgcHJlc2VudCwgaXQgbXVzdCBiZSBlcXVhbCB0byB0aGUgXCJpc3N1ZXJcIiBzcGVjaWZpZWQgaW4gdGhlIGxhYmVsLlxuICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5JTlZBTElEX0lTU1VFUik7XG4gICAgICAgIH1cblxuICAgICAgICByZXQuaXNzdWVyID0gaXNzdWVyIHx8IHBhcmFtZXRlcnMuZ2V0KCdpc3N1ZXInKSB8fCAnJztcblxuICAgICAgICAvLyBPVFAgZGlnaXRzXG4gICAgICAgIHJldC5kaWdpdHMgPSA2OyAgLy8gRGVmYXVsdCBpcyA2XG5cbiAgICAgICAgaWYgKHBhcmFtZXRlcnMuaGFzKCdkaWdpdHMnKSkge1xuICAgICAgICAgICAgdmFyIHBhcnNlZERpZ2l0cyA9IHBhcnNlSW50KHBhcmFtZXRlcnMuZ2V0KCdkaWdpdHMnKSwgMTApO1xuICAgICAgICAgICAgaWYgKFBvc3NpYmxlRGlnaXRzLmluZGV4T2YocGFyc2VkRGlnaXRzKSA9PSAtMSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBPdHBhdXRoSW52YWxpZFVSTChFcnJvclR5cGUuSU5WQUxJRF9ESUdJVFMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXQuZGlnaXRzID0gcGFyc2VkRGlnaXRzO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gQWxnb3JpdGhtIHRvIGNyZWF0ZSBoYXNoXG4gICAgICAgIGlmIChwYXJhbWV0ZXJzLmhhcygnYWxnb3JpdGhtJykpIHtcbiAgICAgICAgICAgIGlmIChQb3NzaWJsZUFsZ29yaXRobXMuaW5kZXhPZihwYXJhbWV0ZXJzLmdldCgnYWxnb3JpdGhtJykpID09IC0xKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5VTktOT1dOX0FMR09SSVRITSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsICdhbGdvcml0aG0nIHBhcmFtZXRlci5cbiAgICAgICAgICAgICAgICByZXQuYWxnb3JpdGhtID0gcGFyYW1ldGVycy5nZXQoJ2FsZ29yaXRobScpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gUGVyaW9kIChvbmx5IGZvciBUT1RQKVxuICAgICAgICBpZiAob3RwQWxnbyA9PT0gJ3RvdHAnKSB7XG4gICAgICAgICAgICAvLyBPcHRpb25hbCAncGVyaW9kJyBwYXJhbWV0ZXIgZm9yIFRPVFAuXG4gICAgICAgICAgICBpZiAocGFyYW1ldGVycy5oYXMoJ3BlcmlvZCcpKSB7XG4gICAgICAgICAgICAgICAgcmV0LnBlcmlvZCA9IHBhcnNlRmxvYXQocGFyYW1ldGVycy5nZXQoJ3BlcmlvZCcpKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENvdW50ZXIgKG9ubHkgZm9yIEhPVFApXG4gICAgICAgIGlmIChvdHBBbGdvID09PSAnaG90cCcpIHtcbiAgICAgICAgICAgIGlmICghcGFyYW1ldGVycy5oYXMoJ2NvdW50ZXInKSkge1xuICAgICAgICAgICAgICAgIC8vIFdlIHJlcXVpcmUgdGhlICdjb3VudGVyJyBwYXJhbWV0ZXIgZm9yIEhPVFAuXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IE90cGF1dGhJbnZhbGlkVVJMKEVycm9yVHlwZS5NSVNTSU5HX0NPVU5URVIpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXQuY291bnRlciA9IHBhcnNlSW50KHBhcmFtZXRlcnMuZ2V0KCdjb3VudGVyJyksIDEwKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiByZXQ7XG4gICAgfSxcblxuICAgIC8qKlxuICAgICAqIEVudW1lcmF0aW9uIG9mIGFsbCBlcnJvciB0eXBlcyByYWlzZWQgYnkgYE90cGF1dGhJbnZhbGlkVVJMYC5cbiAgICAgKi9cbiAgICBFcnJvclR5cGU6IEVycm9yVHlwZSxcblxuICAgIC8qKlxuICAgICAqIEV4Y2VwdGlvbiB0aHJvd24gd2hlbmV2ZXIgdGhlcmUncyBhbiBlcnJvciBkZWNvbnN0cnVjdGluZyBhbiAnb3RwYXV0aDovLycgVVJJLlxuICAgICAqXG4gICAgICogWW91IGNhbiBxdWVyeSB0aGUgYGVycm9yVHlwZWAgYXR0cmlidXRlIHRvIG9idGFpbiB0aGUgZXhhY3QgcmVhc29uIGZvciBmYWlsdXJlLiBUaGVcbiAgICAgKiBgZXJyb3JUeXBlYCBhdHRyaWJ1dGVzIGNvbnRhaW5zIGEgdmFsdWUgZnJvbSB0aGUgYEVycm9yVHlwZWAgZW51bWVyYXRpb24uXG4gICAgICovXG4gICAgT3RwYXV0aEludmFsaWRVUkw6IE90cGF1dGhJbnZhbGlkVVJMXG59O1xuIl19
