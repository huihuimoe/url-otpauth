/**
 * Enumeration of all error types raised by `OtpauthInvalidURL`.
 */

const INVALID_ISSUER = 0;
const INVALID_LABEL = 1;
const INVALID_PROTOCOL = 2;
const MISSING_ACCOUNT_NAME = 3;
const MISSING_COUNTER = 4;
const MISSING_ISSUER = 5;
const MISSING_SECRET_KEY = 6;
const UNKNOWN_OTP = 7;
const INVALID_DIGITS = 8;
const UNKNOWN_ALGORITHM = 9;

var ErrorType = ({
    INVALID_ISSUER: INVALID_ISSUER,
    INVALID_LABEL: INVALID_LABEL,
    INVALID_PROTOCOL: INVALID_PROTOCOL,
    MISSING_ACCOUNT_NAME: MISSING_ACCOUNT_NAME,
    MISSING_COUNTER: MISSING_COUNTER,
    MISSING_ISSUER: MISSING_ISSUER,
    MISSING_SECRET_KEY: MISSING_SECRET_KEY,
    UNKNOWN_OTP: UNKNOWN_OTP,
    INVALID_DIGITS: INVALID_DIGITS,
    UNKNOWN_ALGORITHM: UNKNOWN_ALGORITHM
});

/**
 * Exception thrown whenever there's an error deconstructing an 'otpauth://' URI.
 *
 * You can query the `errorType` attribute to obtain the exact reason for failure. The
 * `errorType` attributes contains a value from the `ErrorType` enumeration.
 */
class OtpauthInvalidURL extends Error {
    constructor(errorType) {
        super();
        this.name = 'OtpauthInvalidURL';
        this.errorType = errorType;
        for (const type in ErrorType)
            if (ErrorType[type] === errorType)
                this.message =
                    'Given otpauth:// URL is invalid. (Error ' + type + ')';
    }
}

const _URL = typeof URL !== 'undefined' ? URL : require('url').URL;

const PossibleDigits = [6, 8];
const PossibleAlgorithms = ['SHA1', 'SHA256', 'SHA512', 'MD5'];

/**
 * Parses an OTPAuth URI.
 *
 * Parses an URL as described in Google Authenticator's "KeyUriFormat" document (see:
 * [https://github.com/google/google-authenticator/wiki/Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))
 * and returns an object that contains the following properties:
 *
 * - `account`: The account name.
 * - `digits`: The number of digits of the resulting OTP. Default is 6 (six).
 * - `key`: The shared key in Base32 encoding.
 * - `issuer`: Provider or service this account is associated with. The default is the empty string.
 * - `type`: Either the string `hotp` or `totp`.
 *
 * OTP of type `hotp` have an additional `counter` field which contains the start value for the
 * HOTP counter. In all other cases this field is missing from the resulting object.
 *
 **/
function parse(rawUrl) {
    const decode = decodeURIComponent;
    const ret = {};

    //
    // Protocol
    //
    let parsed = new _URL(rawUrl);

    if (parsed.protocol !== 'otpauth:') {
        throw new OtpauthInvalidURL(INVALID_PROTOCOL)
    }

    // hack for Chrome
    parsed.protocol = 'http';
    parsed = new _URL(parsed);

    //
    // Type
    //

    const otpAlgo = decode(parsed.host);

    if (otpAlgo !== 'hotp' && otpAlgo !== 'totp') {
        throw new OtpauthInvalidURL(UNKNOWN_OTP)
    }

    ret.type = otpAlgo;

    //
    // Label (contains account name, may contain issuer)
    //

    const label = parsed.pathname.substring(1);
    // if you want to support mutli commas in label
    // const labelComponents = label.split(~label.indexOf(':') ? /:(.*)/ : /%3A(.*)/, 2)
    const labelComponents = label.split(~label.indexOf(':') ? ':' : '%3A');
    let issuer = '';
    let account = '';

    if (labelComponents.length === 1) {
        account = decode(labelComponents[0]);
    } else if (labelComponents.length === 2) {
        issuer = decode(labelComponents[0]);
        account = decode(labelComponents[1]);
    } else {
        throw new OtpauthInvalidURL(INVALID_LABEL)
    }

    if (account.length < 1) {
        throw new OtpauthInvalidURL(MISSING_ACCOUNT_NAME)
    }

    if (labelComponents.length === 2 && issuer.length < 1) {
        throw new OtpauthInvalidURL(INVALID_ISSUER)
    }

    ret.account = account;

    //
    // Parameters
    //

    const parameters = parsed.searchParams;

    // Secret key
    if (!parameters.has('secret')) {
        throw new OtpauthInvalidURL(MISSING_SECRET_KEY)
    }

    ret.key = parameters.get('secret');

    // Issuer
    if (
        parameters.has('issuer') &&
        issuer &&
        parameters.get('issuer') !== issuer
    ) {
        // If present, it must be equal to the "issuer" specified in the label.
        throw new OtpauthInvalidURL(INVALID_ISSUER)
    }

    ret.issuer = parameters.get('issuer') || issuer;

    // OTP digits
    ret.digits = 6; // Default is 6

    if (parameters.has('digits')) {
        const parsedDigits = parseInt(parameters.get('digits')) || 0;
        if (~PossibleDigits.indexOf(parsedDigits)) {
            ret.digits = parsedDigits;
        } else {
            throw new OtpauthInvalidURL(INVALID_DIGITS)
        }
    }

    // Algorithm to create hash
    if (parameters.has('algorithm')) {
        if (~PossibleAlgorithms.indexOf(parameters.get('algorithm'))) {
            // Optional 'algorithm' parameter.
            ret.algorithm = parameters.get('algorithm');
        } else {
            throw new OtpauthInvalidURL(UNKNOWN_ALGORITHM)
        }
    }

    // Period (only for TOTP)
    if (otpAlgo === 'totp') {
        // Optional 'period' parameter for TOTP.
        if (parameters.has('period')) {
            ret.period = parseFloat(parameters.get('period')) || 0;
        }
    }

    // Counter (only for HOTP)
    if (otpAlgo === 'hotp') {
        if (parameters.has('counter')) {
            ret.counter = parseInt(parameters.get('counter')) || 0;
        } else {
            // We require the 'counter' parameter for HOTP.
            throw new OtpauthInvalidURL(MISSING_COUNTER)
        }
    }

    return ret
}

/*!
 * https://github.com/huihuimoe/url-otpauth-ng
 * Released under the MIT license
 */

export { ErrorType, OtpauthInvalidURL, parse };
//# sourceMappingURL=url-otpauth-ng.esm.mjs.map
