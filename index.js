/*!
 * https://github.com/huihuimoe/url-otpauth-ng
 * Released under the MIT license
 */

const _URL = typeof URL !== 'undefined' ? URL : require('url').URL

//
// Exception types
//

/**
 * Enumeration of all error types raised by `OtpauthInvalidURL`.
 */
export const ErrorType = {
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
}

/**
 * Exception thrown whenever there's an error deconstructing an 'otpauth://' URI.
 *
 * You can query the `errorType` attribute to obtain the exact reason for failure. The
 * `errorType` attributes contains a value from the `ErrorType` enumeration.
 */
export function OtpauthInvalidURL(errorType) {
    this.name = 'OtpauthInvalidURL'
    this.message = 'Given otpauth:// URL is invalid. (Error ' + errorType + ')'
    this.errorType = errorType
}
OtpauthInvalidURL.prototype = new Error()
OtpauthInvalidURL.prototype.constructor = OtpauthInvalidURL

const PossibleDigits = [6, 8]
const PossibleAlgorithms = ['SHA1', 'SHA256', 'SHA512', 'MD5']

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
export function parse(rawUrl) {
    const ret = {}

    //
    // Protocol
    //
    let parsed

    try {
        parsed = new _URL(rawUrl)
    } catch (error) {
        throw error instanceof TypeError
            ? new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL)
            : error
    }

    if (parsed.protocol !== 'otpauth:') {
        throw new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL)
    }

    parsed.protocol = 'http'
    parsed = new _URL(parsed)

    //
    // Type
    //

    const otpAlgo = decodeURIComponent(parsed.host)

    if (otpAlgo !== 'hotp' && otpAlgo !== 'totp') {
        throw new OtpauthInvalidURL(ErrorType.UNKNOWN_OTP)
    }

    ret.type = otpAlgo

    //
    // Label (contains account name, may contain issuer)
    //

    const label = parsed.pathname.substring(1)
    const labelComponents = label.split(':')
    let issuer = ''
    let account = ''

    if (labelComponents.length === 1) {
        account = decodeURIComponent(labelComponents[0])
    } else if (labelComponents.length === 2) {
        issuer = decodeURIComponent(labelComponents[0])
        account = decodeURIComponent(labelComponents[1])
    } else {
        throw new OtpauthInvalidURL(ErrorType.INVALID_LABEL)
    }

    if (account.length < 1) {
        throw new OtpauthInvalidURL(ErrorType.MISSING_ACCOUNT_NAME)
    }

    if (labelComponents.length === 2 && issuer.length < 1) {
        throw new OtpauthInvalidURL(ErrorType.INVALID_ISSUER)
    }

    ret.account = account

    //
    // Parameters
    //

    const parameters = parsed.searchParams

    // Secret key
    if (!parameters.has('secret')) {
        throw new OtpauthInvalidURL(ErrorType.MISSING_SECRET_KEY)
    }

    ret.key = parameters.get('secret')

    // Issuer
    if (
        parameters.has('issuer') &&
        issuer &&
        parameters.get('issuer') !== issuer
    ) {
        // If present, it must be equal to the "issuer" specified in the label.
        throw new OtpauthInvalidURL(ErrorType.INVALID_ISSUER)
    }

    ret.issuer = issuer || parameters.get('issuer') || ''

    // OTP digits
    ret.digits = 6 // Default is 6

    if (parameters.has('digits')) {
        const parsedDigits = parseInt(parameters.get('digits'), 10)
        if (PossibleDigits.indexOf(parsedDigits) == -1) {
            throw new OtpauthInvalidURL(ErrorType.INVALID_DIGITS)
        } else {
            ret.digits = parsedDigits
        }
    }

    // Algorithm to create hash
    if (parameters.has('algorithm')) {
        if (PossibleAlgorithms.indexOf(parameters.get('algorithm')) == -1) {
            throw new OtpauthInvalidURL(ErrorType.UNKNOWN_ALGORITHM)
        } else {
            // Optional 'algorithm' parameter.
            ret.algorithm = parameters.get('algorithm')
        }
    }

    // Period (only for TOTP)
    if (otpAlgo === 'totp') {
        // Optional 'period' parameter for TOTP.
        if (parameters.has('period')) {
            ret.period = parseFloat(parameters.get('period'))
        }
    }

    // Counter (only for HOTP)
    if (otpAlgo === 'hotp') {
        if (!parameters.has('counter')) {
            // We require the 'counter' parameter for HOTP.
            throw new OtpauthInvalidURL(ErrorType.MISSING_COUNTER)
        } else {
            ret.counter = parseInt(parameters.get('counter'), 10)
        }
    }

    return ret
}
