import * as ErrorType from './ErrorType'
import { OtpauthInvalidURL } from './OtpauthInvalidURL'

const _URL = typeof URL !== 'undefined' ? URL : require('url').URL

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
    const decode = decodeURIComponent
    const ret = {}

    //
    // Protocol
    //
    let parsed

    try {
        parsed = new _URL(rawUrl)
    } catch (e) {
        throw new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL)
    }

    if (parsed.protocol !== 'otpauth:') {
        throw new OtpauthInvalidURL(ErrorType.INVALID_PROTOCOL)
    }

    // hack for Chrome
    parsed.protocol = 'http'
    parsed = new _URL(parsed)

    //
    // Type
    //

    const otpAlgo = decode(parsed.host)

    if (otpAlgo !== 'hotp' && otpAlgo !== 'totp') {
        throw new OtpauthInvalidURL(ErrorType.UNKNOWN_OTP)
    }

    ret.type = otpAlgo

    //
    // Label (contains account name, may contain issuer)
    //

    const label = parsed.pathname.substring(1)
    const labelComponents = label.split(~label.indexOf(':') ? ':' : '%3A')
    let issuer = ''
    let account = ''

    if (labelComponents.length === 1) {
        account = decode(labelComponents[0])
    } else if (labelComponents.length === 2) {
        issuer = decode(labelComponents[0])
        account = decode(labelComponents[1])
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

    ret.issuer = parameters.get('issuer') || issuer

    // OTP digits
    ret.digits = 6 // Default is 6

    if (parameters.has('digits')) {
        const parsedDigits = parseInt(parameters.get('digits'))
        if (~PossibleDigits.indexOf(parsedDigits)) {
            ret.digits = parsedDigits
        } else {
            throw new OtpauthInvalidURL(ErrorType.INVALID_DIGITS)
        }
    }

    // Algorithm to create hash
    if (parameters.has('algorithm')) {
        if (~PossibleAlgorithms.indexOf(parameters.get('algorithm'))) {
            // Optional 'algorithm' parameter.
            ret.algorithm = parameters.get('algorithm')
        } else {
            throw new OtpauthInvalidURL(ErrorType.UNKNOWN_ALGORITHM)
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
            ret.counter = parseInt(parameters.get('counter'))
        }
    }

    return ret
}
