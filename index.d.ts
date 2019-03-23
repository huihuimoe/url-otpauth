export interface IOtpParseResult {
    type: string
    account: string
    key: string
    issuer?: string
    digits: string
    algorithm?: string
    period?: string
    counter?: string
}

type URLLike = string | URL

export function parse(url: URLLike): IOtpParseResult

export enum ErrorType {
    INVALID_ISSUER = 0,
    INVALID_LABEL,
    INVALID_PROTOCOL,
    MISSING_ACCOUNT_NAME,
    MISSING_COUNTER,
    MISSING_ISSUER,
    MISSING_SECRET_KEY,
    UNKNOWN_OTP,
    INVALID_DIGITS,
    UNKNOWN_ALGORITHM
}

export class OtpauthInvalidURL extends Error {
    constructor(errorType: ErrorType)
}

interface UrlOtpauthNg {
    parse: typeof parse
    ErrorType: typeof ErrorType
    OtpauthInvalidURL: typeof OtpauthInvalidURL
}

declare const urlOtpauthNg: UrlOtpauthNg
