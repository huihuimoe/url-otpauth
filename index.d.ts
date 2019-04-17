export interface IOtpParseResult {
    type: 'totp' | 'hotp' | 'yaotp'
    account: string
    key: string
    issuer: string
    digits: 6 | 8
    algorithm?: 'SHA1' | 'SHA256' | 'SHA512' | 'MD5'
    period?: number
    counter?: number
}

type URLLike = string | URL

export function parse(url: URLLike): IOtpParseResult

type ErrorTypeKey =
    | 'INVALID_ISSUER'
    | 'INVALID_LABEL'
    | 'INVALID_PROTOCOL'
    | 'MISSING_ACCOUNT_NAME'
    | 'MISSING_COUNTER'
    | 'MISSING_ISSUER'
    | 'MISSING_SECRET_KEY'
    | 'UNKNOWN_OTP'
    | 'INVALID_DIGITS'
    | 'UNKNOWN_ALGORITHM'

export type ErrorType = { [K in ErrorTypeKey]: number }

export const ErrorType: ErrorType

export class OtpauthInvalidURL extends Error {
    constructor(errorType: number)
    errorType: number
}

interface UrlOtpauthNg {
    parse: typeof parse
    ErrorType: ErrorType
    OtpauthInvalidURL: typeof OtpauthInvalidURL
}

declare const urlOtpauthNg: UrlOtpauthNg
