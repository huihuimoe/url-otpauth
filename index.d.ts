export interface otpResult {
    type: string
    account: string
    key: string
    issuer?: string
    digits: string
    algorithm?: string
    period?: string
    counter?: string
}

export type URLLike = string | URL

declare const urlOtpauth = {
    parse(url: URLLike): otpResult
}

export = urlOtpauth
