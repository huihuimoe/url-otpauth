import * as ErrorType from './ErrorType'

/**
 * Exception thrown whenever there's an error deconstructing an 'otpauth://' URI.
 *
 * You can query the `errorType` attribute to obtain the exact reason for failure. The
 * `errorType` attributes contains a value from the `ErrorType` enumeration.
 */
class OtpauthInvalidURL extends Error {
    constructor(errorType) {
        super()
        this.name = 'OtpauthInvalidURL'
        this.errorType = errorType
        for (const type in ErrorType)
            if (ErrorType[type] === errorType)
                this.message =
                    'Given otpauth:// URL is invalid. (Error ' + type + ')'
    }
}

export { OtpauthInvalidURL }
