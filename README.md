# url-otpauth

[![Build Status](http://img.shields.io/travis/com/huihuimoe/url-otpauth-ng.svg?style=flat)](https://travis-ci.com/huihuimoe/url-otpauth-ng)
[![Coverage Status](http://img.shields.io/coveralls/huihuimoe/url-otpauth-ng.svg?style=flat)](https://coveralls.io/r/huihuimoe/url-otpauth-ng)
![version](https://img.shields.io/github/package-json/v/huihuimoe/url-otpauth-ng.svg)
[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

--------------------------------------------------------------------------------

This library can be used to parse `otpauth://` URIs used by Google Authenticator as defined in [this
wiki page](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). This is the same
format commonly used in QR Code for use with Google Authenticator.

## Usage

The package is available from NPM:

`npm install url-otpauth-ng`

In browser:

Using `<script src="//unpkg.com/url-otpauth-ng"></script>`

Or using esm:

```javascript
<script type="module">
  import { parse } from '//unpkg.com/url-otpauth-ng/dist/url-otpauth-ng.esm.mjs'
</script>
```
