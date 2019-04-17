import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import { terser } from 'rollup-plugin-terser'
const pkg = require('./package.json')

const banner = `/*!
* url-otpauth-ng v${pkg.version}
* https://github.com/huihuimoe/url-otpauth-ng
* Released under the MIT license
*/
`

const input = 'index.js'

const outputSettings = {
    banner,
    name: 'urlOtpauthNg',
    sourcemap: true,
    freeze: false
}

const plugins = [
    resolve({
        preferBuiltins: true
    }),
    commonjs()
]

export default [
    {
        input,
        output: {
            file: 'dist/url-otpauth-ng.min.js',
            format: 'umd',
            ...outputSettings
        },
        plugins: [...plugins, terser()]
    },
    {
        input,
        output: {
            file: 'dist/url-otpauth-ng.js',
            format: 'umd',
            ...outputSettings
        },
        plugins
    },
    {
        input,
        output: {
            file: 'dist/url-otpauth-ng.esm.min.mjs',
            format: 'esm',
            ...outputSettings
        },
        plugins: [...plugins, terser()]
    },
    {
        input,
        output: {
            file: 'dist/url-otpauth-ng.esm.mjs',
            format: 'esm',
            ...outputSettings
        },
        plugins
    }
]
