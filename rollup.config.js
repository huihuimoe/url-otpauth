import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import { terser } from 'rollup-plugin-terser'

export default [
    {
        input: 'index.js',
        output: {
            file: 'dist/url-otpauth-ng.min.js',
            format: 'umd',
            name: 'urlOtpauthNg',
            sourcemap: true,
            freeze: false
        },
        plugins: [
            resolve({
                preferBuiltins: true
            }),
            commonjs(),
            terser()
        ]
    },
    {
        input: 'index.js',
        output: {
            file: 'dist/url-otpauth-ng.js',
            format: 'umd',
            name: 'urlOtpauthNg',
            sourcemap: true,
            freeze: false
        },
        plugins: [
            resolve({
                preferBuiltins: true
            }),
            commonjs()
        ]
    },
    {
        input: 'index.js',
        output: {
            file: 'dist/url-otpauth-ng.esm.min.mjs',
            format: 'esm',
            sourcemap: true,
            freeze: false
        },
        plugins: [
            resolve({
                preferBuiltins: true
            }),
            commonjs(),
            terser()
        ]
    },
    {
        input: 'index.js',
        output: {
            file: 'dist/url-otpauth-ng.esm.mjs',
            format: 'esm',
            sourcemap: true,
            freeze: false
        },
        plugins: [
            resolve({
                preferBuiltins: true
            }),
            commonjs()
        ]
    }
]
