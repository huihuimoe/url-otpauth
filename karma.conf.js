const resolve = require('rollup-plugin-node-resolve')
const commonjs = require('rollup-plugin-commonjs')
const builtins = require('rollup-plugin-node-builtins')
const globals = require('rollup-plugin-node-globals')

module.exports = function(config) {
    config.set({
        frameworks: ['mocha', 'chai'],
        files: ['test/test.js'],
        reporters: ['progress'],
        port: 9876,
        colors: true,
        logLevel: config.LOG_DEBUG,
        browsers: ['ChromeHeadless'],
        autoWatch: false,
        concurrency: Infinity,
        singleRun: true,
        preprocessors: {
            'test/test.js': ['rollup']
        },
        rollupPreprocessor: {
            plugins: [
                builtins(),
                resolve({
                    preferBuiltins: true
                }),
                commonjs(),
                globals()
            ],
            output: {
                format: 'iife',
                name: 'urlOtpauthNg',
                sourcemap: 'inline'
            }
        }
    })
}
