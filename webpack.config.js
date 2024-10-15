const path = require("path");
const webpack = require("webpack");
const TerserPlugin = require("terser-webpack-plugin");

const isProduction = process.env.NODE_ENV === 'production';

const generalConfig = {
  devtool: isProduction ? false : "source-map",
  mode: isProduction ? "production" : "development",
  optimization: {
    minimize: isProduction,
    splitChunks: false,
    minimizer: [
      new TerserPlugin({
        extractComments: false,
      }),
    ],
  },
};

module.exports = [
  // CommonJS build for Node.js
  {
    target: "node",
    entry: "./index.js",
    output: {
      path: path.resolve(__dirname, "dist"),
      filename: "recheck-node.js",
      libraryTarget: "commonjs2",
    },
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: {
            loader: "babel-loader",
            options: {
              presets: ["@babel/preset-env"],
            },
          },
        },
      ],
    },
    externals: {
      eccrypto: "commonjs eccrypto", // Exclude eccrypto from bundling
    },
    ...generalConfig,
  },

  // ESM build for the browser
  {
    entry: "./bundle.js",
    output: {
      path: path.resolve(__dirname, "dist"),
      filename: "recheck-web-client.js",
      libraryTarget: "umd",
      globalObject: 'this',
    },
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: {
            loader: "babel-loader",
            options: {
              presets: ["@babel/preset-env"],
            },
          },
        },
        {
          test: /\.wasm$/,
          type: "webassembly/async",
        },
      ],
    },
    resolve: {
      fallback: {
        fs: false,
        path: require.resolve("path-browserify"),
        crypto: require.resolve("crypto-browserify"),
        stream: require.resolve("stream-browserify"),
        process: require.resolve("process/browser"),
        buffer: require.resolve("buffer"),
      },
      alias: {
        '@concordium/rust-bindings': '@concordium/rust-bindings/bundler',
      }
    },
    experiments: {
      asyncWebAssembly: true,
    },
    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ["buffer", "Buffer"],
        process: "process/browser",
      }),
    ],
    externals: {
      '@concordium/web-sdk': '@concordium/web-sdk',
      '@concordium/rust-bindings': '@concordium/rust-bindings',
    },
    ...generalConfig,
  },
];
