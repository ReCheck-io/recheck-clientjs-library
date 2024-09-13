const path = require("path");
const webpack = require("webpack");
const TerserPlugin = require("terser-webpack-plugin");

const generalConfig = {
  devtool: "source-map",
  mode: "development",
  optimization: {
    // minimize: true, // Enable minification
    minimizer: [
      new TerserPlugin({
        extractComments: false, // Disable license comments
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
    resolve: {
      fallback: {
        fs: false,
        path: require.resolve("path-browserify"),
        crypto: require.resolve("crypto-browserify"),
        stream: require.resolve("stream-browserify"),
        process: require.resolve("process/browser"),
        buffer: require.resolve("buffer"),
      },
    },
    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ["buffer", "Buffer"],
        process: "process/browser",
      }),
    ],
    ...generalConfig,
  },
];
