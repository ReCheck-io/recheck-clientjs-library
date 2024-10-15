// window.RECHECK = require('./index.js');

(function (root, factory) {
  if (typeof exports === 'object' && typeof module === 'object') {
    // CommonJS (Node.js)
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define([], factory);
  } else if (typeof exports === 'object') {
    // CommonJS-like environments that support module.exports
    exports.RECHECK = factory();
  } else {
    // Browser (global `window`)
    root.RECHECK = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  return require('./index.js'); // Export whatever is in index.js
});
