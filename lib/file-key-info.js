var StringKeyInfo = require("./string-key-info"),
  fs = require("fs");

/**
 * A key info provider implementation
 *
 * @param {string} file path to public certificate
 */
function FileKeyInfo(file) {
  var key = fs.readFileSync(file);
  StringKeyInfo.apply(this, [key]);
}

FileKeyInfo.prototype = StringKeyInfo.prototype;
FileKeyInfo.prototype.constructor = FileKeyInfo;

module.exports = FileKeyInfo;
