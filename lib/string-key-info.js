/**
 * A basic string based implementation of a FileInfoProvider
 *
 * @param {string} key the string contents of a public certificate
 */
function StringKeyInfo(key) {
  this.key = key;
}

/**
 * Builds the contents of a KeyInfo element as an XML string.
 *
 * Currently, this returns exactly one empty X509Data element
 * (e.g. "<X509Data></X509Data>"). The resultant X509Data element will be
 * prefaced with a namespace alias if a value for the prefix argument
 * is provided. In example, if the value of the prefix argument is 'foo', then
 * the resultant XML string will be "<foo:X509Data></foo:X509Data>"
 *
 * @param key (not used) the signing/private key as a string
 * @param prefix an optional namespace alias to be used for the generated XML
 * @return an XML string representation of the contents of a KeyInfo element
 */
StringKeyInfo.prototype.getKeyInfo = function (key, prefix) {
  prefix = prefix || "";
  prefix = prefix ? prefix + ":" : prefix;
  return "<" + prefix + "X509Data></" + prefix + "X509Data>";
};

/**
 * Returns the value of the signing certificate based on the contents of the
 * specified KeyInfo.
 *
 * @param keyInfo (not used) an array with exactly one KeyInfo element
 * @return the signing certificate as a string
 */
StringKeyInfo.prototype.getKey = function (keyInfo) {
  return this.key;
};

module.exports = StringKeyInfo;
