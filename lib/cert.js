var base64 = require('./base64')

exports.extractPubKey = extractPubKey
exports.extractSpkiFromX509 = extractSpkiFromX509

/**
 *
 * @param {Uint8Array} der
 * @param {number} idx
 * @param {number} expected
 */
function checkOctet(der, idx, expected) {
  var octet = der[idx]
  if (octet != expected) {
    throw new Error(
      `Error extracting public key, idx: [${idx}], octet: [${octet.toString(
        16,
      )}], expected: [${expected.toString(16)}]`,
    )
  }
}

// 30 0D 06 09 2A 86 48 86 F7  0D 01 01 01
// (30 SEQ) (09 length) (06 OID) (09 length) (1.2.840.113549.1.1.1) RSA encryption
function isRsaOid(der, idx) {
  if (
    der[idx + 0] === 0x30 &&
    der[idx + 1] === 0x0d &&
    der[idx + 2] === 0x06 &&
    der[idx + 3] === 0x09 &&
    der[idx + 4] === 0x2a &&
    der[idx + 5] === 0x86 &&
    der[idx + 6] === 0x48 &&
    der[idx + 7] === 0x86 &&
    der[idx + 8] === 0xf7 &&
    der[idx + 9] === 0x0d &&
    der[idx + 10] === 0x01 &&
    der[idx + 11] === 0x01 &&
    der[idx + 12] === 0x01
  ) {
    return true;
  }
  return false;
}



/**
 * https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
 * @param {Uint8Array} der
 * @returns {Uint8Array}
 */
function extractPubKey(der) {
  // skip through first two wrapper sequences
  // SEQUENCE
  checkOctet(der, 0, 0x30)
  checkOctet(der, 1, 0x82)
  // SEQUENCE
  checkOctet(der, 4, 0x30)
  checkOctet(der, 5, 0x82)

  var versionStart = 8
  var currentByte = versionStart

  var publicKeyStart = 0;
  var publicKeyLen = 0;
  while(currentByte < der.byteLength) {
    var dataOffset = 2; // + 2 (type, length byte)
    var length = der[currentByte + 1];

    // long form of the length
    if (length === 0x81) {
      dataOffset = 3;  // + 3 (type, length long, length byte)
      length = der[currentByte + 2];
    } else if (length === 0x82) {
      dataOffset = 4; // + 4 (type, length long, 2 length bytes)
      length = der[currentByte + 2] * 256 + der[currentByte + 3];
    } else if (length > 0x80) {
      throw new Error('Certificate is not supported by current implementation');
    }

    if (isRsaOid(der, currentByte + dataOffset)) {
      var view = new Uint8Array(der.buffer, currentByte, length + dataOffset)
      return new Uint8Array(view)
    }

    currentByte += length + dataOffset
  }

  throw new Error('Failed to extract RSA public key from the certificate');
}

/**
 *
 * @param {string} pem
 * @returns string
 */
function extractPemDataString(pem) {
  return pem
    .replace(
      /(\n\s)*-----(BEGIN|END) (CERTIFICATE|PUBLIC KEY|PRIVATE KEY|RSA PUBLIC KEY)-----(\n\s)*/g,
      '',
    )
    .replace(/(\n|\r)/g, '')
    .trim()
}

/**
 *
 * @param {string} x509pem
 * @returns {Uint8Array}
 */
function extractSpkiFromX509(x509pem) {
  const pemDataBase64 = extractPemDataString(x509pem);
  const x509Der = base64.decode(pemDataBase64);
  const spkiDer = extractPubKey(x509Der);
  return spkiDer;
}