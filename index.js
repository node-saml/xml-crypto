var select = require("xpath").select;

module.exports = require("./lib/signed-xml");
module.exports.C14nCanonicalization = require("./lib/c14n-canonicalization").C14nCanonicalization;
module.exports.C14nCanonicalizationWithComments = require("./lib/c14n-canonicalization").C14nCanonicalizationWithComments;
module.exports.ExclusiveCanonicalization = require("./lib/exclusive-canonicalization").ExclusiveCanonicalization;
module.exports.ExclusiveCanonicalizationWithComments = require("./lib/exclusive-canonicalization").ExclusiveCanonicalizationWithComments;
module.exports.xpath = function (node, xpath) {
  return select(xpath, node);
};
