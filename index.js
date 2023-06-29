const select = require("xpath").select;
const utils = require("./lib/utils");

module.exports = require("./lib/signed-xml");
module.exports.xpath = function (node, xpath) {
  return select(xpath, node);
};
module.exports.utils = utils;
