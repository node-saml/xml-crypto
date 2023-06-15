var expect = require("chai").expect;

var C14nCanonicalization = require("../lib/c14n-canonicalization").C14nCanonicalization;
var Dom = require("@xmldom/xmldom").DOMParser;
var select = require("xpath").select;
var findAncestorNs = require("../lib/signed-xml").SignedXml.findAncestorNs;

var test_C14nCanonicalization = function (xml, xpath, expected) {
  var doc = new Dom().parseFromString(xml);
  var elem = select(xpath, doc)[0];
  var can = new C14nCanonicalization();
  var result = can
    .process(elem, {
      ancestorNamespaces: findAncestorNs(doc, xpath),
    })
    .toString();

  expect(result).to.equal(expected);
};

var test_findAncestorNs = function (xml, xpath, expected) {
  var doc = new Dom().parseFromString(xml);
  var result = findAncestorNs(doc, xpath);

  expect(result).to.deep.equal(expected);
};

describe("C14N non-exclusive canonicalization tests", function () {
  it("findAncestorNs: Correctly picks up root ancestor namespace", function () {
    var xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up intermediate ancestor namespace", function () {
    var xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces declared in the one same element", function () {
    var xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [
      { prefix: "aaa", namespaceURI: "bbb" },
      { prefix: "ccc", namespaceURI: "ddd" },
    ];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces scattered among depth", function () {
    var xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [
      { prefix: "ccc", namespaceURI: "ddd" },
      { prefix: "aaa", namespaceURI: "bbb" },
    ];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces without duplicate", function () {
    var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "ccc", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly eliminates duplicate prefix", function () {
    var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "ccc", namespaceURI: "AAA" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Exclude namespace which is already declared with same prefix on target node", function () {
    var xml =
      "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Ignores namespace declared in the target xpath node", function () {
    var xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:ccc='ddd'></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  // Tests for c14nCanonicalization
  it("C14n: Correctly picks up root ancestor namespace", function () {
    var xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up intermediate ancestor namespace", function () {
    var xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces declared in the one same element", function () {
    var xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces scattered among depth", function () {
    var xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces without duplicate", function () {
    var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:ccc="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly eliminates duplicate prefix", function () {
    var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:ccc="AAA"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Exclude namespace which is already declared with same prefix on target node", function () {
    var xml =
      "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:ccc="AAA"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Preserve namespace declared in the target xpath node", function () {
    var xml = '<root xmlns:aaa="bbb"><child1><child2 xmlns:ccc="ddd"></child2></child1></root>';
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Don't redeclare an attribute's namespace prefix if already in scope", function () {
    var xml =
      "<root xmlns:aaa='bbb'><child1><child2 xmlns:aaa='bbb' aaa:foo='bar'></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb" aaa:foo="bar"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Don't declare an attribute's namespace prefix if in scope from parent", function () {
    var xml =
      "<root xmlns:aaa='bbb'><child1><child2><child3 aaa:foo='bar'></child3></child2></child1></root>";
    var xpath = "/root/child1";
    var expected =
      '<child1 xmlns:aaa="bbb"><child2><child3 aaa:foo="bar"></child3></child2></child1>';

    test_C14nCanonicalization(xml, xpath, expected);
  });
});
