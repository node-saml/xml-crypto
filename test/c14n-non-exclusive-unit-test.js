var C14nCanonicalization = require("../lib/c14n-canonicalization").C14nCanonicalization,
  Dom = require("@xmldom/xmldom").DOMParser,
  select = require("xpath").select,
  findAncestorNs = require("../lib/signed-xml").SignedXml.findAncestorNs;

var test_C14nCanonicalization = function (test, xml, xpath, expected) {
  var doc = new Dom().parseFromString(xml);
  var elem = select(xpath, doc)[0];
  var can = new C14nCanonicalization();
  var result = can
    .process(elem, {
      ancestorNamespaces: findAncestorNs(doc, xpath),
    })
    .toString();

  test.equal(result, expected);
  test.done();
};

var test_findAncestorNs = function (test, xml, xpath, expected) {
  var doc = new Dom().parseFromString(xml);
  var result = findAncestorNs(doc, xpath);
  test.deepEqual(result, expected);

  test.done();
};

// Tests for findAncestorNs
exports["findAncestorNs: Correctly picks up root ancestor namespace"] = function (test) {
  var xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports["findAncestorNs: Correctly picks up intermediate ancestor namespace"] = function (test) {
  var xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports[
  "findAncestorNs: Correctly picks up multiple ancestor namespaces declared in the one same element"
] = function (test) {
  var xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [
    { prefix: "aaa", namespaceURI: "bbb" },
    { prefix: "ccc", namespaceURI: "ddd" },
  ];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports["findAncestorNs: Correctly picks up multiple ancestor namespaces scattered among depth"] =
  function (test) {
    var xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [
      { prefix: "ccc", namespaceURI: "ddd" },
      { prefix: "aaa", namespaceURI: "bbb" },
    ];

    test_findAncestorNs(test, xml, xpath, expected);
  };

exports["findAncestorNs: Correctly picks up multiple ancestor namespaces without duplicate"] =
  function (test) {
    var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = [{ prefix: "ccc", namespaceURI: "bbb" }];

    test_findAncestorNs(test, xml, xpath, expected);
  };

exports["findAncestorNs: Correctly eliminates duplicate prefix"] = function (test) {
  var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [{ prefix: "ccc", namespaceURI: "AAA" }];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports[
  "findAncestorNs: Exclude namespace which is already declared with same prefix on target node"
] = function (test) {
  var xml =
    "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports["findAncestorNs: Should not find namespace when both has no prefix"] = function (test) {
  var xml = "<root xmlns='bbb'><child1><child2 xmlns='ddd'></child2></child1></root>";
  var xpath = "//*[local-name()='child2']";
  var expected = [];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports["findAncestorNs: Should find namespace without prefix"] = function (test) {
  var xml =
    "<root xmlns='bbb'><child1><ds:child2 xmlns:ds='ddd'><ds:child3></ds:child3></ds:child2></child1></root>";
  var xpath = "//*[local-name()='child2']";
  var expected = [{ prefix: "", namespaceURI: "bbb" }];

  test_findAncestorNs(test, xml, xpath, expected);
};

exports["findAncestorNs: Ignores namespace declared in the target xpath node"] = function (test) {
  var xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:ccc='ddd'></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

  test_findAncestorNs(test, xml, xpath, expected);
};

// Tests for c14nCanonicalization
exports["C14n: Correctly picks up root ancestor namespace"] = function (test) {
  var xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:aaa="bbb"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Correctly picks up intermediate ancestor namespace"] = function (test) {
  var xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:aaa="bbb"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Correctly picks up multiple ancestor namespaces declared in the one same element"] =
  function (test) {
    var xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(test, xml, xpath, expected);
  };

exports["C14n: Correctly picks up multiple ancestor namespaces scattered among depth"] = function (
  test
) {
  var xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Correctly picks up multiple ancestor namespaces without duplicate"] = function (
  test
) {
  var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:ccc="bbb"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Correctly eliminates duplicate prefix"] = function (test) {
  var xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:ccc="AAA"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Exclude namespace which is already declared with same prefix on target node"] =
  function (test) {
    var xml =
      "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
    var xpath = "/root/child1/child2";
    var expected = '<child2 xmlns:ccc="AAA"></child2>';

    test_C14nCanonicalization(test, xml, xpath, expected);
  };

exports["C14n: Preserve namespace declared in the target xpath node"] = function (test) {
  var xml = '<root xmlns:aaa="bbb"><child1><child2 xmlns:ccc="ddd"></child2></child1></root>';
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Don't redeclare an attribute's namespace prefix if already in scope"] = function (
  test
) {
  var xml =
    "<root xmlns:aaa='bbb'><child1><child2 xmlns:aaa='bbb' aaa:foo='bar'></child2></child1></root>";
  var xpath = "/root/child1/child2";
  var expected = '<child2 xmlns:aaa="bbb" aaa:foo="bar"></child2>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: Don't declare an attribute's namespace prefix if in scope from parent"] = function (
  test
) {
  var xml =
    "<root xmlns:aaa='bbb'><child1><child2><child3 aaa:foo='bar'></child3></child2></child1></root>";
  var xpath = "/root/child1";
  var expected =
    '<child1 xmlns:aaa="bbb"><child2><child3 aaa:foo="bar"></child3></child2></child1>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};

exports["C14n: should not has colon when parent namespace has no prefix"] = function (test) {
  var xml =
    "<root xmlns='bbb'><child1><cc:child2 xmlns:cc='ddd'><cc:child3></cc:child3></cc:child2></child1></root>";
  var xpath = "//*[local-name()='child3']";
  var expected = '<cc:child3 xmlns="bbb" xmlns:cc="ddd"></cc:child3>';

  test_C14nCanonicalization(test, xml, xpath, expected);
};
