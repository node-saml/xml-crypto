import * as fs from "fs";
import * as utils from "../src/utils";
import { expect } from "chai";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Utils tests", function () {
  describe("derToPem", function () {
    it("will return a normalized PEM format when given an non-normalized PEM format", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");
      const nonNormalizedPem = `${pemAsArray[0]}\n${base64String}\n${
        pemAsArray[pemAsArray.length - 1]
      }`;

      expect(utils.derToPem(nonNormalizedPem)).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");

      expect(utils.derToPem(base64String, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will throw if the format is neither PEM nor DER", function () {
      expect(() => utils.derToPem("not a pem")).to.throw();
    });

    it("will return a normalized PEM format when given a DER Buffer", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const derBuffer = fs.readFileSync("./test/static/client_public.der");

      expect(utils.derToPem(derBuffer, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string with line breaks", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const base64String = fs.readFileSync("./test/static/client_public.der", "base64");

      expect(utils.derToPem(base64String, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string with line breaks and spaces at the line breaks", function () {
      const xml = new xmldom.DOMParser().parseFromString(
        fs.readFileSync("./test/static/keyinfo - pretty-printed.xml", "latin1"),
      );
      const cert = xpath.select1(".//*[local-name(.)='X509Certificate']", xml);
      isDomNode.assertIsNodeLike(cert);

      const normalizedPem = fs.readFileSync("./test/static/keyinfo.pem", "latin1");

      expect(utils.derToPem(cert.textContent ?? "", "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will throw if the DER string is not base64 encoded", function () {
      expect(() => utils.derToPem("not base64", "CERTIFICATE")).to.throw();
    });

    it("will throw if the PEM label is not provided", function () {
      const derBuffer = fs.readFileSync("./test/static/client_public.der");
      expect(() => utils.derToPem(derBuffer)).to.throw();
    });
  });

  describe("pemToDer", function () {
    it("will return a Buffer of binary DER when given a normalized PEM format", function () {
      const pem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const derBuffer = fs.readFileSync("./test/static/client_public.der");

      const result = utils.pemToDer(pem);
      expect(result).to.be.instanceOf(Buffer);
      expect(result).to.deep.equal(derBuffer);
    });

    it("will throw if the format is not PEM", function () {
      expect(() => utils.pemToDer("not a pem")).to.throw();
    });
  });

  describe("findAttr", function () {
    it("should find attribute with no namespace when null is passed as namespace", function () {
      const xml =
        '<root testAttr="value" xmlns:ns="http://example.com" ns:testAttr="nsValue"></root>';
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const rootElement = doc.documentElement;

      const attr = utils.findAttr(rootElement, "testAttr", null);

      expect(attr).to.not.be.null;
      expect(attr?.value).to.equal("value");
      expect(attr?.namespaceURI).to.be.undefined;
    });

    it("should not find namespaced attribute when null is passed as namespace", function () {
      const xml = '<root xmlns:ns="http://example.com" ns:testAttr="nsValue"></root>';
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const rootElement = doc.documentElement;

      const attr = utils.findAttr(rootElement, "testAttr", null);

      expect(attr).to.be.null;
    });

    it("should find namespaced attribute when matching namespace is provided", function () {
      const xml = '<root xmlns:ns="http://example.com" ns:testAttr="nsValue"></root>';
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const rootElement = doc.documentElement;

      const attr = utils.findAttr(rootElement, "testAttr", "http://example.com");

      expect(attr).to.not.be.null;
      expect(attr?.value).to.equal("nsValue");
      expect(attr?.namespaceURI).to.equal("http://example.com");
    });

    it("should distinguish between namespaced and non-namespaced attributes with same localName", function () {
      const xml =
        '<root testAttr="noNsValue" xmlns:ns="http://example.com" ns:testAttr="nsValue"></root>';
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const rootElement = doc.documentElement;

      // Find the non-namespaced attribute
      const noNsAttr = utils.findAttr(rootElement, "testAttr", null);
      expect(noNsAttr).to.not.be.null;
      expect(noNsAttr?.value).to.equal("noNsValue");
      expect(noNsAttr?.namespaceURI).to.be.undefined;

      // Find the namespaced attribute
      const nsAttr = utils.findAttr(rootElement, "testAttr", "http://example.com");
      expect(nsAttr).to.not.be.null;
      expect(nsAttr?.value).to.equal("nsValue");
      expect(nsAttr?.namespaceURI).to.equal("http://example.com");
    });
  });
});
