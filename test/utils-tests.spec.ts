import * as crypto from "crypto";
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

    for (const eol of ["\r\n", "\r"]) {
      it(`will return a normalized PEM format when given a PEM with ${JSON.stringify(eol)} line endings`, function () {
        const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");

        expect(utils.derToPem(normalizedPem.replace(/\n/g, eol))).to.equal(normalizedPem);
      });
    }

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

    describe("judges the same data with and without encapsulation boundaries", function () {
      const wrap = (data: string) =>
        `-----BEGIN CERTIFICATE-----\n${data}\n-----END CERTIFICATE-----`;

      const accepted = {
        "a whole quantum": "QUJD",
        "a quantum padded to two characters": "QUJDRQ==",
        "a quantum padded to three characters": "QUJDREU=",
        "a line break between quanta": "QUJD\nREVG",
        "a line break anywhere in the data": "QU\nJDRE\nVG",
        "blanks in the data": " QU JD\tREVG ",
      };

      const rejected = {
        "a lone character": "A",
        "two characters with no pad": "AA",
        "three characters with no pad": "AAA",
        "a character and a pad": "A=",
        "three characters and two pads": "AAA==",
        "a whole quantum and a pad": "AAAA=",
        "a quantum and one character": "AAAAA",
        "a whole quantum and two pads": "AAAA==",
        "a pad in the middle of the data": "QUJD=REVG",
        "a character outside the base64 alphabet": "QU-JD",
        "nothing at all": "",
        "only blanks": "    ",
      };

      Object.entries(accepted).forEach(([description, data]) => {
        it(`accepts ${description} either way, and reads the same certificate`, function () {
          expect(utils.derToPem(wrap(data))).to.equal(utils.derToPem(data, "CERTIFICATE"));
        });
      });

      Object.entries(rejected).forEach(([description, data]) => {
        it(`rejects ${description} either way, for the same reason`, function () {
          expect(() => utils.derToPem(wrap(data), "CERTIFICATE")).to.throw("Unknown DER format.");
          expect(() => utils.derToPem(data, "CERTIFICATE")).to.throw("Unknown DER format.");
        });
      });
    });

    describe("accepts what common tooling produces", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const lines = normalizedPem.trim().split("\n");
      const body = lines.slice(1, -1);
      const rebuild = (bodyLines: string[]) =>
        [lines[0], ...bodyLines, lines[lines.length - 1]].join("\n");

      it("blanks at the ends of lines", function () {
        expect(utils.derToPem(rebuild(body.map((line) => `${line}  `)))).to.equal(normalizedPem);
      });

      it("a pretty-printer's indentation", function () {
        expect(utils.derToPem(rebuild(body.map((line) => `    ${line}`)))).to.equal(normalizedPem);
      });

      it("a line ending replaced by a space", function () {
        expect(utils.derToPem(rebuild([body.join(" ")]))).to.equal(normalizedPem);
      });

      for (const [name, eol] of [
        ["CRLF", "\r\n"],
        ["CR", "\r"],
      ] as const) {
        it(`${name} line endings, with and without boundaries`, function () {
          const bare = body.join("\n").replace(/\n/g, eol);

          expect(utils.derToPem(bare, "CERTIFICATE")).to.equal(normalizedPem);
          expect(utils.derToPem(rebuild(body).replace(/\n/g, eol))).to.equal(normalizedPem);
        });
      }

      it("a blank line between concatenated messages", function () {
        const pair = `${normalizedPem}\n\n${normalizedPem}`;

        expect(utils.derToPem(pair)).to.equal(`${normalizedPem}${normalizedPem}`);
      });

      it("a blank line after the header", function () {
        expect(utils.derToPem(rebuild(["", ...body]))).to.equal(normalizedPem);
      });

      it("a line width other than 64", function () {
        const rewrapped = body.join("").match(/.{1,70}/g) ?? [];

        expect(utils.derToPem(rebuild(rewrapped))).to.equal(normalizedPem);
      });

      it("a UTF-8 BOM, as decoded text", function () {
        expect(utils.derToPem(`\uFEFF${normalizedPem}`)).to.equal(normalizedPem);
      });

      it("a UTF-8 BOM, as the bytes a latin1 read gives", function () {
        const withBom = Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          Buffer.from(normalizedPem, "latin1"),
        ]);

        expect(utils.derToPem(withBom.toString("latin1"))).to.equal(normalizedPem);
      });

      it("several certificates in one value", function () {
        const bundle = fs.readFileSync("./test/static/client_bundle.pem", "latin1");

        expect(utils.derToPem(bundle).match(/-----BEGIN CERTIFICATE-----/g)).to.have.lengthOf(2);
      });

      it("and hands OpenSSL something it can load", function () {
        // Blanks after an encapsulation boundary are the 'preeb *WSP eol' of RFC 7468 Figure 1,
        // and OpenSSL will not read a certificate that carries them.
        const untidy = rebuild(body)
          .split("\n")
          .map((line) => `${line}  `)
          .join("\r\n");

        expect(() => crypto.createPublicKey(utils.derToPem(untidy))).to.not.throw();
      });
    });

    describe("rejects data that is not base64", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const lines = normalizedPem.trim().split("\n");
      const corrupt = (body: string) => [lines[0], body, lines[lines.length - 1]].join("\n");

      it("a body that is not base64 at all", function () {
        expect(() => utils.derToPem(corrupt("not base64 at all!"))).to.throw("Unknown DER format.");
      });

      it("a body that is one long run of blanks", function () {
        expect(() => utils.derToPem(corrupt(" ".repeat(80000)))).to.throw("Unknown DER format.");
      });

      it("a body with a blank line in the middle of the data", function () {
        const body = lines.slice(1, -1);
        const interrupted = [...body.slice(0, 2), "", ...body.slice(2)].join("\n");

        expect(() => utils.derToPem(corrupt(interrupted))).to.throw("Unknown DER format.");
      });

      it("a message whose two labels disagree", function () {
        const mismatched = normalizedPem.replace("-----END CERTIFICATE-----", "-----END KEY-----");

        expect(() => utils.derToPem(mismatched)).to.throw("Unknown DER format.");
      });

      it("a body whose final quantum is incomplete", function () {
        expect(() => utils.derToPem(corrupt(`${lines.slice(1, -1).join("\n")}A`))).to.throw(
          "Unknown DER format.",
        );
      });
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

    it("will throw if the encapsulated data is not base64", function () {
      const pem = fs.readFileSync("./test/static/client_public.pem", "latin1").trim().split("\n");
      const corrupt = [pem[0], "not base64 at all!", pem[pem.length - 1]].join("\n");

      expect(() => utils.pemToDer(corrupt)).to.throw("Invalid PEM format.");
    });

    it("will throw if the value holds more than one PEM message", function () {
      const bundle = fs.readFileSync("./test/static/client_bundle.pem", "latin1");

      expect(() => utils.pemToDer(bundle)).to.throw("Expected a single PEM message, but found 3.");
    });
  });
});
