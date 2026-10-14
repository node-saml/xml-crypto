import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import { expect } from "chai";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const xml = "<root><a>trusted</a></root>";

const elsewhere = () => new Promise((resolve) => setImmediate(resolve));

class RemoteRsaSha256 implements SignatureAlgorithm {
  getAlgorithmName = () => RSA_SHA256;

  getSignature(): never {
    throw new Error("this algorithm signs only asynchronously");
  }

  verifySignature(): never {
    throw new Error("this algorithm verifies only asynchronously");
  }

  async getSignatureAsync(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike) {
    await elsewhere();
    return crypto.createSign("RSA-SHA256").update(signedInfo).sign(privateKey, "base64");
  }

  async verifySignatureAsync(material: string, key: crypto.KeyLike, signatureValue: string) {
    await elsewhere();
    return crypto.createVerify("RSA-SHA256").update(material).verify(key, signatureValue, "base64");
  }
}

function createSigner(algorithm?: new () => SignatureAlgorithm): SignedXml {
  const sig = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: EXCLUSIVE_C14N,
    signatureAlgorithm: RSA_SHA256,
  });
  if (algorithm) {
    sig.SignatureAlgorithms[RSA_SHA256] = algorithm;
  }
  sig.addReference({
    xpath: "/*",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", EXCLUSIVE_C14N],
  });
  return sig;
}

function createVerifier(signatureXml: string, algorithm?: new () => SignatureAlgorithm): SignedXml {
  const sig = new SignedXml({ publicCert: fs.readFileSync("./test/static/client_public.pem") });
  if (algorithm) {
    sig.SignatureAlgorithms[RSA_SHA256] = algorithm;
  }
  sig.loadSignature(signatureXml);
  return sig;
}

describe("computeSignatureAsync()", function () {
  function signedSynchronously(): string {
    const sig = createSigner();
    sig.computeSignature(xml);
    return sig.getSignedXml();
  }

  it("signs through the algorithm's getSignatureAsync()", async function () {
    const sig = createSigner(RemoteRsaSha256);

    await sig.computeSignatureAsync(xml);

    expect(sig.getSignedXml()).to.equal(signedSynchronously());
  });

  it("signs through getSignature() when the algorithm has no getSignatureAsync()", async function () {
    const sig = createSigner();

    await sig.computeSignatureAsync(xml);

    expect(sig.getSignedXml()).to.equal(signedSynchronously());
  });

  it("resolves with the instance", async function () {
    const sig = createSigner(RemoteRsaSha256);

    expect(await sig.computeSignatureAsync(xml)).to.equal(sig);
  });

  it("takes the options computeSignature() takes", async function () {
    const sig = createSigner(RemoteRsaSha256);

    await sig.computeSignatureAsync(xml, { prefix: "ds" });

    expect(sig.getSignatureXml()).to.match(/^<ds:Signature /);
  });

  it("rejects where computeSignature() throws", async function () {
    const sig = createSigner(RemoteRsaSha256);

    await assert.rejects(
      sig.computeSignatureAsync(xml, { location: { reference: "/missing", action: "append" } }),
      { message: "the following xpath cannot be used because it was not found: /missing" },
    );
  });

  it("rejects when the algorithm does, leaving nothing signed", async function () {
    class Unavailable extends RemoteRsaSha256 {
      async getSignatureAsync(): Promise<string> {
        throw new Error("signing server unavailable");
      }
    }
    const sig = createSigner(Unavailable);

    await assert.rejects(sig.computeSignatureAsync(xml), { message: "signing server unavailable" });
    expect(sig.getSignedXml()).to.equal("");
  });

  it("rejects an algorithm that answers only through a callback", async function () {
    class AnswersThroughCallback implements SignatureAlgorithm {
      getAlgorithmName = () => RSA_SHA256;

      verifySignature(): never {
        throw new Error("this algorithm only signs");
      }

      getSignature = function (
        signedInfo: crypto.BinaryLike,
        privateKey: crypto.KeyLike,
        callback?: (error: Error | null, signature?: string) => void,
      ) {
        const signature = crypto.createSign("RSA-SHA256").update(signedInfo);
        callback?.(null, signature.sign(privateKey, "base64"));
      } as unknown as SignatureAlgorithm["getSignature"];
    }
    const sig = createSigner(AnswersThroughCallback);

    await assert.rejects(sig.computeSignatureAsync(xml), {
      message:
        "the signature algorithm returned no signature; an algorithm that signs asynchronously implements getSignatureAsync()",
    });
    expect(sig.getSignedXml()).to.equal("");
  });
});

describe("checkSignatureAsync()", function () {
  const signer = createSigner();
  signer.computeSignature(xml);
  const signedXml = signer.getSignedXml();
  const signatureXml = signer.getSignatureXml();
  const signedContent = '<root Id="_0"><a>trusted</a></root>';

  // The references still match their digests; only the signature over SignedInfo does not verify.
  const withAnotherSignatureValue = (signed: string) =>
    signed.replace(
      /(<SignatureValue>)(.)/,
      (match, open: string, first: string) => open + (first === "A" ? "B" : "A"),
    );

  it("accepts a valid signature, publishing what it signs only once the algorithm answers", async function () {
    const sig = createVerifier(signatureXml, RemoteRsaSha256);

    const verdict = sig.checkSignatureAsync(signedXml);

    expect(sig.getSignedReferences()).to.deep.equal([]);
    expect(await verdict).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([signedContent]);
  });

  it("verifies through verifySignature() when the algorithm has no verifySignatureAsync()", async function () {
    const sig = createVerifier(signatureXml);

    expect(await sig.checkSignatureAsync(signedXml)).to.be.true;
    expect(sig.getSignedReferences()).to.deep.equal([signedContent]);
  });

  it("rejects a signature value that does not verify, publishing nothing", async function () {
    const sig = createVerifier(withAnotherSignatureValue(signatureXml), RemoteRsaSha256);

    await assert.rejects(sig.checkSignatureAsync(withAnotherSignatureValue(signedXml)), {
      message: /^invalid signature: the signature value /,
    });
    expect(sig.getSignedReferences()).to.deep.equal([]);
  });

  it("rejects a verdict other than true, publishing nothing", async function () {
    class AnswersWithText extends RemoteRsaSha256 {
      async verifySignatureAsync() {
        return "true" as unknown as boolean;
      }
    }
    const sig = createVerifier(signatureXml, AnswersWithText);

    await assert.rejects(sig.checkSignatureAsync(signedXml), {
      message: /^invalid signature: the signature value /,
    });
    expect(sig.getSignedReferences()).to.deep.equal([]);
  });

  it("rejects when the algorithm does, publishing nothing", async function () {
    class Unreachable extends RemoteRsaSha256 {
      async verifySignatureAsync(): Promise<boolean> {
        throw new Error("HSM unreachable");
      }
    }
    const sig = createVerifier(signatureXml, Unreachable);

    await assert.rejects(sig.checkSignatureAsync(signedXml), { message: "HSM unreachable" });
    expect(sig.getSignedReferences()).to.deep.equal([]);
  });

  it("resolves false, as checkSignature() returns false, for content that does not match its digest", async function () {
    const sig = createVerifier(signatureXml, RemoteRsaSha256);

    expect(await sig.checkSignatureAsync(signedXml.replace("trusted", "tampered"))).to.be.false;
    expect(sig.getSignedReferences()).to.deep.equal([]);
  });
});
