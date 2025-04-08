import type {
  Reference,
  SignedXmlOptions,
} from "./types";

import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as utils from "./utils";
import * as crypto from "crypto";
import { SignedXml } from "./signed-xml";


// used to verify XML Signatures class
class XMLVerifier {
  // xmlSignatureOptions, XML signature options, i.e. IdMode
  // keyInfoProvider, function: finds a trusted given, given optionally the keyInfo

  private signatureOptions: SignedXmlOptions;
  private signedXMLInstance: SignedXml
  // private keyInfoProvider;
  // this is designed to throw error, but maybe we should do boolean isntead
  private referencePrevalidator: (ref: Reference) => void;

  constructor(xmlSignatureOptions: SignedXmlOptions = {}, referencePrevalidator: (ref: Reference) => void) {
      this.signatureOptions = xmlSignatureOptions;
      this.signedXMLInstance = new SignedXml(xmlSignatureOptions);
      // this.keyInfoProvider = keyInfoProvider;
      this.referencePrevalidator = referencePrevalidator;
  }

  getAuthenticatedReferencesWithCallback(signature: Node, contextXml: string, keyInfoProvider: (keyInfo: Node) => crypto.KeyObject, callback : (err: unknown, authenticatedReferences: string[]) => void) {
    try {
      callback(null, this.getAuthenticatedReferences(signature, contextXml, keyInfoProvider));
    } catch (e) {
      callback(e, []);
    }
  }

  /**
   * Validates the signature of the provided XML document synchronously using the configured key info provider.
   *
   * @param xml The XML document containing the signature to be validated.
   * @returns an array of utf-8 encoded bytes which are authenticated by the KeyInfoProvider
   * Note: This function does NOT return a boolean value.
   * Please DO NOT rely on the length of the array to make security decisions
   * Only use the **contents** of the returned array to make security decisions.
   * @throws Error if no key info resolver is provided.
   */
  getAuthenticatedReferences(signature: Node, contextXml: string, keyInfoProvider: (keyInfo: Node) => crypto.KeyObject): string[] {
    // I: authenticate the keying material
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    // Now it returns a crypto.KeyObject, forcing user to distinguish between which type to use
    const key = this.getCertFromKeyInfo(this.keyInfo);
    if (key == null) {
      throw new Error("KeyInfo or publicCert or privateKey is required to validate signature");
    }


    // II: authenticate signedInfo utf-8 encoded canonical XML string.
    const doc = new xmldom.DOMParser().parseFromString(contextXml);

    const unverifiedSignedInfoCanon = this.getCanonSignedInfoXml(doc);
    if (!unverifiedSignedInfoCanon) {
      throw new Error("Canonical signed info cannot be empty");
    }

    // let's clear the callback up a little bit, so we can access it's results,
    // and decide whether to reset signature value or not
    const sigRes = signer.verifySignature(unverifiedSignedInfoCanon, key, this.signatureValue);
    // true case
    if (sigRes === true) {
      // continue on
    } else {
      throw new Error(`invalid signature: the signature value ${this.signatureValue} is incorrect`)
    }

    // unverifiedSignedInfoCanon is verified

    // unsigned, verify later to keep with consistent callback behavior
    const signedInfo = new xmldom.DOMParser().parseFromString(
      unverifiedSignedInfoCanon,
      "text/xml",
    );

    const unverifiedSignedInfoDoc = signedInfo.documentElement;
    if (!unverifiedSignedInfoDoc) {
      throw new Error("Could not parse unverifiedSignedInfoCanon into a document");
    }

    const references = utils.findChildren(unverifiedSignedInfoDoc, "Reference");
    if (!utils.isArrayHasLength(references)) {
      throw new Error("could not find any Reference elements");
    }

    // load each reference Node
    const unmarshalledReference = references.map((r) => this.loadReferenceNode(r));

    // now authenticate each Reference i.e. verify the Digest Value
    // map & return the utf-8 canon XML from each Reference i.e. the same digest input
    return unmarshalledReference.map((refObj) => this.getVerifiedBytes(refObj, doc));
  }

  // returns a Reference object
  private loadReferenceNode(ref: Node): Reference {

    return ref; // TODO
  }



  // processes a Reference node to get the authenticated bytes
  private getVerifiedBytes(ref: Reference, doc: Document): string {


    const uri = ref.uri?.[0] === "#" ? ref.uri.substring(1) : ref.uri;
    let elem: xpath.SelectSingleReturnType = null;
    for (const attr of this.idAttributes) {
      const tmp_elemXpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
      const tmp_elem = xpath.select(tmp_elemXpath, doc);
      if (utils.isArrayHasLength(tmp_elem)) {
        num_elements_for_id += tmp_elem.length;

        if (num_elements_for_id > 1) {
          throw new Error(
            "Cannot validate a document which contains multiple elements with the " +
            "same value for the ID / Id / Id attributes, in order to prevent " +
            "signature wrapping attack.",
          );
        }

        elem = tmp_elem[0];
      }
    }
    // TODO, fix private issues?
    const canonXml = this.signedXMLInstance.getCanonReferenceXml(doc, ref, elem);
    const hash = this.signedXMLInstance.findHashAlgorithm(ref.digestAlgorithm);
    const digest = hash.getHash(canonXml);

    if (!utils.validateDigestValue(digest, ref.digestValue)) {
      throw new Error(`invalid signature: for uri ${ref.uri} calculated digest is ${digest} but the xml to validate supplies digest ${ref.digestValue}`)
    }
    return canonXml;
  }



  // TODO maybe prevalidate a reference. Ideally this should be handled at the processReference stage
  // but this would help to abstract the function away for SAML.
  private preValidateReference(ref: Reference, contextDoc: Document): void {
    // assert that there are only 5 nodes.
    const uri = ref.uri;
    // spurious pre-verifications
    if (uri === "") {
      elem = xpath.select1("//*", doc);
    } else if (uri?.indexOf("'") !== -1) {
      // xpath injection
      throw new Error("Cannot validate a uri with quotes inside it");
    } else {
      let num_elements_for_id = 0;
      for (const attr of this.idAttributes) {
        const tmp_elemXpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
        const tmp_elem = xpath.select(tmp_elemXpath, doc);
        if (utils.isArrayHasLength(tmp_elem)) {
          num_elements_for_id += tmp_elem.length;

          if (num_elements_for_id > 1) {
            throw new Error(
              "Cannot validate a document which contains multiple elements with the " +
              "same value for the ID / Id / Id attributes, in order to prevent " +
              "signature wrapping attack.",
            );
          }

          elem = tmp_elem[0];
          ref.xpath = tmp_elemXpath;
        }
      }
    }

    // ref
    if (ref.transforms.length >= 5) {
      throw new Error('...')
    }
  }

}