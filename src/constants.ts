import { NamespacedId } from "./types";

/** Well known namespaced ids */
export const KNOWN_NAMESPACED_IDS: { [key: string]: NamespacedId } = {
  /** WS-Security */
  wssecurity: {
    prefix: "wsu",
    localName: "Id",
    nameSpaceURI:
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
  },
  /** Xml */
  xml: {
    prefix: "xml",
    localName: "id",
    nameSpaceURI: "http://www.w3.org/XML/1998/namespace",
  },
};
