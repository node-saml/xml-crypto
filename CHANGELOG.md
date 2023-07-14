# Changelog

## 3.x (2023-07-14)

### 🚀 Minor Changes

- [**enhancement**] Exports C14nCanonicalization, ExclusiveCanonicalization [#335](https://github.com/node-saml/xml-crypto/pull/335)

### 🔗 Dependencies

- [**dependencies**] Update gren for better support for branches [#339](https://github.com/node-saml/xml-crypto/pull/339)
- [**dependencies**] Bump @xmldom/xmldom [#333](https://github.com/node-saml/xml-crypto/pull/333)

### 🐛 Bug Fixes

- [**bug**] Fix test case error [#338](https://github.com/node-saml/xml-crypto/pull/338)
- [**bug**] Fix missing `index.js` on release [#337](https://github.com/node-saml/xml-crypto/pull/337)
- [**bug**] Fix issue in case when namespace has no prefix [#329](https://github.com/node-saml/xml-crypto/pull/329)

### ⚙️ Technical Tasks

- [**chore**] Don't force `master` branch when generating changelog [#341](https://github.com/node-saml/xml-crypto/pull/341)
- [**chore**] Ignore unnecessary files in the release [#334](https://github.com/node-saml/xml-crypto/pull/334)

---

## v3.1.0 (2023-06-05)

### 🚀 Minor Changes

- [**enhancement**] Add support for appending attributes to KeyInfo element [#285](https://github.com/node-saml/xml-crypto/pull/285)
- [**enhancement**] Use inclusiveNamespacesPrefixList to generate InclusiveNamespaces [#284](https://github.com/node-saml/xml-crypto/pull/284)
- [**enhancement**] build: add release-it to facilitate builds [#275](https://github.com/node-saml/xml-crypto/pull/275)
- [**enhancement**] [**documentation**] feat: add type declaration [#277](https://github.com/node-saml/xml-crypto/pull/277)
- [**enhancement**] make FileKeyInfo extensible for compatibility with TypeScript [#273](https://github.com/node-saml/xml-crypto/pull/273)
- [**enhancement**] Updated getKeyInfo function with actual implementation [#249](https://github.com/node-saml/xml-crypto/pull/249)

### 🔗 Dependencies

- [**dependencies**] Update dependencies [#296](https://github.com/node-saml/xml-crypto/pull/296)
- [**dependencies**] Bump minimatch from 3.0.4 to 3.1.2 [#276](https://github.com/node-saml/xml-crypto/pull/276)
- [**dependencies**] [**javascript**] Bump qs from 6.5.2 to 6.5.3 [#271](https://github.com/node-saml/xml-crypto/pull/271)

### 📚 Documentation

- [**documentation**] [**chore**] Adjust references for `node-saml` organization [#298](https://github.com/node-saml/xml-crypto/pull/298)

### ⚙️ Technical Tasks

- [**chore**] Force CI to run on every PR [#286](https://github.com/node-saml/xml-crypto/pull/286)
- [**chore**] Format code [#289](https://github.com/node-saml/xml-crypto/pull/289)
- [**chore**] Lint code [#288](https://github.com/node-saml/xml-crypto/pull/288)
- [**chore**] Add support for linting [#287](https://github.com/node-saml/xml-crypto/pull/287)

---

## v3.0.1 (2022-10-31)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump ajv and har-validator [#266](https://github.com/node-saml/xml-crypto/pull/266)
- [**dependencies**] [**javascript**] Bump yargs-parser and tap [#257](https://github.com/node-saml/xml-crypto/pull/257)
- [**dependencies**] [**javascript**] Bump minimist and tap [#264](https://github.com/node-saml/xml-crypto/pull/264)

---

## v3.0.0 (2022-10-13)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump @xmldom/xmldom from 0.7.0 to 0.8.3 [#261](https://github.com/node-saml/xml-crypto/pull/261)
- [**dependencies**] [**javascript**] Bump handlebars from 4.0.11 to 4.7.7 [#247](https://github.com/node-saml/xml-crypto/pull/247)
- [**dependencies**] [**javascript**] Bump lodash from 4.17.10 to 4.17.21 [#248](https://github.com/node-saml/xml-crypto/pull/248)
- [**dependencies**] [**javascript**] Bump hosted-git-info from 2.6.0 to 2.8.9 [#246](https://github.com/node-saml/xml-crypto/pull/246)
- [**dependencies**] [**javascript**] Bump ejs from 2.6.1 to 3.1.7 [#244](https://github.com/node-saml/xml-crypto/pull/244)
- [**dependencies**] [**javascript**] Bump path-parse from 1.0.5 to 1.0.7 [#245](https://github.com/node-saml/xml-crypto/pull/245)

### ⚙️ Technical Tasks

- [**chore**] build(ci): test on later node versions [#251](https://github.com/node-saml/xml-crypto/pull/251)

---

## v2.1.4 (2022-07-08)

### 🐛 Bug Fixes

- [**bug**] Correct behavior for XML canonicalization with namespaces and nested elements [#242](https://github.com/node-saml/xml-crypto/pull/242)

---

## v2.1.3 (2021-08-20)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] [**security**] Update xmldom to 0.7.0 [#236](https://github.com/node-saml/xml-crypto/pull/236)
- [**dependencies**] [**java**] Bump commons-io from 2.4 to 2.7 in /test/validators/XmlCryptoJava [#229](https://github.com/node-saml/xml-crypto/pull/229)

---

## v2.1.2 (2021-04-19)

_No changelog for this release._

---

## v2.1.1 (2021-03-16)

_No changelog for this release._

---

## v2.1.0 (2021-03-15)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump xmldom from 0.1.27 to 0.5.0 [#225](https://github.com/node-saml/xml-crypto/pull/225)
- [**dependencies**] [**java**] Bump junit from 4.12 to 4.13.1 in /test/validators/XmlCryptoJava [#217](https://github.com/node-saml/xml-crypto/pull/217)

### ⚙️ Technical Tasks

- [**chore**] Don't pull the example folder into the module build [#220](https://github.com/node-saml/xml-crypto/pull/220)

### 🙈 Other

- [**closed**] fix for #201 [#218](https://github.com/node-saml/xml-crypto/pull/218)

---

## v2.0.0 (2020-10-05)

_No changelog for this release._

---

## v1.5.3 (2020-04-14)

### 🙈 Other

- [**closed**] Async response for built in algo sign/verify [#209](https://github.com/node-saml/xml-crypto/pull/209)

---

## v1.5.2 (2020-04-13)

_No changelog for this release._

---

## v1.5.1 (2020-04-13)

### 🙈 Other

- [**closed**] Test suites of other projects (mocha) that include v1.5.0 fail [#207](https://github.com/node-saml/xml-crypto/pull/207)

---

## v1.5.0 (2020-04-12)

### 🙈 Other

- [**closed**] Add callback options to sign/verify asynchronously [#206](https://github.com/node-saml/xml-crypto/pull/206)

---

## v1.4.1 (2020-04-03)

### 🔗 Dependencies

- [**dependencies**] Bump js-yaml from 3.12.0 to 3.13.1 [#205](https://github.com/node-saml/xml-crypto/pull/205)

### 🙈 Other

- [**closed**] validation instruction typo [#192](https://github.com/node-saml/xml-crypto/pull/192)
- [**closed**] Fixes line end and white space normalization. [#196](https://github.com/node-saml/xml-crypto/pull/196)

---

## v1.4.0 (2019-04-26)

### 🙈 Other

- [**closed**] Fix canon xml being computed differently when signing, than when verifying [#183](https://github.com/node-saml/xml-crypto/pull/183)

---

## v1.3.0 (2019-03-23)

### 🙈 Other

- [**closed**] Xml enc c14# inclusivenamespace fixes [#179](https://github.com/node-saml/xml-crypto/pull/179)

---

## v1.2.0 (2019-02-26)

### 🙈 Other

- [**closed**] Accept existing xml prefixes to avoid adding to signature [#171](https://github.com/node-saml/xml-crypto/pull/171)

---

## v1.1.4 (2019-02-11)

### 🙈 Other

- [**closed**] fix for enveloped signatures [#174](https://github.com/node-saml/xml-crypto/pull/174)

---

## v1.1.3 (2019-02-10)

### 🙈 Other

- [**closed**] Update signed-xml.js [#172](https://github.com/node-saml/xml-crypto/pull/172)

---

## v1.1.2 (2019-01-28)

_No changelog for this release._

---

## v1.1.1 (2019-01-01)

_No changelog for this release._

---

## v1.1.0 (2019-01-01)

_No changelog for this release._

---

## v1.0.2 (2018-11-08)

### 🙈 Other

- [**closed**] Bugfix: a namespace in the inclusive namespace list should be treated… [#163](https://github.com/node-saml/xml-crypto/pull/163)

---

## v1.0.1 (2018-09-10)

_No changelog for this release._

---

## v1.0.0 (2018-09-10)

### 🙈 Other

- [**closed**] Decode DigestValue for validation [#160](https://github.com/node-saml/xml-crypto/pull/160)
- [**closed**] Addresses issue #235 by upgrading xmldom version to 0.1.27 [#155](https://github.com/node-saml/xml-crypto/pull/155)
- [**closed**] Patch for non exclusive c14n [#157](https://github.com/node-saml/xml-crypto/pull/157)
- [**closed**] Merge changes from datagovsg fork [#161](https://github.com/node-saml/xml-crypto/pull/161)

---

## v0.9.0 (2017-02-26)

_No changelog for this release._

---

## 0.9.0 (2017-02-26)

### 🙈 Other

- [**closed**] Separate namespaces with same prefix but different URI [#117](https://github.com/node-saml/xml-crypto/pull/117)
- [**closed**] Implement transform: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' [#116](https://github.com/node-saml/xml-crypto/pull/116)

---

## v0.8.5 (2016-12-08)

### 🙈 Other

- [**closed**] Add possible id attribute 'id' [#121](https://github.com/node-saml/xml-crypto/pull/121)
- [**closed**] Update license field to npm recommendation [#119](https://github.com/node-saml/xml-crypto/pull/119)
- [**closed**] Fix author field format [#120](https://github.com/node-saml/xml-crypto/pull/120)
- [**closed**] Remove namespace-breaking reserialization of signature from example in README [#105](https://github.com/node-saml/xml-crypto/pull/105)

---

## v0.8.4 (2016-03-12)

_No changelog for this release._

---

## v0.8.3 (2016-03-06)

_No changelog for this release._

---

## v0.8.2 (2015-12-13)

_No changelog for this release._

---

## v0.8.1 (2015-10-15)

_No changelog for this release._

---

## v0.8.0 (2015-10-03)

_No changelog for this release._

---

## V1 (2013-07-20)

_No changelog for this release._
