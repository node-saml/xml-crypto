# Changelog

## 6.0.0 (2024-01-26)

### 💣 Major Changes

- [**breaking-change**] Set `getCertFromKeyInfo` to `noop` [#445](https://github.com/node-saml/xml-crypto/pull/445)

### 🔗 Dependencies

- [**dependencies**] [**github_actions**] Bump github/codeql-action from 2 to 3 [#434](https://github.com/node-saml/xml-crypto/pull/434)

### 📚 Documentation

- [**documentation**] Chore: Update README.md [#432](https://github.com/node-saml/xml-crypto/pull/432)

---

## v5.1.1 (2024-01-17)

### 🐛 Bug Fixes

- [**bug**] fix: template literal [#443](https://github.com/node-saml/xml-crypto/pull/443)

---

## v5.1.0 (2024-01-07)

### 🚀 Minor Changes

- [**enhancement**] Enhance derToPem to support XML pretty-print [#439](https://github.com/node-saml/xml-crypto/pull/439)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump @typescript-eslint/parser from 6.13.0 to 6.18.1 [#442](https://github.com/node-saml/xml-crypto/pull/442)
- [**dependencies**] [**javascript**] Bump @typescript-eslint/eslint-plugin from 6.13.0 to 6.18.1 [#441](https://github.com/node-saml/xml-crypto/pull/441)
- [**dependencies**] [**javascript**] Bump follow-redirects from 1.15.3 to 1.15.4 [#440](https://github.com/node-saml/xml-crypto/pull/440)
- [**dependencies**] [**javascript**] Bump eslint from 8.54.0 to 8.56.0 [#436](https://github.com/node-saml/xml-crypto/pull/436)
- [**dependencies**] [**javascript**] Bump @types/node from 16.18.65 to 16.18.69 [#435](https://github.com/node-saml/xml-crypto/pull/435)
- [**dependencies**] [**javascript**] Bump release-it from 16.2.1 to 16.3.0 [#428](https://github.com/node-saml/xml-crypto/pull/428)

---

## v5.0.0 (2023-11-27)

### 💣 Major Changes

- [**breaking-change**] Mark `getKeyInfo()` private as it has no public consumers [#412](https://github.com/node-saml/xml-crypto/pull/412)
- [**breaking-change**] Remove the default for `getKeyInfoContent` forcing a consumer to choose [#411](https://github.com/node-saml/xml-crypto/pull/411)
- [**documentation**] [**breaking-change**] Remove default for transformation algorithm [#410](https://github.com/node-saml/xml-crypto/pull/410)
- [**breaking-change**] Remove default for signature algorithm [#408](https://github.com/node-saml/xml-crypto/pull/408)
- [**breaking-change**] Remove default for digest algorithm [#406](https://github.com/node-saml/xml-crypto/pull/406)
- [**breaking-change**] Remove default canonicalization algorithm [#405](https://github.com/node-saml/xml-crypto/pull/405)
- [**chore**] [**breaking-change**] Improve code clarity; remove unused functions [#397](https://github.com/node-saml/xml-crypto/pull/397)
- [**breaking-change**] Move validation messages to each reference [#396](https://github.com/node-saml/xml-crypto/pull/396)
- [**breaking-change**] Make references accessible only via get/set [#395](https://github.com/node-saml/xml-crypto/pull/395)
- [**chore**] [**breaking-change**] Reduce public interface by making some methods private [#394](https://github.com/node-saml/xml-crypto/pull/394)
- [**chore**] [**breaking-change**] Update build to support Node@16 [#385](https://github.com/node-saml/xml-crypto/pull/385)

### 🚀 Minor Changes

- [**enhancement**] Add support for directly querying a node to see if it has passed validation [#389](https://github.com/node-saml/xml-crypto/pull/389)
- [**enhancement**] Add method for checking if element is signed [#368](https://github.com/node-saml/xml-crypto/pull/368)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.62.0 to 6.13.0 [#422](https://github.com/node-saml/xml-crypto/pull/422)
- [**dependencies**] [**javascript**] Bump @prettier/plugin-xml from 3.2.1 to 3.2.2 [#423](https://github.com/node-saml/xml-crypto/pull/423)
- [**dependencies**] [**javascript**] Bump @types/mocha from 10.0.2 to 10.0.6 [#421](https://github.com/node-saml/xml-crypto/pull/421)
- [**dependencies**] [**javascript**] Bump @types/chai from 4.3.6 to 4.3.11 [#419](https://github.com/node-saml/xml-crypto/pull/419)
- [**dependencies**] [**javascript**] Bump prettier from 3.0.3 to 3.1.0 [#418](https://github.com/node-saml/xml-crypto/pull/418)
- [**dependencies**] [**javascript**] Bump typescript from 5.2.2 to 5.3.2 [#415](https://github.com/node-saml/xml-crypto/pull/415)
- [**dependencies**] [**javascript**] Bump eslint from 8.51.0 to 8.54.0 [#414](https://github.com/node-saml/xml-crypto/pull/414)
- [**dependencies**] [**github_actions**] Bump actions/setup-node from 3 to 4 [#413](https://github.com/node-saml/xml-crypto/pull/413)
- [**dependencies**] [**javascript**] Bump @babel/traverse from 7.22.4 to 7.23.2 [#407](https://github.com/node-saml/xml-crypto/pull/407)
- [**dependencies**] [**github_actions**] Bump actions/checkout from 3 to 4 [#392](https://github.com/node-saml/xml-crypto/pull/392)
- [**dependencies**] [**javascript**] Bump eslint-plugin-deprecation from 1.4.1 to 2.0.0 [#390](https://github.com/node-saml/xml-crypto/pull/390)
- [**dependencies**] [**javascript**] Bump typescript from 5.1.6 to 5.2.2 [#383](https://github.com/node-saml/xml-crypto/pull/383)
- [**dependencies**] [**javascript**] Bump eslint-config-prettier from 8.8.0 to 9.0.0 [#381](https://github.com/node-saml/xml-crypto/pull/381)
- [**dependencies**] Update dependencies; move to @xmldom-scoped is-dom-node package [#402](https://github.com/node-saml/xml-crypto/pull/402)

### 🐛 Bug Fixes

- [**bug**] Ensure the X509Certificate tag is properly prefixed [#377](https://github.com/node-saml/xml-crypto/pull/377)
- [**bug**] Fix transform processing regression [#379](https://github.com/node-saml/xml-crypto/pull/379)
- [**bug**] Enforce consistent transform processing [#380](https://github.com/node-saml/xml-crypto/pull/380)

### 📚 Documentation

- [**documentation**] Clarify use of <KeyInfo /> in signature validation [#401](https://github.com/node-saml/xml-crypto/pull/401)

### ⚙️ Technical Tasks

- [**chore**] Use is-dom-node for DOM node checking and narrowing [#388](https://github.com/node-saml/xml-crypto/pull/388)
- [**chore**] Improve and simplify validation logic [#373](https://github.com/node-saml/xml-crypto/pull/373)
- [**chore**] Add additional type checking [#369](https://github.com/node-saml/xml-crypto/pull/369)

---

## v4.1.0 (2023-07-28)

### 💣 Major Changes

- [**bug**] [**breaking-change**] Fix `pemToDer()` return type [#364](https://github.com/node-saml/xml-crypto/pull/364)

### ⚙️ Technical Tasks

- [**chore**] Improve exported typings [#367](https://github.com/node-saml/xml-crypto/pull/367)
- [**chore**] Use stricter typing in tests [#366](https://github.com/node-saml/xml-crypto/pull/366)
- [**chore**] Consistently reference `xmldom` [#365](https://github.com/node-saml/xml-crypto/pull/365)
- [**chore**] Rename `findChilds()` to `findChildren()` [#363](https://github.com/node-saml/xml-crypto/pull/363)

---

## v4.0.1 (2023-07-22)

### 🐛 Bug Fixes

- [**bug**] Use correct type for options [#360](https://github.com/node-saml/xml-crypto/pull/360)
- [**bug**] Fix validationErrors type [#361](https://github.com/node-saml/xml-crypto/pull/361)

---

## v4.0.0 (2023-07-21)

### 💣 Major Changes

- [**documentation**] [**breaking-change**] Expand the options, move idmode into options, fix types [#323](https://github.com/node-saml/xml-crypto/pull/323)
- [**breaking-change**] Refactor classes into their own files [#318](https://github.com/node-saml/xml-crypto/pull/318)
- [**breaking-change**] Prefer ES6 classes to prototypical inheritance [#316](https://github.com/node-saml/xml-crypto/pull/316)
- [**breaking-change**] Rename `signingCert` -> `publicCert` and `signingKey` -> `privateKey` [#315](https://github.com/node-saml/xml-crypto/pull/315)
- [**semver-major**] [**breaking-change**] Add support for <X509Certificate /> in <KeyInfo />; remove `KeyInfoProvider` [#301](https://github.com/node-saml/xml-crypto/pull/301)
- [**semver-major**] Target an LTS version of Node [#299](https://github.com/node-saml/xml-crypto/pull/299)

### 🚀 Minor Changes

- [**enhancement**] Exports C14nCanonicalization, ExclusiveCanonicalization [#336](https://github.com/node-saml/xml-crypto/pull/336)

### 🔗 Dependencies

- [**dependencies**] [**javascript**] Bump @xmldom/xmldom from 0.8.8 to 0.8.10 [#358](https://github.com/node-saml/xml-crypto/pull/358)
- [**dependencies**] [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.60.1 to 5.62.0 [#357](https://github.com/node-saml/xml-crypto/pull/357)
- [**dependencies**] [**javascript**] Bump @prettier/plugin-xml from 2.2.0 to 3.1.1 [#356](https://github.com/node-saml/xml-crypto/pull/356)
- [**dependencies**] [**javascript**] Bump prettier from 2.8.8 to 3.0.0 [#350](https://github.com/node-saml/xml-crypto/pull/350)
- [**dependencies**] [**javascript**] Bump release-it from 15.11.0 to 16.1.3 [#352](https://github.com/node-saml/xml-crypto/pull/352)
- [**dependencies**] [**javascript**] Bump prettier-plugin-packagejson from 2.4.3 to 2.4.5 [#353](https://github.com/node-saml/xml-crypto/pull/353)
- [**dependencies**] [**javascript**] Bump @typescript-eslint/parser from 5.60.1 to 5.62.0 [#354](https://github.com/node-saml/xml-crypto/pull/354)
- [**dependencies**] [**javascript**] Bump typescript from 5.1.5 to 5.1.6 [#351](https://github.com/node-saml/xml-crypto/pull/351)
- [**dependencies**] [**javascript**] Bump word-wrap from 1.2.3 to 1.2.4 [#348](https://github.com/node-saml/xml-crypto/pull/348)
- [**dependencies**] [**javascript**] Bump eslint from 8.42.0 to 8.45.0 [#344](https://github.com/node-saml/xml-crypto/pull/344)
- [**dependencies**] Update gren for better support for branches [#340](https://github.com/node-saml/xml-crypto/pull/340)
- [**dependencies**] [**github_actions**] Bump codecov/codecov-action from 3.1.1 to 3.1.4 [#290](https://github.com/node-saml/xml-crypto/pull/290)

### 🐛 Bug Fixes

- [**bug**] Fix issue in case when namespace has no prefix [#330](https://github.com/node-saml/xml-crypto/pull/330)
- [**bug**] Use correct path for code coverage reports [#302](https://github.com/node-saml/xml-crypto/pull/302)

### ⚙️ Technical Tasks

- [**chore**] Enforce eslint `no-unused-vars` [#349](https://github.com/node-saml/xml-crypto/pull/349)
- [**chore**] Enforce eslint `deprecation` [#347](https://github.com/node-saml/xml-crypto/pull/347)
- [**chore**] Enforce eslint `prefer-template` [#346](https://github.com/node-saml/xml-crypto/pull/346)
- [**chore**] Enforce eslint `no-this-alias` [#345](https://github.com/node-saml/xml-crypto/pull/345)
- [**chore**] Convert this project to TypeScript [#325](https://github.com/node-saml/xml-crypto/pull/325)
- [**chore**] Rename files in preparation for TS migration [#343](https://github.com/node-saml/xml-crypto/pull/343)
- [**chore**] Don't force `master` branch when generating changelog [#342](https://github.com/node-saml/xml-crypto/pull/342)
- [**chore**] Enforce eslint `no-unused-vars` [#322](https://github.com/node-saml/xml-crypto/pull/322)
- [**chore**] Enforce eslint `no-prototype-builtins` [#321](https://github.com/node-saml/xml-crypto/pull/321)
- [**chore**] Enforce eslint `eqeqeq` rule [#320](https://github.com/node-saml/xml-crypto/pull/320)
- [**chore**] Update types [#319](https://github.com/node-saml/xml-crypto/pull/319)
- [**chore**] Adjust code to pass eslint `prefer-const` [#312](https://github.com/node-saml/xml-crypto/pull/312)
- [**chore**] Adjust code to pass eslint `no-var` [#311](https://github.com/node-saml/xml-crypto/pull/311)
- [**chore**] Adjust code to pass eslint `curly` [#310](https://github.com/node-saml/xml-crypto/pull/310)
- [**chore**] Adjust code to pass eslint `one-var` [#309](https://github.com/node-saml/xml-crypto/pull/309)
- [**chore**] Typings [#295](https://github.com/node-saml/xml-crypto/pull/295)
- [**chore**] Lint code for new linting rules [#300](https://github.com/node-saml/xml-crypto/pull/300)
- [**chore**] Make linting rules more strict [#293](https://github.com/node-saml/xml-crypto/pull/293)
- [**chore**] Replace Nodeunit with Mocha [#294](https://github.com/node-saml/xml-crypto/pull/294)

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

### 🐛 Bug Fixes

- [**bug**] fix for #201 [#218](https://github.com/node-saml/xml-crypto/pull/218)

### ⚙️ Technical Tasks

- [**chore**] Don't pull the example folder into the module build [#220](https://github.com/node-saml/xml-crypto/pull/220)

---

## v2.0.0 (2020-10-05)

_No changelog for this release._

---

## v1.5.3 (2020-04-14)

### 🚀 Minor Changes

- [**enhancement**] Async response for built in algo sign/verify [#209](https://github.com/node-saml/xml-crypto/pull/209)

---

## v1.5.2 (2020-04-13)

_No changelog for this release._

---

## v1.5.1 (2020-04-13)

### 🐛 Bug Fixes

- [**bug**] Test suites of other projects (mocha) that include v1.5.0 fail [#207](https://github.com/node-saml/xml-crypto/pull/207)

---

## v1.5.0 (2020-04-12)

### 🚀 Minor Changes

- [**enhancement**] Add callback options to sign/verify asynchronously [#206](https://github.com/node-saml/xml-crypto/pull/206)

---

## v1.4.1 (2020-04-03)

### 🔗 Dependencies

- [**dependencies**] Bump js-yaml from 3.12.0 to 3.13.1 [#205](https://github.com/node-saml/xml-crypto/pull/205)

### 🐛 Bug Fixes

- [**bug**] validation instruction typo [#192](https://github.com/node-saml/xml-crypto/pull/192)
- [**bug**] Fixes line end and white space normalization. [#196](https://github.com/node-saml/xml-crypto/pull/196)

---

## v1.4.0 (2019-04-26)

### 🐛 Bug Fixes

- [**bug**] Fix canon xml being computed differently when signing, than when verifying [#183](https://github.com/node-saml/xml-crypto/pull/183)

---

## v1.3.0 (2019-03-23)

### 🐛 Bug Fixes

- [**bug**] Xml enc c14# inclusivenamespace fixes [#179](https://github.com/node-saml/xml-crypto/pull/179)

---

## v1.2.0 (2019-02-26)

### 🐛 Bug Fixes

- [**bug**] Accept existing xml prefixes to avoid adding to signature [#171](https://github.com/node-saml/xml-crypto/pull/171)

---

## v1.1.4 (2019-02-11)

### 🐛 Bug Fixes

- [**bug**] fix for enveloped signatures [#174](https://github.com/node-saml/xml-crypto/pull/174)

---

## v1.1.3 (2019-02-10)

### 🐛 Bug Fixes

- [**bug**] Update signed-xml.js [#172](https://github.com/node-saml/xml-crypto/pull/172)

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

### 🐛 Bug Fixes

- [**bug**] Bugfix: a namespace in the inclusive namespace list should be treated… [#163](https://github.com/node-saml/xml-crypto/pull/163)

---

## v1.0.1 (2018-09-10)

_No changelog for this release._

---

## v1.0.0 (2018-09-10)

### 🔗 Dependencies

- [**dependencies**] Addresses issue #235 by upgrading xmldom version to 0.1.27 [#155](https://github.com/node-saml/xml-crypto/pull/155)

### 🐛 Bug Fixes

- [**bug**] Decode DigestValue for validation [#160](https://github.com/node-saml/xml-crypto/pull/160)
- [**bug**] Patch for non exclusive c14n [#157](https://github.com/node-saml/xml-crypto/pull/157)
- [**bug**] Merge changes from datagovsg fork [#161](https://github.com/node-saml/xml-crypto/pull/161)

---

## v0.9.0 (2017-02-26)

_No changelog for this release._

---

## 0.9.0 (2017-02-26)

### 🚀 Minor Changes

- [**enhancement**] Separate namespaces with same prefix but different URI [#117](https://github.com/node-saml/xml-crypto/pull/117)

### 🐛 Bug Fixes

- [**bug**] Implement transform: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' [#116](https://github.com/node-saml/xml-crypto/pull/116)

---

## v0.8.5 (2016-12-08)

### 🚀 Minor Changes

- [**enhancement**] Add possible id attribute 'id' [#121](https://github.com/node-saml/xml-crypto/pull/121)

### 📚 Documentation

- [**documentation**] Update license field to npm recommendation [#119](https://github.com/node-saml/xml-crypto/pull/119)
- [**documentation**] Fix author field format [#120](https://github.com/node-saml/xml-crypto/pull/120)
- [**documentation**] Remove namespace-breaking reserialization of signature from example in README [#105](https://github.com/node-saml/xml-crypto/pull/105)

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
