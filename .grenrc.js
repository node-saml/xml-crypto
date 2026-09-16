// Fixed in one merge from a private fork on each release line, so the commits carrying them
// have no pull request to take a title or labels from.
const signatureBypassAdvisories = {
  title:
    "Address CVEs: [CVE-2025-29774](https://github.com/node-saml/xml-crypto/security/advisories/GHSA-9p8x-f768-wp2g) and [CVE-2025-29775](https://github.com/node-saml/xml-crypto/security/advisories/GHSA-x3m8-899r-f7c3)",
  labels: ["security"],
};

module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: [],
  ignoreLabels: [],
  // The master-side copies of changes already released from 6.x, which git cannot tell
  // are the same change as the commits that shipped.
  ignoreIssuesWith: ["duplicate"],
  commitNotes: {
    "8ac6118ee7": signatureBypassAdvisories,
    "28f92218ec": signatureBypassAdvisories,
    "886dc63a8b": signatureBypassAdvisories,
  },
  tags: "all",
  groupBy: {
    "Major Changes": ["semver-major", "breaking-change"],
    "Minor Changes": ["semver-minor", "enhancement", "new-feature"],
    Dependencies: ["dependencies"],
    "Bug Fixes": ["semver-patch", "bug", "security"],
    Documentation: ["documentation"],
    "Technical Tasks": ["chore"],
    Other: ["..."],
  },
  changelogFilename: "CHANGELOG.md",
  username: "node-saml",
  repo: "xml-crypto",
  template: {
    issue: function (placeholders) {
      const parts = [
        "-",
        placeholders.labels,
        placeholders.name,
        `[${placeholders.text}](${placeholders.url})`,
      ];
      return parts
        .filter((_) => _)
        .join(" ")
        .replace("  ", " ");
    },
    release: function (placeholders) {
      placeholders.body = placeholders.body.replace(
        "*No changelog for this release.*",
        "\n_No changelog for this release._",
      );
      return `## ${placeholders.release} (${placeholders.date})\n${placeholders.body}`;
    },
    group: function (placeholders) {
      const iconMap = {
        Enhancements: "🚀",
        "Minor Changes": "🚀",
        "Bug Fixes": "🐛",
        Documentation: "📚",
        "Technical Tasks": "⚙️",
        "Major Changes": "💣",
        Dependencies: "🔗",
      };
      const icon = iconMap[placeholders.heading] || "🙈";
      return "\n### " + icon + " " + placeholders.heading + "\n";
    },
  },
};
