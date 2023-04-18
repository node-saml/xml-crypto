module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: [],
  ignoreLabels: [],
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
        "\n_No changelog for this release._"
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
