import type { ReportInput } from "@vulnfuse/core";

const trivy = {
  SchemaVersion: 2,
  ArtifactName: "registry.example.com/acme/payments:1.0.0",
  ArtifactType: "container_image",
  Results: [
    {
      Target: "app.jar",
      Class: "lang-pkgs",
      Type: "jar",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2021-44228",
          PkgID: "org.apache.logging.log4j:log4j-core:2.14.1",
          PkgName: "org.apache.logging.log4j:log4j-core",
          PkgIdentifier: { PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
          InstalledVersion: "2.14.1",
          FixedVersion: "2.17.1",
          Severity: "CRITICAL",
          Title: "Log4Shell remote code execution in log4j-core",
          Description:
            "Apache Log4j2 JNDI features could allow attacker-controlled code execution.",
          PrimaryURL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
          VulnerabilityID: "CVE-2022-0778",
          PkgID: "openssl:1.1.1k",
          PkgName: "openssl",
          PkgIdentifier: { PURL: "pkg:apk/alpine/openssl@1.1.1k" },
          InstalledVersion: "1.1.1k",
          FixedVersion: "1.1.1n",
          Severity: "HIGH",
          Title: "Infinite loop in BN_mod_sqrt",
        },
      ],
    },
  ],
};

const grype = {
  matches: [
    {
      vulnerability: {
        id: "CVE-2021-44228",
        aliases: ["GHSA-jfh8-c2jp-5v3q"],
        severity: "Critical",
        description: "Log4Shell remote code execution in Apache Log4j2.",
        urls: ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"],
        fix: { versions: ["2.17.1"], state: "fixed" },
      },
      artifact: {
        id: "sha256:log4j-demo",
        name: "org.apache.logging.log4j:log4j-core",
        version: "2.14.1",
        type: "java-archive",
        language: "java",
        purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        locations: [{ path: "app.jar" }],
      },
    },
    {
      vulnerability: {
        id: "CVE-2023-45853",
        severity: "Medium",
        description: "Integer overflow in MiniZip.",
        fix: { versions: [], state: "not-fixed" },
      },
      artifact: {
        id: "sha256:zlib-demo",
        name: "zlib",
        version: "1.2.13",
        type: "apk",
        purl: "pkg:apk/alpine/zlib@1.2.13",
        locations: [{ path: "/lib/apk/db/installed" }],
      },
    },
  ],
  source: { type: "image", target: "registry.example.com/acme/payments:1.0.0" },
  descriptor: { name: "grype", version: "0.99.0" },
};

const snyk = {
  projectName: "acme/payments-source",
  displayTargetFile: "pom.xml",
  packageManager: "maven",
  vulnerabilities: [
    {
      id: "SNYK-JAVA-LOG4J-2314720",
      title: "Remote Code Execution in Apache Log4j",
      description: "CVE-2021-44228 allows remote code execution through JNDI lookups.",
      severity: "critical",
      packageName: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
      purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      fixedIn: ["2.17.1"],
      identifiers: { CVE: ["CVE-2021-44228"], CWE: ["CWE-502"] },
      url: "https://security.snyk.io/vuln/SNYK-JAVA-LOG4J-2314720",
    },
  ],
};

export const demoReports: ReportInput[] = [
  { name: "demo-trivy.json", content: JSON.stringify(trivy) },
  { name: "demo-grype.json", content: JSON.stringify(grype) },
  { name: "demo-snyk.json", content: JSON.stringify(snyk) },
];

export const demoBaselineReports: ReportInput[] = [
  { name: "baseline-trivy.json", content: JSON.stringify(trivy) },
];
