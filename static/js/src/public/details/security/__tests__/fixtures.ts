import type { Dependency, SecurityReport, Vulnerability } from "../types";

export const dependency = (
  overrides: Partial<Dependency> & Pick<Dependency, "id" | "name" | "type">
): Dependency => ({
  version: "1.0.0",
  relationship: "direct",
  parent: null,
  ...overrides,
});

export const vulnerability = (
  overrides: Partial<Vulnerability> & Pick<Vulnerability, "id" | "dependency">
): Vulnerability => ({
  cve: null,
  summary: "A vulnerability",
  severity: "medium",
  cvss: 5,
  installed_version: "1.0.0",
  fixed_version: null,
  published: "2026-01-01",
  source: "OSV.dev",
  url: null,
  status: "triaged",
  status_note: null,
  ...overrides,
});

export const report: SecurityReport = {
  charm: "grafana-k8s",
  generated_at: "2026-10-28",
  revision: 200,
  channel: "12.4/stable",
  base: "Ubuntu 26.04",
  dependencies: [
    dependency({
      id: "resource:image",
      name: "grafana-image",
      type: "resource",
    }),
    dependency({
      id: "pypi:jinja2",
      name: "jinja2",
      type: "python-package",
      version: "2.11.3",
    }),
    dependency({
      id: "go:golang.org/x/net",
      name: "golang.org/x/net",
      type: "go-module",
      relationship: "transitive",
      parent: "resource:image",
    }),
    dependency({
      id: "interface:ingress",
      name: "ingress",
      type: "interface",
      version: null,
      endpoints: [{ name: "ingress", role: "requires", optional: true }],
    }),
  ],
  vulnerabilities: [
    vulnerability({
      id: "GHSA-aaaa",
      cve: "CVE-2026-0001",
      dependency: "pypi:jinja2",
      severity: "high",
      summary: "Sandbox breakout",
      status: "in-progress",
    }),
    vulnerability({
      id: "GO-2026-0002",
      dependency: "go:golang.org/x/net",
      severity: "critical",
      status: "fixed",
    }),
    vulnerability({
      id: "CHARM-2026-0001",
      dependency: "interface:ingress",
      severity: "low",
      source: "Illustrative",
      status: "triaged",
      summary: "Route shadowing",
    }),
  ],
};
