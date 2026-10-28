import {
  EMPTY_VULNERABILITY_FILTERS,
  countOpenVulnerabilities,
  filterDependencies,
  filterVulnerabilities,
  filtersFromSearch,
} from "../utils";
import { report } from "./fixtures";

const deps = Object.fromEntries(report.dependencies.map((d) => [d.id, d]));
const ids = (items: { id: string }[]) => items.map((item) => item.id);

describe("filterVulnerabilities", () => {
  const filter = (filters: Partial<typeof EMPTY_VULNERABILITY_FILTERS>) =>
    ids(
      filterVulnerabilities(report.vulnerabilities, deps, {
        ...EMPTY_VULNERABILITY_FILTERS,
        ...filters,
      })
    );

  test("returns everything without filters", () => {
    expect(filter({})).toHaveLength(3);
  });

  test("filters by severity", () => {
    expect(filter({ severity: "critical" })).toEqual(["GO-2026-0002"]);
  });

  test("filters by status and open", () => {
    expect(filter({ status: "triaged" })).toEqual(["CHARM-2026-0001"]);
    expect(filter({ status: "open" })).toEqual([
      "GHSA-aaaa",
      "CHARM-2026-0001",
    ]);
  });

  test("filters by dependency type, source and dependency", () => {
    expect(filter({ type: "go-module" })).toEqual(["GO-2026-0002"]);
    expect(filter({ source: "Illustrative" })).toEqual(["CHARM-2026-0001"]);
    expect(filter({ dependency: "pypi:jinja2" })).toEqual(["GHSA-aaaa"]);
  });

  test("searches IDs, CVEs, summaries and dependency names", () => {
    expect(filter({ query: "cve-2026-0001" })).toEqual(["GHSA-aaaa"]);
    expect(filter({ query: "sandbox" })).toEqual(["GHSA-aaaa"]);
    expect(filter({ query: "x/net" })).toEqual(["GO-2026-0002"]);
  });
});

describe("filterDependencies", () => {
  const open = countOpenVulnerabilities(report.vulnerabilities);
  const filter = (filters: Partial<Parameters<typeof filterDependencies>[2]>) =>
    ids(
      filterDependencies(report.dependencies, open, {
        query: "",
        type: "",
        relationship: "",
        vulnerable: false,
        ...filters,
      })
    );

  test("counts only unresolved vulnerabilities", () => {
    expect(open).toEqual({ "pypi:jinja2": 1, "interface:ingress": 1 });
  });

  test("filters by type, relationship, vulnerability and query", () => {
    expect(filter({ type: "interface" })).toEqual(["interface:ingress"]);
    expect(filter({ relationship: "transitive" })).toEqual([
      "go:golang.org/x/net",
    ]);
    expect(filter({ vulnerable: true })).toEqual([
      "pypi:jinja2",
      "interface:ingress",
    ]);
    expect(filter({ query: "2.11" })).toEqual(["pypi:jinja2"]);
  });
});

test("filtersFromSearch reads known filters from the URL", () => {
  expect(filtersFromSearch("?type=go-module&foo=bar&status=open")).toEqual({
    type: "go-module",
    status: "open",
  });
});
