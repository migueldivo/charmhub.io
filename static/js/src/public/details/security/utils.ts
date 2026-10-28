import type {
  Dependency,
  DependencyType,
  MaintenanceStatus,
  SecurityReport,
  Severity,
  Vulnerability,
} from "./types";

export const DEPENDENCY_TYPE_LABELS: Record<DependencyType, string> = {
  resource: "Resource",
  application: "Workload",
  runtime: "Runtime",
  "os-package": "OS package",
  "go-module": "Go module",
  interface: "Interface",
  "charm-library": "Charm library",
  "python-package": "Python package",
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const STATUS_LABELS: Record<MaintenanceStatus, string> = {
  triaged: "Triaged",
  "in-progress": "In progress",
  "ready-for-release": "Ready for release",
  fixed: "Fixed",
};

export const SEVERITY_ORDER = Object.keys(SEVERITY_LABELS) as Severity[];
export const STATUS_ORDER = Object.keys(STATUS_LABELS) as MaintenanceStatus[];

export const readReport = (): SecurityReport | null => {
  const element = document.getElementById("security-report-data");
  if (!element?.textContent) {
    return null;
  }
  return JSON.parse(element.textContent) as SecurityReport;
};

export interface VulnerabilityFilters {
  query: string;
  severity: string;
  status: string;
  type: string;
  source: string;
  dependency: string;
}

export const EMPTY_VULNERABILITY_FILTERS: VulnerabilityFilters = {
  query: "",
  severity: "",
  status: "",
  type: "",
  source: "",
  dependency: "",
};

export const filtersFromSearch = (
  search: string
): Partial<VulnerabilityFilters> => {
  const params = new URLSearchParams(search);
  const filters: Partial<VulnerabilityFilters> = {};
  (
    Object.keys(EMPTY_VULNERABILITY_FILTERS) as (keyof VulnerabilityFilters)[]
  ).forEach((key) => {
    const value = params.get(key);
    if (value) {
      filters[key] = value;
    }
  });
  return filters;
};

export const filterVulnerabilities = (
  vulnerabilities: Vulnerability[],
  dependencies: Record<string, Dependency>,
  filters: VulnerabilityFilters
): Vulnerability[] => {
  const query = filters.query.trim().toLowerCase();
  return vulnerabilities.filter((vuln) => {
    const dependency = dependencies[vuln.dependency];
    if (filters.severity && vuln.severity !== filters.severity) {
      return false;
    }
    if (filters.status === "open") {
      if (vuln.status === "fixed") {
        return false;
      }
    } else if (filters.status && vuln.status !== filters.status) {
      return false;
    }
    if (filters.type && dependency?.type !== filters.type) {
      return false;
    }
    if (filters.source && vuln.source !== filters.source) {
      return false;
    }
    if (filters.dependency && vuln.dependency !== filters.dependency) {
      return false;
    }
    if (query) {
      const haystack = [
        vuln.id,
        vuln.cve,
        vuln.summary,
        dependency?.name,
        vuln.installed_version,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    }
    return true;
  });
};

export interface DependencyFilters {
  query: string;
  type: string;
  relationship: string;
  vulnerable: boolean;
}

export const filterDependencies = (
  dependencies: Dependency[],
  openCounts: Record<string, number>,
  filters: DependencyFilters
): Dependency[] => {
  const query = filters.query.trim().toLowerCase();
  return dependencies.filter((dep) => {
    if (filters.type && dep.type !== filters.type) {
      return false;
    }
    if (filters.relationship && dep.relationship !== filters.relationship) {
      return false;
    }
    if (filters.vulnerable && !openCounts[dep.id]) {
      return false;
    }
    if (query) {
      return `${dep.name} ${dep.version ?? ""}`.toLowerCase().includes(query);
    }
    return true;
  });
};

export const countOpenVulnerabilities = (
  vulnerabilities: Vulnerability[]
): Record<string, number> =>
  vulnerabilities.reduce<Record<string, number>>((counts, vuln) => {
    if (vuln.status !== "fixed") {
      counts[vuln.dependency] = (counts[vuln.dependency] ?? 0) + 1;
    }
    return counts;
  }, {});
