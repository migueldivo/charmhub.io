export type DependencyType =
  | "resource"
  | "application"
  | "runtime"
  | "os-package"
  | "go-module"
  | "interface"
  | "charm-library"
  | "python-package";

export type Severity = "critical" | "high" | "medium" | "low";

export type MaintenanceStatus =
  "triaged" | "in-progress" | "ready-for-release" | "fixed";

export interface Endpoint {
  name: string;
  role: "requires" | "provides" | "peer";
  optional: boolean;
}

export interface Dependency {
  id: string;
  name: string;
  type: DependencyType;
  version: string | null;
  relationship: "direct" | "transitive";
  parent: string | null;
  url?: string | null;
  endpoints?: Endpoint[];
  owner?: string | null;
  latest_version?: string | null;
  outdated?: boolean;
  image?: string | null;
  os?: string;
  constraint?: string | null;
}

export interface Vulnerability {
  id: string;
  cve: string | null;
  summary: string;
  severity: Severity;
  cvss: number | null;
  dependency: string;
  installed_version: string | null;
  fixed_version: string | null;
  published: string;
  source: "OSV.dev" | "Illustrative";
  url: string | null;
  status: MaintenanceStatus;
  status_note: string | null;
}

export interface SecurityReport {
  charm: string;
  generated_at: string;
  revision: number;
  channel: string;
  base: string;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
}
