import { useMemo, useState } from "react";
import {
  Button,
  MainTable,
  SearchBox,
  Select,
} from "@canonical/react-components";

import type { Dependency, SecurityReport, Vulnerability } from "../types";
import {
  DEPENDENCY_TYPE_LABELS,
  EMPTY_VULNERABILITY_FILTERS,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  STATUS_LABELS,
  STATUS_ORDER,
  filterVulnerabilities,
  type VulnerabilityFilters,
} from "../utils";

type Props = {
  report: SecurityReport;
  initialFilters?: Partial<VulnerabilityFilters>;
};

const countBy = <T,>(items: T[], key: (item: T) => string | undefined) =>
  items.reduce<Record<string, number>>((counts, item) => {
    const value = key(item);
    if (value) {
      counts[value] = (counts[value] ?? 0) + 1;
    }
    return counts;
  }, {});

const VulnerabilityCell = ({ vuln }: { vuln: Vulnerability }) => (
  <>
    <div>
      {vuln.url ? (
        <a href={vuln.url} target="_blank" rel="noreferrer">
          {vuln.id}
        </a>
      ) : (
        <strong>{vuln.id}</strong>
      )}
      {vuln.cve && vuln.cve !== vuln.id && (
        <span className="u-text--muted u-no-wrap"> · {vuln.cve}</span>
      )}
      {vuln.source === "Illustrative" && (
        <>
          {" "}
          <span
            className="p-status-label--caution"
            title="Interfaces and charm libraries aren't tracked by public vulnerability databases"
          >
            Illustrative
          </span>
        </>
      )}
    </div>
    <p className="p-security-table__summary">{vuln.summary}</p>
  </>
);

const DependencyCell = ({
  dependency,
  parent,
}: {
  dependency?: Dependency;
  parent?: Dependency;
}) => {
  if (!dependency) {
    return null;
  }
  return (
    <>
      <div>
        {dependency.url ? (
          <a href={dependency.url}>{dependency.name}</a>
        ) : (
          dependency.name
        )}
      </div>
      <p className="p-security-table__summary">
        {DEPENDENCY_TYPE_LABELS[dependency.type]}
        {parent ? ` · via ${parent.name}` : ""}
      </p>
    </>
  );
};

const VersionCell = ({ vuln }: { vuln: Vulnerability }) => (
  <>
    <div>{vuln.installed_version ?? "—"}</div>
    {vuln.fixed_version && (
      <p className="p-security-table__summary">Fixed in {vuln.fixed_version}</p>
    )}
  </>
);

export const SecurityTable = ({ report, initialFilters = {} }: Props) => {
  const [filters, setFilters] = useState<VulnerabilityFilters>({
    ...EMPTY_VULNERABILITY_FILTERS,
    ...initialFilters,
  });

  const dependencies = useMemo(
    () =>
      Object.fromEntries(
        report.dependencies.map((dep) => [dep.id, dep])
      ) as Record<string, Dependency>,
    [report]
  );

  const filtered = useMemo(
    () => filterVulnerabilities(report.vulnerabilities, dependencies, filters),
    [report, dependencies, filters]
  );

  const counts = useMemo(() => {
    const vulns = report.vulnerabilities;
    return {
      severity: countBy(vulns, (v) => v.severity),
      status: countBy(vulns, (v) => v.status),
      type: countBy(vulns, (v) => dependencies[v.dependency]?.type),
      source: countBy(vulns, (v) => v.source),
    };
  }, [report, dependencies]);

  const update = (key: keyof VulnerabilityFilters) => (value: string) =>
    setFilters((current) => ({ ...current, [key]: value }));

  const isFiltered = Object.entries(filters).some(([, value]) => value);
  const filteredDependency = filters.dependency
    ? dependencies[filters.dependency]
    : undefined;

  const rows = filtered.map((vuln) => {
    const dependency = dependencies[vuln.dependency];
    const parent = dependency?.parent
      ? dependencies[dependency.parent]
      : undefined;
    return {
      key: `${vuln.dependency}-${vuln.id}`,
      columns: [
        { content: <VulnerabilityCell vuln={vuln} /> },
        {
          content: <DependencyCell dependency={dependency} parent={parent} />,
        },
        { content: <VersionCell vuln={vuln} /> },
        {
          content: (
            <>
              <span className={`p-security-status is-${vuln.status}`}>
                {STATUS_LABELS[vuln.status]}
              </span>
              {vuln.status_note && (
                <p className="p-security-table__summary">{vuln.status_note}</p>
              )}
            </>
          ),
        },
        {
          content: (
            <>
              <span className={`p-security-severity is-${vuln.severity}`}>
                {SEVERITY_LABELS[vuln.severity]}
              </span>
              {vuln.cvss !== null && (
                <p className="p-security-table__summary">
                  CVSS {vuln.cvss.toFixed(1)}
                </p>
              )}
            </>
          ),
        },
        { content: vuln.published, className: "u-no-wrap" },
      ],
      sortData: {
        id: vuln.id,
        severity:
          SEVERITY_ORDER.indexOf(vuln.severity) * 100 - (vuln.cvss ?? 0),
        dependency: dependency?.name ?? "",
        status: STATUS_ORDER.indexOf(vuln.status),
        published: vuln.published,
      },
    };
  });

  const option = (label: string, value: string, count?: number) => ({
    label: count === undefined ? label : `${label} (${count})`,
    value,
  });

  return (
    <div className="p-section--shallow">
      <h2 className="p-heading--4">Vulnerabilities</h2>
      <div className="p-security-filters">
        <div className="p-security-filters__search">
          <label htmlFor="security-search">Search</label>
          <SearchBox
            id="security-search"
            placeholder="ID, CVE, package or summary"
            value={filters.query}
            externallyControlled
            onChange={update("query")}
            onClear={() => update("query")("")}
          />
        </div>
        <Select
          id="security-severity"
          label="Severity"
          value={filters.severity}
          onChange={(e) => update("severity")(e.target.value)}
          options={[
            option("All severities", ""),
            ...SEVERITY_ORDER.filter((s) => counts.severity[s]).map((s) =>
              option(SEVERITY_LABELS[s], s, counts.severity[s])
            ),
          ]}
        />
        <Select
          id="security-status"
          label="Maintenance status"
          value={filters.status}
          onChange={(e) => update("status")(e.target.value)}
          options={[
            option("All statuses", ""),
            option(
              "Open (not fixed)",
              "open",
              report.vulnerabilities.length - (counts.status.fixed ?? 0)
            ),
            ...STATUS_ORDER.map((s) =>
              option(STATUS_LABELS[s], s, counts.status[s] ?? 0)
            ),
          ]}
        />
        <Select
          id="security-type"
          label="Dependency type"
          value={filters.type}
          onChange={(e) => update("type")(e.target.value)}
          options={[
            option("All types", ""),
            ...Object.entries(DEPENDENCY_TYPE_LABELS)
              .filter(([type]) => counts.type[type])
              .map(([type, label]) => option(label, type, counts.type[type])),
          ]}
        />
        <Select
          id="security-source"
          label="Source"
          value={filters.source}
          onChange={(e) => update("source")(e.target.value)}
          options={[
            option("All sources", ""),
            ...Object.keys(counts.source).map((source) =>
              option(source, source, counts.source[source])
            ),
          ]}
        />
      </div>
      <p>
        Showing {filtered.length} of {report.vulnerabilities.length}{" "}
        vulnerabilities
        {filteredDependency && (
          <>
            {" "}
            in <strong>{filteredDependency.name}</strong>
          </>
        )}
        {isFiltered && (
          <>
            {" "}
            <Button
              appearance="link"
              className="u-no-margin--bottom"
              onClick={() => setFilters(EMPTY_VULNERABILITY_FILTERS)}
            >
              Clear filters
            </Button>
          </>
        )}
      </p>
      <MainTable
        className="p-security-table"
        headers={[
          { content: "Vulnerability", sortKey: "id", style: { width: "32%" } },
          { content: "Dependency", sortKey: "dependency" },
          { content: "Version" },
          {
            content: "Maintenance status",
            sortKey: "status",
            style: { width: "18%" },
          },
          { content: "Severity", sortKey: "severity" },
          { content: "Published", sortKey: "published" },
        ]}
        rows={rows}
        sortable
        defaultSort="severity"
        defaultSortDirection="ascending"
        paginate={25}
        emptyStateMsg="No vulnerabilities match the selected filters."
      />
    </div>
  );
};

export default SecurityTable;
