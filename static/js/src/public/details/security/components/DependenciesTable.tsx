import { useMemo, useState } from "react";
import {
  Button,
  CheckboxInput,
  MainTable,
  SearchBox,
  Select,
} from "@canonical/react-components";

import type { Dependency, SecurityReport } from "../types";
import {
  DEPENDENCY_TYPE_LABELS,
  countOpenVulnerabilities,
  filterDependencies,
  type DependencyFilters,
} from "../utils";

type Props = {
  report: SecurityReport;
  initialFilters?: Partial<DependencyFilters>;
};

const EMPTY_FILTERS: DependencyFilters = {
  query: "",
  type: "",
  relationship: "",
  vulnerable: false,
};

// Direct charm dependencies first, then the contents of the OCI image.
const TYPE_ORDER = [
  "resource",
  "interface",
  "charm-library",
  "python-package",
  "application",
  "runtime",
  "os-package",
  "go-module",
];

const Details = ({
  dependency,
  parent,
}: {
  dependency: Dependency;
  parent?: Dependency;
}) => {
  if (dependency.endpoints) {
    return (
      <>
        {dependency.endpoints.map((endpoint) => (
          <div key={endpoint.name}>
            <code>{endpoint.name}</code>{" "}
            <span className="u-text--muted">
              {endpoint.role}
              {endpoint.optional ? "" : ", required"}
            </span>
          </div>
        ))}
      </>
    );
  }
  if (dependency.type === "charm-library" && dependency.owner) {
    return (
      <>
        Published by <a href={`/${dependency.owner}`}>{dependency.owner}</a>
      </>
    );
  }
  if (dependency.type === "resource") {
    return (
      <>
        OCI image{dependency.os ? ` · ${dependency.os}` : ""}
        {dependency.image && (
          <div className="p-security-table__summary u-truncate">
            {dependency.image}
          </div>
        )}
      </>
    );
  }
  if (dependency.constraint) {
    return (
      <>
        Pinned <code>{dependency.constraint}</code>
      </>
    );
  }
  if (parent) {
    return <span className="u-text--muted">via {parent.name}</span>;
  }
  return null;
};

export const DependenciesTable = ({ report, initialFilters = {} }: Props) => {
  const [filters, setFilters] = useState<DependencyFilters>({
    ...EMPTY_FILTERS,
    ...initialFilters,
  });

  const byId = useMemo(
    () =>
      Object.fromEntries(
        report.dependencies.map((dep) => [dep.id, dep])
      ) as Record<string, Dependency>,
    [report]
  );
  const openCounts = useMemo(
    () => countOpenVulnerabilities(report.vulnerabilities),
    [report]
  );
  const typeCounts = useMemo(
    () =>
      report.dependencies.reduce<Record<string, number>>((counts, dep) => {
        counts[dep.type] = (counts[dep.type] ?? 0) + 1;
        return counts;
      }, {}),
    [report]
  );

  const filtered = useMemo(
    () => filterDependencies(report.dependencies, openCounts, filters),
    [report, openCounts, filters]
  );

  const update = <K extends keyof DependencyFilters>(
    key: K,
    value: DependencyFilters[K]
  ) => setFilters((current) => ({ ...current, [key]: value }));

  const isFiltered = Object.values(filters).some(Boolean);
  const charm = report.charm;

  const rows = filtered.map((dep) => {
    const open = openCounts[dep.id] ?? 0;
    const parent = dep.parent ? byId[dep.parent] : undefined;
    return {
      key: dep.id,
      columns: [
        {
          content: dep.url ? <a href={dep.url}>{dep.name}</a> : dep.name,
          className: "u-truncate",
          title: dep.name,
        },
        { content: DEPENDENCY_TYPE_LABELS[dep.type] },
        {
          content: (
            <>
              <div>{dep.version ?? "—"}</div>
              {dep.outdated && dep.latest_version && (
                <p className="p-security-table__summary">
                  {dep.latest_version} available
                </p>
              )}
            </>
          ),
        },
        {
          content: dep.relationship === "direct" ? "Direct" : "Transitive",
        },
        { content: <Details dependency={dep} parent={parent} /> },
        {
          content: open ? (
            <a
              href={`/${charm}/security?dependency=${encodeURIComponent(dep.id)}`}
            >
              {open}
            </a>
          ) : (
            <span className="u-text--muted">0</span>
          ),
          className: "u-align--right",
        },
      ],
      sortData: {
        name: dep.name,
        type: TYPE_ORDER.indexOf(dep.type),
        relationship: dep.relationship,
        vulnerabilities: open,
      },
    };
  });

  return (
    <div className="p-section--shallow">
      <div className="p-security-filters">
        <div className="p-security-filters__search">
          <label htmlFor="dependencies-search">Search</label>
          <SearchBox
            id="dependencies-search"
            placeholder="Name or version"
            value={filters.query}
            externallyControlled
            onChange={(value) => update("query", value)}
            onClear={() => update("query", "")}
          />
        </div>
        <Select
          id="dependencies-type"
          label="Type"
          value={filters.type}
          onChange={(e) => update("type", e.target.value)}
          options={[
            { label: "All types", value: "" },
            ...Object.entries(DEPENDENCY_TYPE_LABELS)
              .filter(([type]) => typeCounts[type])
              .map(([type, label]) => ({
                label: `${label} (${typeCounts[type]})`,
                value: type,
              })),
          ]}
        />
        <Select
          id="dependencies-relationship"
          label="Relationship"
          value={filters.relationship}
          onChange={(e) => update("relationship", e.target.value)}
          options={[
            { label: "Direct and transitive", value: "" },
            { label: "Direct", value: "direct" },
            { label: "Transitive", value: "transitive" },
          ]}
        />
        <CheckboxInput
          label="Only with open vulnerabilities"
          checked={filters.vulnerable}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            update("vulnerable", e.target.checked)
          }
        />
      </div>
      <p>
        Showing {filtered.length} of {report.dependencies.length} dependencies
        {isFiltered && (
          <>
            {" "}
            <Button
              appearance="link"
              className="u-no-margin--bottom"
              onClick={() => setFilters(EMPTY_FILTERS)}
            >
              Clear filters
            </Button>
          </>
        )}
      </p>
      <MainTable
        className="p-security-table"
        headers={[
          { content: "Name", sortKey: "name", style: { width: "24%" } },
          { content: "Type", sortKey: "type" },
          { content: "Version", style: { width: "16%" } },
          { content: "Relationship", sortKey: "relationship" },
          { content: "Details", style: { width: "24%" } },
          {
            content: "Open vulnerabilities",
            sortKey: "vulnerabilities",
            className: "u-align--right",
          },
        ]}
        rows={rows}
        sortable
        defaultSort="type"
        defaultSortDirection="ascending"
        paginate={25}
        emptyStateMsg="No dependencies match the selected filters."
      />
    </div>
  );
};

export default DependenciesTable;
