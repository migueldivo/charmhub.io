import { useMemo, useRef, useState } from "react";
import { Button } from "@canonical/react-components";

import type { Dependency, DependencyType, SecurityReport } from "../types";
import {
  DEPENDENCY_TYPE_LABELS,
  SEVERITY_ORDER,
  countOpenVulnerabilities,
} from "../utils";

export const TYPE_COLORS: Record<DependencyType | "charm", string> = {
  charm: "#333333",
  resource: "#e95420",
  application: "#772953",
  runtime: "#0066cc",
  "os-package": "#a86500",
  "go-module": "#00a3c4",
  interface: "#0e8420",
  "charm-library": "#7764d8",
  "python-package": "#3776ab",
};

const SEVERITY_COLORS = {
  critical: "#8b0000",
  high: "#da291c",
  medium: "#f5841f",
  low: "#f6c311",
};

// Large groups only show this many children (vulnerable ones first).
const GROUP_LIMIT = 20;
const ROW_HEIGHT = 30;
const COLUMN_WIDTH = 230;

export interface TreeNode {
  id: string;
  label: string;
  type: DependencyType | "charm";
  dependency?: Dependency;
  isGroup?: boolean;
  hiddenCount?: number;
  children: TreeNode[];
  openVulns: number;
}

interface PositionedNode {
  node: TreeNode;
  x: number;
  y: number;
  parent?: PositionedNode;
}

export const buildTree = (report: SecurityReport): TreeNode => {
  const openCounts = countOpenVulnerabilities(report.vulnerabilities);
  const leaf = (dep: Dependency): TreeNode => ({
    id: dep.id,
    label: dep.version ? `${dep.name} ${dep.version}` : dep.name,
    type: dep.type,
    dependency: dep,
    children: [],
    openVulns: openCounts[dep.id] ?? 0,
  });
  const byVulns = (a: TreeNode, b: TreeNode) => b.openVulns - a.openVulns;
  const group = (
    id: string,
    type: DependencyType,
    label: string,
    children: TreeNode[]
  ): TreeNode => {
    const sorted = [...children].sort(byVulns);
    const shown = sorted.slice(0, GROUP_LIMIT);
    const count = (nodes: TreeNode[]): number =>
      nodes.reduce((sum, node) => sum + 1 + count(node.children), 0);
    return {
      id,
      label: `${label} (${count(children)})`,
      type,
      isGroup: true,
      hiddenCount: children.length - shown.length,
      children: shown,
      openVulns: children.reduce((sum, child) => sum + child.openVulns, 0),
    };
  };
  const withChildren = (node: TreeNode, children: TreeNode[]): TreeNode => ({
    ...node,
    children,
    openVulns:
      node.openVulns + children.reduce((sum, c) => sum + c.openVulns, 0),
  });

  const deps = report.dependencies;
  const ofType = (type: DependencyType) => deps.filter((d) => d.type === type);
  const childrenOf = (id: string, type: DependencyType) =>
    deps.filter((d) => d.type === type && d.parent === id).map(leaf);

  const pythonNode = (dep: Dependency): TreeNode =>
    withChildren(
      leaf(dep),
      deps
        .filter((d) => d.type === "python-package" && d.parent === dep.id)
        .map(pythonNode)
    );

  const resources = ofType("resource").map((resource) => {
    const apps = deps
      .filter((d) => d.type === "application" && d.parent === resource.id)
      .map((app) => {
        const modules = childrenOf(app.id, "go-module");
        return withChildren(leaf(app), [
          ...childrenOf(app.id, "runtime"),
          ...(modules.length
            ? [group(`${app.id}:go`, "go-module", "Go modules", modules)]
            : []),
        ]);
      });
    const packages = childrenOf(resource.id, "os-package");
    return withChildren(leaf(resource), [
      ...apps,
      ...(packages.length
        ? [group(`${resource.id}:os`, "os-package", "OS packages", packages)]
        : []),
    ]);
  });

  const children = [
    ...resources,
    group(
      "group:interface",
      "interface",
      "Interfaces",
      ofType("interface").map(leaf)
    ),
    group(
      "group:charm-library",
      "charm-library",
      "Charm libraries",
      ofType("charm-library").map(leaf)
    ),
    group(
      "group:python-package",
      "python-package",
      "Python packages",
      deps
        .filter((d) => d.type === "python-package" && !d.parent)
        .map(pythonNode)
    ),
  ];

  return withChildren(
    {
      id: "charm",
      label: report.charm,
      type: "charm",
      children: [],
      openVulns: 0,
    },
    children
  );
};

const layout = (root: TreeNode, expanded: Set<string>): PositionedNode[] => {
  const positioned: PositionedNode[] = [];
  let row = 0;
  const visit = (
    node: TreeNode,
    depth: number,
    parent?: PositionedNode
  ): PositionedNode => {
    const item: PositionedNode = {
      node,
      x: depth * COLUMN_WIDTH,
      y: 0,
      parent,
    };
    positioned.push(item);
    const children = expanded.has(node.id) ? node.children : [];
    if (children.length === 0) {
      item.y = row++ * ROW_HEIGHT;
    } else {
      const placed = children.map((child) => visit(child, depth + 1, item));
      item.y = (placed[0].y + placed[placed.length - 1].y) / 2;
    }
    return item;
  };
  visit(root, 0);
  return positioned;
};

const curve = (from: PositionedNode, to: PositionedNode) => {
  const midX = (from.x + to.x) / 2;
  return `M${from.x},${from.y} C${midX},${from.y} ${midX},${to.y} ${to.x},${to.y}`;
};

type Props = {
  report: SecurityReport;
  onShowInTable: (type: string) => void;
};

export const DependencyGraph = ({ report, onShowInTable }: Props) => {
  const tree = useMemo(() => buildTree(report), [report]);
  const [expanded, setExpanded] = useState<Set<string>>(
    () =>
      new Set([
        "charm",
        ...tree.children
          .filter((child) => child.type === "resource")
          .map((child) => child.id),
      ])
  );
  const [selected, setSelected] = useState<TreeNode | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [view, setView] = useState({ x: 40, y: 0, scale: 1 });
  const drag = useRef<{ x: number; y: number } | null>(null);

  const nodes = useMemo(() => layout(tree, expanded), [tree, expanded]);
  const offsetY = useMemo(() => {
    const ys = nodes.map((n) => n.y);
    return 260 - (Math.min(...ys) + Math.max(...ys)) / 2;
  }, [nodes]);

  const highlighted = useMemo(() => {
    const ids = new Set<string>();
    let current = nodes.find((n) => n.node.id === hovered);
    while (current) {
      ids.add(current.node.id);
      current = current.parent;
    }
    return ids;
  }, [hovered, nodes]);

  const toggle = (node: TreeNode) => {
    setSelected(node);
    if (node.children.length === 0) {
      return;
    }
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(node.id)) {
        next.delete(node.id);
      } else {
        next.add(node.id);
      }
      return next;
    });
  };

  const zoom = (factor: number) =>
    setView((v) => ({
      ...v,
      scale: Math.min(2, Math.max(0.3, v.scale * factor)),
    }));

  const openTotal = report.vulnerabilities.filter(
    (v) => v.status !== "fixed"
  ).length;
  const selectedDep = selected?.dependency;
  const selectedVulns = selectedDep
    ? report.vulnerabilities.filter(
        (v) => v.dependency === selectedDep.id && v.status !== "fixed"
      )
    : [];

  return (
    <div className="row">
      <div className="col-8">
        <div
          className="p-dependency-graph"
          onPointerDown={(e) => {
            drag.current = { x: e.clientX - view.x, y: e.clientY - view.y };
          }}
          onPointerMove={(e) => {
            if (drag.current) {
              const start = drag.current;
              setView((v) => ({
                ...v,
                x: e.clientX - start.x,
                y: e.clientY - start.y,
              }));
            }
          }}
          onPointerUp={() => (drag.current = null)}
          onPointerLeave={() => (drag.current = null)}
        >
          <div className="p-dependency-graph__toolbar p-segmented-control">
            <Button
              dense
              hasIcon
              aria-label="Zoom in"
              onPointerDown={(e) => e.stopPropagation()}
              onClick={() => zoom(1.2)}
            >
              <i className="p-icon--plus" />
            </Button>
            <Button
              dense
              hasIcon
              aria-label="Zoom out"
              onPointerDown={(e) => e.stopPropagation()}
              onClick={() => zoom(1 / 1.2)}
            >
              <i className="p-icon--minus" />
            </Button>
            <Button
              dense
              onPointerDown={(e) => e.stopPropagation()}
              onClick={() => setView({ x: 40, y: 0, scale: 1 })}
            >
              Reset
            </Button>
          </div>
          <svg role="img" aria-label={`Dependency tree of ${report.charm}`}>
            <g
              transform={`translate(${view.x},${view.y + offsetY}) scale(${view.scale})`}
            >
              {nodes
                .filter((n) => n.parent)
                .map((n) => {
                  const active = highlighted.has(n.node.id);
                  return (
                    <path
                      key={`edge-${n.node.id}`}
                      d={curve(n.parent as PositionedNode, n)}
                      fill="none"
                      stroke={TYPE_COLORS[n.node.type]}
                      strokeWidth={active ? 2.5 : 1.25}
                      strokeOpacity={hovered && !active ? 0.15 : 0.55}
                    />
                  );
                })}
              {nodes.map(({ node, x, y }) => {
                const color = TYPE_COLORS[node.type];
                const isOpen = expanded.has(node.id);
                const dimmed = hovered && !highlighted.has(node.id);
                const severity = node.dependency
                  ? SEVERITY_ORDER.find((s) =>
                      report.vulnerabilities.some(
                        (v) =>
                          v.dependency === node.id &&
                          v.status !== "fixed" &&
                          v.severity === s
                      )
                    )
                  : undefined;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${x},${y})`}
                    opacity={dimmed ? 0.35 : 1}
                    style={{ cursor: "pointer" }}
                    onPointerDown={(e) => e.stopPropagation()}
                    onMouseEnter={() => setHovered(node.id)}
                    onMouseLeave={() => setHovered(null)}
                    onClick={() => toggle(node)}
                    role="button"
                    aria-label={node.label}
                  >
                    <circle
                      r={node.type === "charm" ? 11 : 8}
                      fill={node.children.length && !isOpen ? color : "#fff"}
                      stroke={color}
                      strokeWidth={selected?.id === node.id ? 4 : 2.5}
                    />
                    <text
                      x={14}
                      y={4}
                      fontSize={12}
                      fontWeight={
                        node.isGroup || node.type === "charm" ? 600 : 400
                      }
                      fill="#111"
                      stroke="#f7f7f7"
                      strokeWidth={4}
                      paintOrder="stroke"
                    >
                      {node.label.length > 34
                        ? `${node.label.slice(0, 33)}…`
                        : node.label}
                      {node.openVulns > 0 && (
                        <tspan
                          fill={
                            severity ? SEVERITY_COLORS[severity] : "#da291c"
                          }
                          fontWeight={600}
                        >
                          {`  ⚠ ${node.openVulns}`}
                        </tspan>
                      )}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
          <div className="p-dependency-graph__footer">
            {report.dependencies.length} dependencies · {openTotal} open
            vulnerabilities · click a filled node to expand it, drag to pan
          </div>
        </div>
      </div>

      <div className="col-4">
        {selected && selected.type !== "charm" ? (
          <div>
            <Button appearance="base" dense onClick={() => setSelected(null)}>
              ‹ Back
            </Button>
            <p className="p-text--small-caps u-text--muted u-no-margin--bottom">
              {DEPENDENCY_TYPE_LABELS[selected.type]}
            </p>
            <h3 className="p-heading--4" style={{ overflowWrap: "anywhere" }}>
              {selectedDep?.name ?? selected.label}
            </h3>
            <div className="p-dependency-graph__panel">
              {selectedDep?.version && <p>Version {selectedDep.version}</p>}
              {selectedDep?.endpoints && (
                <p>
                  Endpoints:{" "}
                  {selectedDep.endpoints
                    .map((e) => `${e.name} (${e.role})`)
                    .join(", ")}
                </p>
              )}
              {selectedDep?.owner && <p>Published by {selectedDep.owner}</p>}
              {selectedDep?.image && (
                <p style={{ overflowWrap: "anywhere" }}>{selectedDep.image}</p>
              )}
              {selected.isGroup && selected.hiddenCount ? (
                <p>
                  Showing {selected.children.length} with the most
                  vulnerabilities; {selected.hiddenCount} more in the table.
                </p>
              ) : null}
              <p>
                <strong>{selected.openVulns}</strong> open vulnerabilities
                {selected.children.length > 0 ? " including dependencies" : ""}
              </p>
              {selectedVulns.slice(0, 5).map((v) => (
                <p key={v.id} className="p-text--small u-no-margin--bottom">
                  <span className={`p-security-severity is-${v.severity}`}>
                    {v.id}
                  </span>
                </p>
              ))}
            </div>
            <p className="u-sv3">
              {selectedDep ? (
                <a
                  href={`/${report.charm}/security?dependency=${encodeURIComponent(selectedDep.id)}`}
                >
                  View vulnerabilities
                </a>
              ) : (
                <Button
                  appearance="link"
                  onClick={() => onShowInTable(selected.type)}
                >
                  Show all in table
                </Button>
              )}
            </p>
          </div>
        ) : (
          <div>
            <p className="p-text--small-caps u-text--muted">
              {report.charm} dependency tree
            </p>
            <div className="p-dependency-graph__panel">
              <p>
                How {report.charm} revision {report.revision} connects to
                everything it depends on. <strong>Hover</strong> to highlight a
                path, <strong>click</strong> a node for details or to expand it.
              </p>
            </div>
            <p className="p-text--small-caps u-text--muted u-sv3">
              Dependency types
            </p>
            <ul className="p-dependency-graph__legend">
              {Object.entries(DEPENDENCY_TYPE_LABELS).map(([type, label]) => (
                <li key={type}>
                  <span
                    className="p-dependency-graph__dot"
                    style={{
                      backgroundColor: TYPE_COLORS[type as DependencyType],
                    }}
                  />
                  {label}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};

export default DependencyGraph;
