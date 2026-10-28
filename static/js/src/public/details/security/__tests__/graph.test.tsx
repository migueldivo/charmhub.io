import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";

import { buildTree } from "../components/DependencyGraph";
import DependenciesView from "../components/DependenciesView";
import { getSealStatus } from "../components/SecuritySeal";
import { report } from "./fixtures";

describe("buildTree", () => {
  test("nests dependencies under the charm and rolls up open vulnerabilities", () => {
    const tree = buildTree(report);

    expect(tree.label).toBe("grafana-k8s");
    expect(tree.children.map((child) => child.label)).toEqual([
      "grafana-image 1.0.0",
      "Interfaces (1)",
      "Charm libraries (0)",
      "Python packages (1)",
    ]);
    expect(tree.openVulns).toBe(2);
  });
});

describe("DependenciesView", () => {
  test("toggles between the graph and the table", async () => {
    render(<DependenciesView report={report} />);

    expect(
      screen.getByRole("img", { name: "Dependency tree of grafana-k8s" })
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Table view" }));
    expect(screen.getByText("Showing 4 of 4 dependencies")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Graph view" }));
    expect(
      screen.getByRole("img", { name: "Dependency tree of grafana-k8s" })
    ).toBeInTheDocument();
  });

  test("expands a group and shows its details", async () => {
    render(<DependenciesView report={report} />);

    await userEvent.click(
      screen.getByRole("button", { name: "Interfaces (1)" })
    );

    expect(screen.getByRole("button", { name: "ingress" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Interfaces (1)" })
    ).toBeInTheDocument();
  });
});

test("getSealStatus is stable and assigns about 20% to each state", () => {
  const names = Array.from({ length: 1000 }, (_, i) => `charm-${i}`);
  const statuses = names.map(getSealStatus);
  const share = (status: string | null) =>
    statuses.filter((s) => s === status).length / names.length;

  expect(getSealStatus("prometheus-k8s")).toBe(getSealStatus("prometheus-k8s"));
  expect(share("approved")).toBeGreaterThan(0.15);
  expect(share("approved")).toBeLessThan(0.25);
  expect(share("in-progress")).toBeGreaterThan(0.15);
  expect(share("in-progress")).toBeLessThan(0.25);
});
