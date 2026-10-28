import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";

import SecurityTable from "../components/SecurityTable";
import DependenciesTable from "../components/DependenciesTable";
import { report } from "./fixtures";

describe("SecurityTable", () => {
  test("renders all vulnerabilities sorted by severity", () => {
    render(<SecurityTable report={report} />);

    expect(
      screen.getByText("Showing 3 of 3 vulnerabilities")
    ).toBeInTheDocument();
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("GO-2026-0002");
    expect(rows[0]).toHaveTextContent("Critical");
    expect(rows[0]).toHaveTextContent("Go module · via grafana-image");
    expect(rows[0]).toHaveTextContent("Fixed");
    expect(rows[1]).toHaveTextContent("GHSA-aaaa");
    expect(rows[2]).toHaveTextContent("Illustrative");
  });

  test("filters by maintenance status and clears filters", async () => {
    render(<SecurityTable report={report} />);

    await userEvent.selectOptions(
      screen.getByLabelText("Maintenance status"),
      "in-progress"
    );
    expect(
      screen.getByText("Showing 1 of 3 vulnerabilities")
    ).toBeInTheDocument();
    expect(screen.getByText("GHSA-aaaa")).toBeInTheDocument();
    expect(screen.queryByText("GO-2026-0002")).not.toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: "Clear filters" })
    );
    expect(
      screen.getByText("Showing 3 of 3 vulnerabilities")
    ).toBeInTheDocument();
  });

  test("applies initial filters", () => {
    render(
      <SecurityTable report={report} initialFilters={{ type: "interface" }} />
    );

    expect(
      screen.getByText("Showing 1 of 3 vulnerabilities")
    ).toBeInTheDocument();
    expect(screen.getByText("CHARM-2026-0001")).toBeInTheDocument();
  });
});

describe("DependenciesTable", () => {
  test("renders dependencies with open vulnerability links", () => {
    render(<DependenciesTable report={report} />);

    expect(screen.getByText("Showing 4 of 4 dependencies")).toBeInTheDocument();
    const link = screen
      .getAllByRole("link", { name: "1" })
      .map((el) => el.getAttribute("href"));
    expect(link).toContain("/grafana-k8s/security?dependency=pypi%3Ajinja2");
    expect(
      screen.getByText("ingress", { selector: "code" })
    ).toBeInTheDocument();
  });

  test("filters to vulnerable dependencies", async () => {
    render(<DependenciesTable report={report} />);

    await userEvent.click(
      screen.getByLabelText("Only with open vulnerabilities")
    );

    expect(screen.getByText("Showing 2 of 4 dependencies")).toBeInTheDocument();
    expect(screen.queryByText("golang.org/x/net")).not.toBeInTheDocument();
  });
});
