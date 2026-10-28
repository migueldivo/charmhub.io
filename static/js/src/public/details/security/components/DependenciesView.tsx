import { useState } from "react";

import type { SecurityReport } from "../types";
import DependenciesTable from "./DependenciesTable";
import DependencyGraph from "./DependencyGraph";

type View = "graph" | "table";

type Props = {
  report: SecurityReport;
  initialView?: View;
  initialType?: string;
};

export const DependenciesView = ({
  report,
  initialView = "graph",
  initialType = "",
}: Props) => {
  const [view, setView] = useState<View>(initialView);
  const [type, setType] = useState(initialType);

  const changeView = (next: View) => {
    setView(next);
    const url = new URL(window.location.href);
    url.searchParams.set("view", next);
    window.history.replaceState(null, "", url);
  };

  return (
    <>
      <div className="p-segmented-control u-sv3">
        <div
          className="p-segmented-control__list"
          role="tablist"
          aria-label="Dependencies view"
        >
          {(["graph", "table"] as View[]).map((option) => (
            <button
              key={option}
              className="p-segmented-control__button"
              role="tab"
              aria-selected={view === option}
              onClick={() => changeView(option)}
            >
              {option === "graph" ? "Graph view" : "Table view"}
            </button>
          ))}
        </div>
      </div>
      {view === "graph" ? (
        <DependencyGraph
          report={report}
          onShowInTable={(nextType) => {
            setType(nextType);
            changeView("table");
          }}
        />
      ) : (
        <DependenciesTable
          key={type}
          report={report}
          initialFilters={{ type }}
        />
      )}
    </>
  );
};

export default DependenciesView;
