import { createRoot } from "react-dom/client";

import DependenciesView from "./components/DependenciesView";
import { readReport } from "./utils";

const report = readReport();
const container = document.getElementById("dependencies-table");

if (report && container) {
  const params = new URLSearchParams(window.location.search);
  createRoot(container).render(
    <DependenciesView
      report={report}
      initialView={params.get("view") === "table" ? "table" : "graph"}
      initialType={params.get("type") ?? ""}
    />
  );
}
