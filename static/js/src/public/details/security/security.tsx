import { createRoot } from "react-dom/client";

import SecurityTable from "./components/SecurityTable";
import { filtersFromSearch, readReport } from "./utils";

const report = readReport();
const container = document.getElementById("security-table");

if (report && container) {
  createRoot(container).render(
    <SecurityTable
      report={report}
      initialFilters={filtersFromSearch(window.location.search)}
    />
  );
}
