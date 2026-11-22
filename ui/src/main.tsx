import "./app.css";
import "./ladder/ladder.css";
import "./tables/tables.css";
import "./inventory/inventory.css";
import "./coverage/coverage.css";
import "./auth/auth.css";
import "./topology/topology.css";
import { render } from "preact";
import { Root } from "./auth/Gate";
import { applyTheme, loadPrefs } from "./theme";

applyTheme(loadPrefs());
render(<Root />, document.getElementById("app")!);
