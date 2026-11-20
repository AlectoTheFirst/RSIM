import { render } from "preact";
import { Root } from "./auth/Gate";
import "./app.css";
import { applyTheme, loadPrefs } from "./theme";

applyTheme(loadPrefs());
render(<Root />, document.getElementById("app")!);
