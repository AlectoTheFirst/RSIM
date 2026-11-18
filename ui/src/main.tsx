import { render } from "preact";
import { App } from "./App";
import "./app.css";
import { applyTheme, loadPrefs } from "./theme";

applyTheme(loadPrefs());
render(<App />, document.getElementById("app")!);
