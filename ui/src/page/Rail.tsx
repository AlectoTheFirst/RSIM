// The navigation rail: the wordmark and the views of the page.
import { SIZE } from "../theme";
import { RAIL_BOTTOM, RAIL_TOP, type View } from "./frame";
import { Icon, type IconName } from "./Icon";

const ICONS: Partial<Record<View, IconName>> = {
  Trace: "trace",
  Topology: "topology",
  Tables: "tables",
  Coverage: "coverage",
  Inventory: "inventory",
};

function Item(props: { view: View; current: View; href: string; onView: (v: View) => void }) {
  const icon = ICONS[props.view];
  return (
    <a
      class="rail-item"
      href={props.href}
      aria-current={props.view === props.current ? "page" : undefined}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
        e.preventDefault();
        props.onView(props.view);
      }}
    >
      {icon ? <Icon name={icon} size={SIZE.railIcon} /> : null}
      <span>{props.view}</span>
    </a>
  );
}

/** The rail. `href` gives the URL of a view. */
export function Rail(props: { view: View; href: (v: View) => string; onView: (v: View) => void }) {
  return (
    <nav class="rail" aria-label="Views">
      <span class="rail-mark t-wordmark">RSIM</span>
      {RAIL_TOP.map((v) => (
        <Item view={v} current={props.view} href={props.href(v)} onView={props.onView} />
      ))}
      <span class="rail-space" />
      {RAIL_BOTTOM.map((v) => (
        <Item view={v} current={props.view} href={props.href(v)} onView={props.onView} />
      ))}
    </nav>
  );
}
