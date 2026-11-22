// The content of a page: the page head, the cards, and the layout of the
// content with the panel at its right.
import type { ComponentChildren } from "preact";

/** The head of a page: the tabs or the controls of the page, and the actions at the right. */
export function PageHead(props: { tabs?: ComponentChildren; actions?: ComponentChildren }) {
  return (
    <div class="page-head">
      {props.tabs ?? null}
      {props.actions ? <span class="page-actions group">{props.actions}</span> : null}
    </div>
  );
}

/**
 * A card on the page ground. `title` is the section title of its head and
 * `head` the other content of the head, at the right of the title. `foot`
 * is a row of actions below the body. `flush` drops the padding of the
 * body, for a table or a drawing that runs to the border. `fill` makes the
 * card take the rest of the height of a `page fill`.
 */
export function Card(props: {
  title?: string;
  head?: ComponentChildren;
  foot?: ComponentChildren;
  /** The name of the card when it has no title. */
  label?: string;
  flush?: boolean;
  fill?: boolean;
  class?: string;
  children?: ComponentChildren;
}) {
  const cls = ["card", props.flush ? "flush" : "", props.fill ? "fill" : "", props.class ?? ""].filter(Boolean).join(" ");
  const headed = props.title !== undefined || props.head !== undefined;
  return (
    <section class={cls} aria-label={props.title === undefined ? props.label : undefined}>
      {headed ? (
        <div class="card-head">
          {props.title !== undefined ? <h2 class="t-section">{props.title}</h2> : null}
          {props.head ?? null}
        </div>
      ) : null}
      <div class="card-body">{props.children}</div>
      {props.foot ? <div class="card-foot group">{props.foot}</div> : null}
    </section>
  );
}

/** The state of a card or a list with no content: words in `ink-muted`, or a problem in `drop`. */
export function Empty(props: { problem?: boolean; role?: "row"; children?: ComponentChildren }) {
  return (
    <div class={`empty ${props.problem ? "c-drop" : "muted"}`} role={props.role}>
      {props.children}
    </div>
  );
}

/** The content at the left and, when `panel` is given, the panel at its right. */
export function PanelLayout(props: { panel?: ComponentChildren | null; children?: ComponentChildren; fill?: boolean }) {
  const open = props.panel !== undefined && props.panel !== null && props.panel !== false;
  return (
    <div class={`with-panel${open ? " open" : ""}${props.fill ? " fill" : ""}`}>
      <div class="with-panel-main">{props.children}</div>
      {open ? props.panel : null}
    </div>
  );
}
