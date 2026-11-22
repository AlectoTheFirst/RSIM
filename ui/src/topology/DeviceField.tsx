// The fields Device and Site of the map: a name with the options that start
// with its text, 50 at a time.
import { useEffect, useState } from "preact/hooks";
import { tableRows } from "../api/client";
import { OptionList } from "../page/Picker";
import { PICKER_CLOSED, PICKER_MAX, type PickerState, hasMore, pickerKey, pickerLimit } from "../page/pick";
import { SIZE } from "../theme";
import { devicePickParams, devicePicks } from "./draw";
import { siteOptions } from "./scope";

/** The wait after the last key before the field asks the API, in ms. */
const WAIT_MS = 150;

interface Options {
  key: string;
  list: { name: string; detail: string }[];
  more: boolean;
}

/**
 * A field with its option list. Enter or a choice of an option calls
 * `onChoose` with the name; Enter with no active option calls it with the
 * text of the field.
 */
function PickField(props: {
  id: string;
  label: string;
  listLabel: string;
  class: string;
  columns: "one" | "two";
  text: string;
  onText: (t: string) => void;
  opts: Options;
  textKey: string;
  onMore: () => void;
  onOpen: (open: boolean) => void;
  onChoose: (name: string) => void;
  autoFocus?: boolean;
}) {
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const list = props.opts.key === props.textKey ? props.opts.list : [];
  const shown = state.open && list.length > 0;

  useEffect(() => setState((s) => ({ ...s, active: -1 })), [props.textKey]);
  useEffect(() => props.onOpen(state.open), [state.open]);

  const choose = (name: string) => {
    props.onText(name);
    setState(PICKER_CLOSED);
    props.onChoose(name);
  };

  return (
    <label class={`map-field ${props.class}`}>
      <span class="t-label">{props.label}</span>
      <span class="map-device-box">
        <input
          class="t-value"
          value={props.text}
          autoFocus={props.autoFocus}
          spellcheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded={shown}
          aria-controls={props.id}
          aria-activedescendant={shown && state.active >= 0 ? `${props.id}-${state.active}` : undefined}
          onFocus={() => setState({ open: true, active: -1 })}
          onBlur={() => setState(PICKER_CLOSED)}
          onInput={(e) => {
            props.onText((e.target as HTMLInputElement).value);
            setState({ open: true, active: -1 });
          }}
          onKeyDown={(e) => {
            const r = pickerKey(state, e.key, list.length);
            if (r.handled) {
              e.preventDefault();
              if (e.key === "Escape") e.stopPropagation();
              setState(r.state);
              if (r.action === "choose") choose(list[state.active]!.name);
            } else if (e.key === "Enter") {
              e.preventDefault();
              choose(props.text.trim());
            } else if (e.key === "ArrowDown") {
              setState({ open: true, active: -1 });
            }
          }}
        />
        {shown ? (
          <OptionList
            id={props.id}
            label={props.listLabel}
            count={list.length}
            active={state.active}
            estimate={SIZE.button}
            columns={props.columns}
            option={(i) =>
              props.columns === "two" ? (
                <>
                  <span class="t-value">{list[i]!.name}</span>
                  <span class="t-label">{list[i]!.detail}</span>
                </>
              ) : (
                <span class="t-value">{list[i]!.name}</span>
              )
            }
            onChoose={(i) => choose(list[i]!.name)}
            onMore={props.opts.more ? props.onMore : undefined}
          />
        ) : null}
      </span>
    </label>
  );
}

/** The field Device: the devices of the twin from the table `devices`. Enter on an empty field gives the empty text. */
export function DeviceField(props: { twin: string; device: string; onDevice: (name: string) => void; autoFocus?: boolean }) {
  const [text, setText] = useState(props.device);
  const [open, setOpen] = useState(false);
  const [pages, setPages] = useState(1);
  const [opts, setOpts] = useState<Options>({ key: "", list: [], more: false });
  const key = `${props.twin}\u0000${text.trim()}`;

  useEffect(() => setText(props.device), [props.device]);
  useEffect(() => setPages(1), [key]);

  useEffect(() => {
    if (!open || !props.twin) return;
    let live = true;
    const limit = pickerLimit(pages);
    const timer = setTimeout(() => {
      tableRows(props.twin, "devices", devicePickParams(text, limit))
        .then((t) => {
          if (live) setOpts({ key, list: devicePicks(t).map((d) => ({ name: d.name, detail: d.vendor ?? "" })), more: hasMore(t, limit) });
        })
        .catch(() => {
          if (live) setOpts({ key, list: [], more: false });
        });
    }, WAIT_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [key, open, pages]);

  return (
    <PickField
      id="map-device-list"
      label="Device"
      listLabel="Devices"
      class="map-device"
      columns="two"
      text={text}
      onText={setText}
      opts={opts}
      textKey={key}
      onMore={() => setPages((p) => (p * PICKER_MAX <= opts.list.length ? p + 1 : p))}
      onOpen={setOpen}
      onChoose={props.onDevice}
      autoFocus={props.autoFocus}
    />
  );
}

/** The field Site: the sites of the inventory. Enter on an empty field gives the empty text. */
export function SiteField(props: { sites: readonly string[]; site: string; onSite: (site: string) => void }) {
  const [text, setText] = useState(props.site);
  const [pages, setPages] = useState(1);

  useEffect(() => setText(props.site), [props.site]);
  useEffect(() => setPages(1), [text]);

  const found = siteOptions(props.sites, text, pages);
  const opts: Options = { key: text, list: found.list.map((s) => ({ name: s, detail: "" })), more: found.more };

  return (
    <PickField
      id="map-site-list"
      label="Site"
      listLabel="Sites"
      class="map-device"
      columns="one"
      text={text}
      onText={setText}
      opts={opts}
      textKey={text}
      onMore={() => setPages((p) => (p * PICKER_MAX <= found.list.length ? p + 1 : p))}
      onOpen={() => undefined}
      onChoose={props.onSite}
    />
  );
}
