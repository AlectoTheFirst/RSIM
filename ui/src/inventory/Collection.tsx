// The settings of the collector: the history of the snapshot store. A change
// commits on Enter or when the focus leaves the field, and Escape cancels.
import { useEffect, useState } from "preact/hooks";
import { putCollection } from "../api/client";
import { type Inventory, collectionChecked } from "./model";
import { type Refuse, type Write, addKeys } from "./parts";
import { TextRow } from "./SettingsEditor";

export function CollectionSettings(props: { inv: Inventory; write: Write; refuse: Refuse }) {
  const stored = String(props.inv.collection.history_days);
  const [text, setText] = useState(stored);
  useEffect(() => setText(stored), [stored]);
  const commit = () => {
    if (text.trim() === stored) return;
    const c = collectionChecked(text);
    if (!c.ok) props.refuse(c.problem);
    else void props.write(() => putCollection(c.body));
  };
  const keys = addKeys(commit, () => setText(stored));
  return (
    <>
      <div class="inv-sec">Collection</div>
      <div class="inv-settings">
        <TextRow
          id="collection"
          k="history_days"
          label="history"
          note="days"
          draft={{ history_days: text }}
          h={{ onInput: (_, v) => setText(v), onPick: () => {}, keys: () => keys, onBlur: commit }}
        />
      </div>
    </>
  );
}
