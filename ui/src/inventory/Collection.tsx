// The part Collection: the history of the snapshot store. A change commits
// on Enter or when the focus leaves the field, and Escape cancels.
import { useEffect, useState } from "preact/hooks";
import { putCollection } from "../api/client";
import { Card } from "../page/Card";
import { type Inventory, collectionChecked } from "./model";
import { type Refuse, type Write, addKeys } from "./parts";

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
    <Card title="Collection">
      <label class="inv-field inv-collection" for="collection-history_days">
        <span class="t-label muted">history</span>
        <span class="inv-control">
          <input
            id="collection-history_days"
            class={`t-value inv-number${text.trim() !== stored ? " param" : ""}`}
            value={text}
            spellcheck={false}
            autoComplete="off"
            onInput={(e) => setText(e.currentTarget.value)}
            onKeyDown={keys}
            onBlur={commit}
          />
          <span class="t-label muted">days</span>
        </span>
      </label>
    </Card>
  );
}
