// The hooks of the entry point list, rendered with Preact into a stub
// container: the request count of the button Select entry point, and the
// rows of the list by twin.
import { h, render } from "preact";
import { act } from "preact/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EntryOption } from "../src/page/pick";

type Rows = { columns: string[]; rows: unknown[][] };
const pending: { twin: string; table: string; params: Record<string, string>; resolve: (t: Rows) => void }[] = [];

vi.mock("../src/api/client", () => ({
  tableRows: (twin: string, table: string, params: Record<string, string>) =>
    new Promise<Rows>((resolve) => pending.push({ twin, table, params, resolve })),
}));

const { useAsk, useEntryList } = await import("../src/page/Picker");

// The answers that resolved reach their handlers.
const settled = () => new Promise<void>((r) => queueMicrotask(() => queueMicrotask(() => queueMicrotask(r))));

// A container that holds a component that renders no element.
const root = () => ({ childNodes: [] }) as unknown as HTMLElement;

let container: HTMLElement;

beforeEach(() => {
  vi.useFakeTimers();
  pending.length = 0;
  container = root();
});

afterEach(async () => {
  await act(() => render(null, container));
  vi.useRealTimers();
});

describe("request count of Select entry point", () => {
  function Ask(props: { count: number; onAsk: () => void }) {
    useAsk(props.count, props.onAsk);
    return null;
  }

  it("is not a request when the bar mounts with a count from an earlier press", async () => {
    const onAsk = vi.fn();
    await act(() => render(h(Ask, { count: 3, onAsk }), container));
    expect(onAsk).not.toHaveBeenCalled();
  });

  it("is a request each time it changes after the mount, and once for each change", async () => {
    const onAsk = vi.fn();
    await act(() => render(h(Ask, { count: 3, onAsk }), container));
    await act(() => render(h(Ask, { count: 4, onAsk }), container));
    expect(onAsk).toHaveBeenCalledTimes(1);
    await act(() => render(h(Ask, { count: 4, onAsk }), container));
    expect(onAsk).toHaveBeenCalledTimes(1);
    await act(() => render(h(Ask, { count: 5, onAsk }), container));
    expect(onAsk).toHaveBeenCalledTimes(2);
  });

  it("is not a request when the bar mounts again with the same count", async () => {
    const onAsk = vi.fn();
    await act(() => render(h(Ask, { count: 3, onAsk }), container));
    await act(() => render(h(Ask, { count: 4, onAsk }), container));
    await act(() => render(null, container));
    await act(() => render(h(Ask, { count: 4, onAsk }), container));
    expect(onAsk).toHaveBeenCalledTimes(1);
  });
});

describe("rows of the entry point list", () => {
  let shown: EntryOption[] = [];
  function Entries(props: { twin: string; value: string }) {
    shown = useEntryList(props.twin, props.value, true, null, 1).list;
    return null;
  }

  async function answer(twin: string, rows: Rows) {
    await act(() => {
      vi.advanceTimersByTime(200);
    });
    const reqs = pending.filter((r) => r.twin === twin);
    expect(reqs.length).toBeGreaterThan(0);
    await act(async () => {
      for (const r of reqs) r.resolve(rows);
      await settled();
    });
  }

  it("are the devices of the shown twin, not those of the twin before it", async () => {
    await act(() => render(h(Entries, { twin: "a", value: "" }), container));
    await answer("a", { columns: ["device"], rows: [["ra1"], ["ra2"]] });
    expect(shown.map((o) => o.name)).toEqual(["ra1", "ra2"]);

    await act(() => render(h(Entries, { twin: "b", value: "" }), container));
    expect(shown).toEqual([]);
    await answer("b", { columns: ["device"], rows: [["rb1"]] });
    expect(shown.map((o) => o.name)).toEqual(["rb1"]);
  });

  it("are the entry interfaces of both forms of the device of the text", async () => {
    await act(() => render(h(Entries, { twin: "a", value: "sw1/" }), container));
    await act(() => {
      vi.advanceTimersByTime(200);
    });
    expect(pending.map((r) => r.params["function.prefix"])).toEqual(["sw1/in/", "sw1/host/"]);
    await act(async () => {
      pending[0]!.resolve({ columns: ["function"], rows: [["sw1/in/vlan10"]] });
      pending[1]!.resolve({ columns: ["function"], rows: [["sw1/host/port/1"], ["sw1/host/port/2"]] });
      await settled();
    });
    expect(shown.map((o) => o.value)).toEqual(["sw1/port/1", "sw1/port/2", "sw1/vlan10"]);
  });
});
