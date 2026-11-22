/// <reference types="node" />
// The fields of the query bar: the field module from the OpenAPI
// document, the check of the form of a value, the list of names of a
// field, and the request body, the command and the fields of an echo.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FIELD_SCHEMA, MODE_TEXT, SET_SYNTAX } from "../src/api/fields";
import {
  QUERY_FIELDS,
  checkIn,
  checkValue,
  filterValues,
  firstError,
  formOf,
  insertValue,
  kindOf,
  FIELD_LABELS,
  labelOf,
  parseIp,
  queryMode,
  takes,
  valueToken,
  valuesOf,
} from "../src/page/fields";
import {
  defaultsOf,
  echoOfFields,
  explainCommand,
  fieldsOf,
  hasDefaults,
  mcpCall,
  requestBody,
  rsimCommand,
  toggleDefaults,
  unstatedLabel,
} from "../src/page/query";
import { notStated } from "../src/ladder/layout";

const openapi = JSON.parse(readFileSync(new URL("../../crates/rsim-api/openapi.json", import.meta.url), "utf8"));
const schemas = openapi.components.schemas;

describe("field module", () => {
  it("has each argument of a path query and of a set query, except topology and form", () => {
    const args = Object.keys(schemas.PathQueryArgs.properties).filter((k) => k !== "topology" && k !== "form");
    expect(Object.keys(FIELD_SCHEMA).sort()).toEqual(args.sort());
    const setArgs = Object.keys(schemas.SetQueryArgs.properties).filter((k) => k !== "topology" && k !== "form");
    expect(setArgs.sort()).toEqual(args.filter((k) => k !== "unstated").sort());
    expect(FIELD_SCHEMA.unstated.set).toBeNull();
    expect(FIELD_SCHEMA.unstated.values).toEqual(["all", "defaults"]);
  });

  it("puts each field in the query bar once", () => {
    expect([...QUERY_FIELDS].sort()).toEqual(Object.keys(FIELD_SCHEMA).sort());
    expect(new Set(QUERY_FIELDS).size).toBe(QUERY_FIELDS.length);
  });

  it("takes the descriptions, the ranges and the names from the OpenAPI document", () => {
    expect(FIELD_SCHEMA["destination.port"].path).toBe(schemas.PathQueryArgs.properties["destination.port"].description);
    expect(FIELD_SCHEMA.tcp_flags.set).toBe(schemas.SetQueryArgs.properties["tcp_flags"].description);
    expect(FIELD_SCHEMA["network.vlan.id"].maximum).toBe(4095);
    expect(FIELD_SCHEMA["network.transport"].values).toEqual(schemas.Transport.enum);
    expect(FIELD_SCHEMA.fragment.values).toEqual(schemas.FragmentName.enum);
    expect(FIELD_SCHEMA.icmp_type.values).toEqual(schemas.IcmpName.enum);
    expect(FIELD_SCHEMA.tcp_flags.values).toEqual(schemas.TcpFlag.enum);
    expect(SET_SYNTAX).toBe(schemas.SetArg.description.replace(/\s+/g, " "));
    expect(MODE_TEXT.set).toBe(schemas.SetQueryArgs.description.replace(/\s+/g, " "));
  });

  it("gives each field a kind and one form", () => {
    expect(kindOf("source.ip")).toBe("address");
    expect(kindOf("destination.mac")).toBe("mac");
    expect(kindOf("ingress")).toBe("ingress");
    expect(kindOf("dscp")).toBe("number");
    expect(kindOf("icmp_type")).toBe("icmp");
    expect(kindOf("tcp_flags")).toBe("flags");
    expect(kindOf("fragment")).toBe("names");
    expect(kindOf("reply")).toBe("boolean");
    expect(formOf("source.ip")).toBe("addresses and prefixes, comma list");
    expect(formOf("destination.port")).toBe("0 to 65535 and ranges a-b, comma list");
    expect(formOf("icmp_type")).toBe("0 to 255, echo-request, echo-reply, ranges a-b, comma list");
    expect(formOf("network.transport")).toBe("tcp, udp, icmp, icmpv6, comma list");
    for (const k of QUERY_FIELDS) expect(formOf(k).length).toBeGreaterThan(0);
  });
});

describe("field labels", () => {
  it("give each field of the query bar a short label of its own", () => {
    expect(Object.keys(FIELD_LABELS).sort()).toEqual([...QUERY_FIELDS].sort());
    for (const k of QUERY_FIELDS) {
      const label = labelOf(k);
      expect(label.length, k).toBeGreaterThan(0);
      expect(label.split(" ").length, k).toBeLessThanOrEqual(3);
      expect(label, k).not.toMatch(/[.!?]$/);
    }
  });
});

describe("form check", () => {
  it("reads IPv4 and IPv6 addresses as the server does", () => {
    expect(parseIp("192.0.2.1")?.width).toBe(32);
    expect(parseIp("2001:db8::1")?.width).toBe(128);
    expect(parseIp("::")?.bits).toBe(0n);
    expect(parseIp("::ffff:192.0.2.1")?.width).toBe(128);
    expect(parseIp("1:2:3:4:5:6:7:8")?.width).toBe(128);
    for (const bad of ["192.0.2", "192.0.2.256", "192.0.2.01", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", "2001:db8::g", ""]) {
      expect(parseIp(bad), bad).toBeNull();
    }
  });

  it("takes one address in a path query, and a host prefix of it", () => {
    expect(checkIn("path", "source.ip", "192.0.2.10")).toBeNull();
    expect(checkIn("path", "source.ip", "192.0.2.10/32")).toBeNull();
    expect(checkIn("path", "source.ip", "2001:db8::1/128")).toBeNull();
    expect(checkIn("path", "source.ip", "192.0.2.0/24")).toBe("prefix in a path query: 192.0.2.0/24");
    expect(checkIn("path", "source.ip", "192.0.2.")).toBe("not an IP address: 192.0.2.");
    expect(checkIn("path", "source.ip", "")).toBeNull();
  });

  it("takes addresses and prefixes with no host bits in a set query", () => {
    expect(checkIn("set", "source.ip", "192.0.2.0/24, 198.51.100.7, 2001:db8::/32")).toBeNull();
    expect(checkIn("set", "source.ip", "192.0.2.5/24")).toBe("not an address or a prefix: 192.0.2.5/24");
    expect(checkIn("set", "source.ip", "192.0.2.0/33")).not.toBeNull();
    expect(checkIn("set", "source.ip", "192.0.2.0/24,")).toBe("not an address or a prefix: empty item");
  });

  it("takes numbers in range in a path query and ranges in a set query", () => {
    expect(checkIn("path", "destination.port", "65535")).toBeNull();
    expect(checkIn("path", "destination.port", "65536")).toBe("not 0 to 65535: 65536");
    expect(checkIn("path", "destination.port", "80,443")).not.toBeNull();
    expect(checkIn("path", "dscp", "64")).not.toBeNull();
    expect(checkIn("set", "destination.port", "53,80,1024-65535")).toBeNull();
    expect(checkIn("set", "destination.port", "443-80")).not.toBeNull();
    expect(checkIn("set", "destination.port", "1 - 2")).not.toBeNull();
    expect(checkIn("set", "network.vlan.id", "4095")).toBeNull();
    expect(checkIn("set", "network.vlan.id", "4096")).not.toBeNull();
  });

  it("takes the names of a field as the server reads them", () => {
    expect(checkIn("path", "network.transport", "UDP")).toBeNull();
    expect(checkIn("path", "network.transport", "6")).toBeNull();
    expect(checkIn("path", "network.transport", "7")).not.toBeNull();
    expect(checkIn("set", "network.transport", "tcp, Udp")).toBeNull();
    expect(checkIn("path", "fragment", "first")).toBeNull();
    expect(checkIn("path", "fragment", "First")).not.toBeNull();
    expect(checkIn("path", "icmp_type", "echo-request")).toBeNull();
    expect(checkIn("path", "icmp_type", "8")).toBeNull();
    expect(checkIn("set", "icmp_type", "echo-request")).not.toBeNull();
    expect(checkIn("set", "icmp_type", "0,8")).toBeNull();
    expect(checkIn("path", "reply", "false")).toBeNull();
    expect(checkIn("path", "reply", "no")).not.toBeNull();
  });

  it("takes the flags of one packet with + in a path query and flag values in a set query", () => {
    expect(checkIn("path", "tcp_flags", "syn+ack")).toBeNull();
    expect(checkIn("path", "tcp_flags", "syn + ack")).toBeNull();
    expect(checkIn("path", "tcp_flags", "syn,ack")).not.toBeNull();
    expect(checkIn("path", "tcp_flags", "SYN")).not.toBeNull();
    expect(checkIn("set", "tcp_flags", "syn,syn+ack,16-18")).toBeNull();
    expect(checkIn("set", "tcp_flags", "syn+bad")).not.toBeNull();
    expect(checkIn("set", "tcp_flags", "256")).not.toBeNull();
  });

  it("takes MAC addresses and an ingress point", () => {
    expect(checkIn("path", "source.mac", "00:00:5e:00:53:01")).toBeNull();
    expect(checkIn("path", "source.mac", "00:00:5e:00:53")).not.toBeNull();
    expect(checkIn("path", "source.mac", "0:00:5e:00:53:01")).not.toBeNull();
    expect(checkIn("set", "source.mac", "00:00:5e:00:53:01,00:00:5E:00:53:02")).toBeNull();
    expect(checkIn("path", "ingress", "r1/eth0")).toBeNull();
    expect(checkIn("path", "ingress", "r1/")).not.toBeNull();
    expect(checkIn("path", "ingress", "/eth0")).not.toBeNull();
  });

  it("names the first stated field with a wrong form", () => {
    expect(firstError({ "source.ip": "192.0.2.10", "destination.port": "99999", dscp: "70" })).toEqual({
      field: "destination.port",
      message: "not 0 to 65535 or a range a-b: 99999",
    });
    expect(firstError({ "source.ip": "192.0.2.10", "destination.ip": "", dscp: "46" })).toBeNull();
    expect(firstError({ "source.ip": "192.0.2.0/24", "destination.port": "1-1000" })).toBeNull();
  });

  it("takes a value of either query type in one field", () => {
    expect(checkValue("source.ip", "192.0.2.10")).toBeNull();
    expect(checkValue("source.ip", "192.0.2.0/24,198.51.100.7")).toBeNull();
    expect(checkValue("source.ip", "192.0.2.5/24")).toBe("not an address or a prefix: 192.0.2.5/24");
    expect(checkValue("destination.port", "45000")).toBeNull();
    expect(checkValue("destination.port", "1-1000")).toBeNull();
    expect(checkValue("icmp_type", "echo-request")).toBeNull();
    expect(checkValue("icmp_type", "0,8")).toBeNull();
    expect(checkValue("icmp_type", "ping")).toBe("not 0 to 255, echo-request, echo-reply or a range a-b: ping");
    expect(checkValue("tcp_flags", "syn+ack")).toBeNull();
    expect(checkValue("tcp_flags", "syn,syn+ack")).toBeNull();
    expect(checkValue("unstated", "defaults")).toBeNull();
  });

  it("refuses an ICMP name when another field makes a set query", () => {
    expect(firstError({ "source.ip": "192.0.2.0/24", icmp_type: "echo-request" })).toEqual({
      field: "icmp_type",
      message: "not 0 to 255 or a range a-b: echo-request",
    });
    expect(firstError({ "source.ip": "192.0.2.1", icmp_type: "echo-request" })).toBeNull();
  });
});

describe("query type", () => {
  it("is a path query when each stated field has one value", () => {
    expect(queryMode({})).toBe("path");
    expect(queryMode({ "source.ip": "192.0.2.10", "destination.ip": "198.51.100.20", "destination.port": "443", "network.transport": "tcp" })).toBe("path");
    expect(queryMode({ "source.ip": "192.0.2.10/32", "destination.ip": "2001:db8::1/128" })).toBe("path");
    expect(queryMode({ tcp_flags: "syn+ack", icmp_type: "echo-reply", reply: "false", ingress: "r1/eth0" })).toBe("path");
  });

  it("is a set query when a field has a prefix, a list or a range", () => {
    expect(queryMode({ "source.ip": "192.168.2.0/24" })).toBe("set");
    expect(queryMode({ "source.ip": "192.0.2.10,192.0.2.11" })).toBe("set");
    expect(queryMode({ "source.port": "1-1000" })).toBe("set");
    expect(queryMode({ "network.transport": "tcp,udp" })).toBe("set");
    expect(queryMode({ tcp_flags: "syn,syn+ack" })).toBe("set");
    expect(queryMode({ tcp_flags: "18" })).toBe("set");
    expect(queryMode({ "source.mac": "00:00:5e:00:53:01,00:00:5e:00:53:02" })).toBe("set");
  });

  it("keeps a value with a wrong form out of the choice", () => {
    expect(queryMode({ "source.ip": "192.0.2.5/24" })).toBe("path");
    expect(queryMode({ "destination.port": "99999" })).toBe("path");
  });
});

describe("list of names", () => {
  it("proposes the names of a field", () => {
    expect(valuesOf("network.transport")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(valuesOf("icmp_type")).toEqual(["echo-request", "echo-reply"]);
    expect(valuesOf("reply")).toEqual(["true", "false"]);
    expect(valuesOf("source.port")).toEqual([]);
  });

  it("filters with no regard to case, the names that start with the text first", () => {
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "ICM")).toEqual(["icmp", "icmpv6"]);
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "p")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(filterValues(["unfragmented", "first", "later"], "te")).toEqual(["unfragmented", "later"]);
    expect(filterValues(["tcp", "udp"], "x")).toEqual([]);
  });

  it("filters by the item that is typed and puts a choice in its place", () => {
    expect(valueToken("network.transport", "tcp, ud")).toBe("ud");
    expect(insertValue("network.transport", "tcp, ud", "udp")).toBe("tcp, udp");
    expect(valueToken("network.transport", "ud")).toBe("ud");
    expect(insertValue("network.transport", "ud", "udp")).toBe("udp");
    expect(valueToken("tcp_flags", "fin,syn+a")).toBe("a");
    expect(insertValue("tcp_flags", "fin,syn+a", "ack")).toBe("fin,syn+ack");
    expect(insertValue("tcp_flags", "syn+", "ack")).toBe("syn+ack");
    expect(insertValue("ingress", "r1/e", "r1/eth0")).toBe("r1/eth0");
  });
});

describe("query of the bar", () => {
  const fields = {
    "source.ip": "192.0.2.10",
    "destination.ip": "198.51.100.20",
    "network.transport": "tcp",
    "destination.port": "443",
    tcp_flags: "syn+ack",
    dscp: "46",
    icmp_type: "",
    reply: "false",
  };

  it("gives a path query numbers, a list of TCP flags and a boolean reply", () => {
    expect(requestBody(fields)).toEqual({
      "source.ip": "192.0.2.10",
      "destination.ip": "198.51.100.20",
      "network.transport": "tcp",
      "destination.port": 443,
      tcp_flags: ["syn", "ack"],
      dscp: 46,
      reply: false,
    });
    expect(requestBody({ icmp_type: "8" })).toEqual({ icmp_type: 8 });
    expect(requestBody({ icmp_type: "echo-reply" })).toEqual({ icmp_type: "echo-reply" });
  });

  it("gives a set query text and a boolean reply", () => {
    expect(requestBody({ "destination.port": "80,443", reply: "true" })).toEqual({
      mode: "set",
      "destination.port": "80,443",
      reply: true,
    });
    expect(requestBody({ "source.ip": "192.168.2.0/24", "source.port": "1-1000", tcp_flags: "syn+ack" })).toEqual({
      mode: "set",
      "source.ip": "192.168.2.0/24",
      "source.port": "1-1000",
      tcp_flags: "syn+ack",
    });
  });

  it("gives the reply as --no-reply in an rsim command", () => {
    expect(rsimCommand("path", "snapshot-2026-11-22-140504", fields)).toBe(
      "rsim path store:<data folder> --source.ip 192.0.2.10 --destination.ip 198.51.100.20 --destination.port 443 --network.transport tcp --tcp_flags syn,ack --dscp 46 --no-reply",
    );
    expect(JSON.parse(mcpCall("path", "snapshot-2026-11-22-140504", { "destination.port": "53" })).arguments).toEqual({
      topology: "store",
      "destination.port": 53,
    });
  });

  it("reads the fields of an echo, with no protocol number next to a protocol name", () => {
    const echo = {
      topology: "store",
      "source.ip": "192.0.2.10",
      "network.iana_number": 6,
      "network.transport": "tcp",
      tcp_flags: ["syn", "ack"],
      reply: false,
      dscp: null,
    };
    expect(fieldsOf(echo)).toEqual({
      "source.ip": "192.0.2.10",
      "network.transport": "tcp",
      tcp_flags: "syn+ack",
      reply: "false",
    });
    expect(queryMode(fieldsOf(echo))).toBe("path");
    expect(fieldsOf({ "network.iana_number": 47 })).toEqual({ "network.iana_number": "47" });
  });
});

describe("unstated setting", () => {
  it("is a field of a path query only, with the names all and defaults", () => {
    expect(takes("path", "unstated")).toBe(true);
    expect(takes("set", "unstated")).toBe(false);
    expect(QUERY_FIELDS.filter((k) => takes("set", k)).length).toBe(QUERY_FIELDS.length - 1);
    expect(kindOf("unstated")).toBe("names");
    expect(valuesOf("unstated")).toEqual(["all", "defaults"]);
    expect(formOf("unstated")).toBe("all, defaults");
    expect(labelOf("unstated")).toBe("unstated fields");
    expect(checkValue("unstated", "defaults")).toBeNull();
    expect(checkValue("unstated", "some")).toBe("not one of all, defaults: some");
  });

  it("goes into the request, the rsim command, the explain command and the MCP call with defaults", () => {
    const f = { "source.ip": "172.31.10.20", "destination.ip": "10.20.0.53", "network.transport": "udp", unstated: "defaults" };
    expect(requestBody(f)).toEqual({ "source.ip": "172.31.10.20", "destination.ip": "10.20.0.53", "network.transport": "udp", unstated: "defaults" });
    expect(rsimCommand("path", "snapshot-2026-11-22-140504", f)).toBe(
      "rsim path store:<data folder> --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --unstated defaults",
    );
    expect(explainCommand("path", "snapshot-2026-11-22-140504", f, 0, 3, null)).toContain(" --unstated defaults --branch 0 --step 3");
    expect(JSON.parse(mcpCall("path", "snapshot-2026-11-22-140504", f))).toEqual({
      name: "path_query",
      arguments: { topology: "store", "source.ip": "172.31.10.20", "destination.ip": "10.20.0.53", "network.transport": "udp", unstated: "defaults" },
    });
  });

  it("changes nothing with all, and a set query leaves it out", () => {
    const base = { "source.ip": "172.31.10.20", "network.transport": "udp" };
    const all = { ...base, unstated: "all" };
    expect(requestBody(all)).toEqual(requestBody(base));
    expect(rsimCommand("path", "snapshot-2026-11-22-140504", all)).toBe(rsimCommand("path", "snapshot-2026-11-22-140504", base));
    expect(mcpCall("path", "snapshot-2026-11-22-140504", all)).toBe(mcpCall("path", "snapshot-2026-11-22-140504", base));
    const defaults = { ...base, "source.ip": "172.31.10.0/24", unstated: "defaults" };
    expect(requestBody(defaults)).toEqual(requestBody({ ...base, "source.ip": "172.31.10.0/24" }));
    expect(rsimCommand("set", "snapshot-2026-11-22-140504", { ...base, unstated: "defaults" })).toBe(rsimCommand("set", "snapshot-2026-11-22-140504", base));
    expect(mcpCall("set", "snapshot-2026-11-22-140504", { ...base, unstated: "defaults" })).toBe(mcpCall("set", "snapshot-2026-11-22-140504", base));
    expect(firstError({ "source.ip": "172.31.10.0/24", unstated: "defaults" })).toBeNull();
  });

  it("comes back from the echo of a path query", () => {
    expect(fieldsOf({ "source.ip": "172.31.10.20", unstated: "defaults" })).toEqual({ "source.ip": "172.31.10.20", unstated: "defaults" });
  });
});

describe("unstated button", () => {
  it("switches between all and defaults, and all leaves the request as it is", () => {
    const base = { "source.ip": "172.31.10.20", "network.transport": "udp" };
    const on = toggleDefaults(base);
    expect(hasDefaults(base)).toBe(false);
    expect(hasDefaults(on)).toBe(true);
    expect(requestBody(on)).toEqual({ ...requestBody(base), unstated: "defaults" });
    expect(rsimCommand("path", "snapshot-2026-11-22-140504", on)).toBe(`${rsimCommand("path", "snapshot-2026-11-22-140504", base)} --unstated defaults`);
    const off = toggleDefaults(on);
    expect(hasDefaults(off)).toBe(false);
    expect(requestBody(off)).toEqual(requestBody(base));
    expect(mcpCall("path", "snapshot-2026-11-22-140504", off)).toBe(mcpCall("path", "snapshot-2026-11-22-140504", base));
  });

  it("reads the count of the fields that are not stated with all, and defaults with defaults", () => {
    expect(unstatedLabel(false)).toBe("not stated");
    expect(unstatedLabel(true)).toBe("defaults");
  });

  it("names the defaults that apply, in the words of the note of the answer", () => {
    const udp = { "source.ip": "172.31.10.20", "destination.ip": "10.20.0.53", "network.transport": "udp", "destination.port": "53" };
    expect(defaultsOf(udp)).toEqual(["dscp 0", "ecn 0", "no VLAN", "source.port 49152-65535"]);
    expect(defaultsOf({ ...udp, "source.port": "40000" })).toEqual(["dscp 0", "ecn 0", "no VLAN"]);
    expect(defaultsOf({ ...udp, "network.transport": "tcp" })).toEqual(["dscp 0", "ecn 0", "no VLAN", "tcp syn", "source.port 49152-65535"]);
    expect(defaultsOf({ ...udp, "network.transport": "tcp", tcp_flags: "ack", "source.port": "40000" })).toEqual(["dscp 0", "ecn 0", "no VLAN"]);
    expect(defaultsOf({ "network.transport": "icmp" })).toEqual(["dscp 0", "ecn 0", "no VLAN", "icmp_type echo-request", "icmp_code 0"]);
    expect(defaultsOf({ "network.iana_number": "58" })).toEqual(["dscp 0", "ecn 0", "no VLAN", "icmp_type echo-request", "icmp_code 0"]);
    expect(defaultsOf({ "network.transport": "udp", dscp: "46", "network.vlan.id": "10", fragment: "later" })).toEqual(["ecn 0"]);
    const two = { "network.transport": "udp", dscp: "46", fragment: "later", "network.vlan.id": "10", "network.inner.vlan.id": "20" };
    expect(defaultsOf(two)).toEqual(["ecn 0", "network.vlan.tpid 0x88a8"]);
    expect(defaultsOf({ ...two, "network.vlan.tpid": "37120" })).toEqual(["ecn 0"]);
  });

  it("counts the fields of the bar that are not stated with no answer", () => {
    const f = { "source.ip": "172.31.10.20", "network.transport": "udp", unstated: "defaults" };
    const echo = echoOfFields(f);
    expect(echo).not.toHaveProperty("unstated");
    const n = notStated(echo);
    expect(n).toContain("dscp");
    expect(n).not.toContain("source.ip");
    expect(n).not.toContain("network.transport");
    for (const k of ["network.vlan.tpid", "network.inner.vlan.id", "inner_l2_priority", "network.inner.vlan.tpid"]) {
      expect(echo).toHaveProperty(k, null);
      expect(n).not.toContain(k);
    }
  });
});
