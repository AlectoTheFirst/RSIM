/// <reference types="node" />
// The fields of the query bar: the field module from the OpenAPI
// document, the check of the form of a value, the list of names of a
// field, and the request body, the command and the fields of an echo.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FIELD_SCHEMA, MODE_TEXT, SET_SYNTAX } from "../src/api/fields";
import {
  QUERY_FIELDS,
  checkValue,
  descriptionOf,
  filterValues,
  firstError,
  formOf,
  insertValue,
  kindOf,
  modeHelp,
  parseIp,
  valueToken,
  valuesOf,
} from "../src/page/fields";
import { fieldsOf, mcpCall, requestBody, rsimCommand } from "../src/page/query";

const openapi = JSON.parse(readFileSync(new URL("../../crates/rsim-api/openapi.json", import.meta.url), "utf8"));
const schemas = openapi.components.schemas;

describe("field module", () => {
  it("has each argument of a path query and of a set query, except topology and form", () => {
    const args = Object.keys(schemas.PathQueryArgs.properties).filter((k) => k !== "topology" && k !== "form");
    expect(Object.keys(FIELD_SCHEMA).sort()).toEqual(args.sort());
    expect(Object.keys(schemas.SetQueryArgs.properties).filter((k) => k !== "topology" && k !== "form").sort()).toEqual(args.sort());
  });

  it("puts each field in the query bar once", () => {
    expect([...QUERY_FIELDS].sort()).toEqual(Object.keys(FIELD_SCHEMA).sort());
    expect(new Set(QUERY_FIELDS).size).toBe(QUERY_FIELDS.length);
  });

  it("takes the descriptions, the ranges and the names from the OpenAPI document", () => {
    expect(descriptionOf("path", "destination.port")).toBe(schemas.PathQueryArgs.properties["destination.port"].description);
    expect(descriptionOf("set", "tcp_flags")).toBe(schemas.SetQueryArgs.properties["tcp_flags"].description);
    expect(FIELD_SCHEMA["network.vlan.id"].maximum).toBe(4095);
    expect(FIELD_SCHEMA["network.transport"].values).toEqual(schemas.Transport.enum);
    expect(FIELD_SCHEMA.fragment.values).toEqual(schemas.FragmentName.enum);
    expect(FIELD_SCHEMA.icmp_type.values).toEqual(schemas.IcmpName.enum);
    expect(FIELD_SCHEMA.tcp_flags.values).toEqual(schemas.TcpFlag.enum);
    expect(SET_SYNTAX).toBe(schemas.SetArg.description.replace(/\s+/g, " "));
    expect(MODE_TEXT.set).toBe(schemas.SetQueryArgs.description.replace(/\s+/g, " "));
  });

  it("gives each field a kind and a form in each mode", () => {
    expect(kindOf("source.ip")).toBe("address");
    expect(kindOf("destination.mac")).toBe("mac");
    expect(kindOf("ingress")).toBe("ingress");
    expect(kindOf("dscp")).toBe("number");
    expect(kindOf("icmp_type")).toBe("icmp");
    expect(kindOf("tcp_flags")).toBe("flags");
    expect(kindOf("fragment")).toBe("names");
    expect(kindOf("reply")).toBe("boolean");
    expect(formOf("path", "destination.port")).toBe("A number 0 to 65535.");
    expect(formOf("set", "destination.port")).toBe("A comma list of numbers 0 to 65535 and ranges a-b.");
    expect(formOf("path", "network.transport")).toBe("One of tcp, udp, icmp, icmpv6.");
    expect(modeHelp("set")).toContain(SET_SYNTAX);
    for (const k of QUERY_FIELDS) {
      expect(formOf("path", k).length).toBeGreaterThan(0);
      expect(formOf("set", k).length).toBeGreaterThan(0);
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
    expect(checkValue("path", "source.ip", "192.0.2.10")).toBeNull();
    expect(checkValue("path", "source.ip", "192.0.2.10/32")).toBeNull();
    expect(checkValue("path", "source.ip", "2001:db8::1/128")).toBeNull();
    expect(checkValue("path", "source.ip", "192.0.2.0/24")).toContain("is a prefix");
    expect(checkValue("path", "source.ip", "192.0.2.")).toBe('"192.0.2." is not an IP address');
    expect(checkValue("path", "source.ip", "")).toBeNull();
  });

  it("takes addresses and prefixes with no host bits in a set query", () => {
    expect(checkValue("set", "source.ip", "192.0.2.0/24, 198.51.100.7, 2001:db8::/32")).toBeNull();
    expect(checkValue("set", "source.ip", "192.0.2.5/24")).toBe('"192.0.2.5/24" is not an address or a prefix');
    expect(checkValue("set", "source.ip", "192.0.2.0/33")).not.toBeNull();
    expect(checkValue("set", "source.ip", "192.0.2.0/24,")).toBe('"" is not an address or a prefix');
  });

  it("takes numbers in range in a path query and ranges in a set query", () => {
    expect(checkValue("path", "destination.port", "65535")).toBeNull();
    expect(checkValue("path", "destination.port", "65536")).toBe('"65536" is not a number 0 to 65535');
    expect(checkValue("path", "destination.port", "80,443")).not.toBeNull();
    expect(checkValue("path", "dscp", "64")).not.toBeNull();
    expect(checkValue("set", "destination.port", "53,80,1024-65535")).toBeNull();
    expect(checkValue("set", "destination.port", "443-80")).not.toBeNull();
    expect(checkValue("set", "destination.port", "1 - 2")).not.toBeNull();
    expect(checkValue("set", "network.vlan.id", "4095")).toBeNull();
    expect(checkValue("set", "network.vlan.id", "4096")).not.toBeNull();
  });

  it("takes the names of a field as the server reads them", () => {
    expect(checkValue("path", "network.transport", "UDP")).toBeNull();
    expect(checkValue("path", "network.transport", "6")).toBeNull();
    expect(checkValue("path", "network.transport", "7")).not.toBeNull();
    expect(checkValue("set", "network.transport", "tcp, Udp")).toBeNull();
    expect(checkValue("path", "fragment", "first")).toBeNull();
    expect(checkValue("path", "fragment", "First")).not.toBeNull();
    expect(checkValue("path", "icmp_type", "echo-request")).toBeNull();
    expect(checkValue("path", "icmp_type", "8")).toBeNull();
    expect(checkValue("set", "icmp_type", "echo-request")).not.toBeNull();
    expect(checkValue("set", "icmp_type", "0,8")).toBeNull();
    expect(checkValue("path", "reply", "false")).toBeNull();
    expect(checkValue("path", "reply", "no")).not.toBeNull();
  });

  it("takes TCP flag names in a path query and flag values in a set query", () => {
    expect(checkValue("path", "tcp_flags", "syn, ack")).toBeNull();
    expect(checkValue("path", "tcp_flags", "syn+ack")).not.toBeNull();
    expect(checkValue("path", "tcp_flags", "SYN")).not.toBeNull();
    expect(checkValue("set", "tcp_flags", "syn,syn+ack,16-18")).toBeNull();
    expect(checkValue("set", "tcp_flags", "syn+bad")).not.toBeNull();
    expect(checkValue("set", "tcp_flags", "256")).not.toBeNull();
  });

  it("takes MAC addresses and an ingress point", () => {
    expect(checkValue("path", "source.mac", "00:00:5e:00:53:01")).toBeNull();
    expect(checkValue("path", "source.mac", "00:00:5e:00:53")).not.toBeNull();
    expect(checkValue("path", "source.mac", "0:00:5e:00:53:01")).not.toBeNull();
    expect(checkValue("set", "source.mac", "00:00:5e:00:53:01,00:00:5E:00:53:02")).toBeNull();
    expect(checkValue("path", "ingress", "r1/eth0")).toBeNull();
    expect(checkValue("path", "ingress", "r1/")).not.toBeNull();
    expect(checkValue("path", "ingress", "/eth0")).not.toBeNull();
  });

  it("names the first stated field with a wrong form", () => {
    expect(firstError("path", { "source.ip": "192.0.2.10", "destination.port": "99999", dscp: "70" })).toEqual({
      field: "destination.port",
      message: '"99999" is not a number 0 to 65535',
    });
    expect(firstError("path", { "source.ip": "192.0.2.10", "destination.ip": "", dscp: "46" })).toBeNull();
  });
});

describe("list of names", () => {
  it("proposes the names of a field in each mode", () => {
    expect(valuesOf("path", "network.transport")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(valuesOf("path", "icmp_type")).toEqual(["echo-request", "echo-reply"]);
    expect(valuesOf("set", "icmp_type")).toEqual([]);
    expect(valuesOf("path", "reply")).toEqual(["true", "false"]);
    expect(valuesOf("path", "source.port")).toEqual([]);
  });

  it("filters with no regard to case, the names that start with the text first", () => {
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "ICM")).toEqual(["icmp", "icmpv6"]);
    expect(filterValues(["tcp", "udp", "icmp", "icmpv6"], "p")).toEqual(["tcp", "udp", "icmp", "icmpv6"]);
    expect(filterValues(["unfragmented", "first", "later"], "te")).toEqual(["unfragmented", "later"]);
    expect(filterValues(["tcp", "udp"], "x")).toEqual([]);
  });

  it("filters by the item that is typed and puts a choice in its place", () => {
    expect(valueToken("set", "network.transport", "tcp, ud")).toBe("ud");
    expect(insertValue("set", "network.transport", "tcp, ud", "udp")).toBe("tcp, udp");
    expect(valueToken("path", "network.transport", "ud")).toBe("ud");
    expect(insertValue("path", "network.transport", "ud", "udp")).toBe("udp");
    expect(valueToken("set", "tcp_flags", "fin,syn+a")).toBe("a");
    expect(insertValue("set", "tcp_flags", "fin,syn+a", "ack")).toBe("fin,syn+ack");
    expect(insertValue("path", "tcp_flags", "syn,", "ack")).toBe("syn,ack");
  });
});

describe("query of the bar", () => {
  const fields = {
    "source.ip": "192.0.2.10",
    "destination.ip": "198.51.100.20",
    "network.transport": "tcp",
    "destination.port": "443",
    tcp_flags: "syn, ack",
    dscp: "46",
    icmp_type: "",
    reply: "false",
  };

  it("gives a path query numbers, a list of TCP flags and a boolean reply", () => {
    expect(requestBody("path", fields)).toEqual({
      "source.ip": "192.0.2.10",
      "destination.ip": "198.51.100.20",
      "network.transport": "tcp",
      "destination.port": 443,
      tcp_flags: ["syn", "ack"],
      dscp: 46,
      reply: false,
    });
    expect(requestBody("path", { icmp_type: "8" })).toEqual({ icmp_type: 8 });
    expect(requestBody("path", { icmp_type: "echo-reply" })).toEqual({ icmp_type: "echo-reply" });
  });

  it("gives a set query text and a boolean reply", () => {
    expect(requestBody("set", { "destination.port": "80,443", reply: "true" })).toEqual({
      mode: "set",
      "destination.port": "80,443",
      reply: true,
    });
  });

  it("gives the reply as --no-reply in an rsim command", () => {
    expect(rsimCommand("path", "builtin.mini-enterprise", fields)).toBe(
      "rsim path mini-enterprise --source.ip 192.0.2.10 --destination.ip 198.51.100.20 --destination.port 443 --network.transport tcp --tcp_flags syn,ack --dscp 46 --no-reply",
    );
    expect(JSON.parse(mcpCall("path", "builtin.mini-enterprise", { "destination.port": "53" })).arguments).toEqual({
      topology: "mini-enterprise",
      "destination.port": 53,
    });
  });

  it("reads the fields of an echo, with no protocol number next to a protocol name", () => {
    const echo = {
      topology: "mini-enterprise",
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
      tcp_flags: "syn,ack",
      reply: "false",
    });
    expect(fieldsOf({ "network.iana_number": 47 })).toEqual({ "network.iana_number": "47" });
  });
});
