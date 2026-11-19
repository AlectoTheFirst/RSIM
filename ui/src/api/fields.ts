// The fields of a query, from crates/rsim-api/openapi.json.
// scripts/fields.mjs writes this file: `npm run api`. Do not edit it.

/** The description of a set argument. */
export const SET_SYNTAX = "A set: an address, a prefix, a number, a range such as 1-1023, or a comma list. A field that is not given has all values.";

/** The description of the fields of a path query and of a set query. */
export const MODE_TEXT = {
  "path": "The fields of a path query. A field that the query does not state is not known.",
  "set": "The fields of a set query. Each field takes a set. A field that is not given has all values."
} as const;

/**
 * Each field of a path query and of a set query: the description of each
 * mode, the JSON type of the path query value, its largest number, and
 * its names.
 */
export const FIELD_SCHEMA = {
  "destination.ip": {
    "path": "The destination IP address.",
    "set": "The destination addresses.",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "destination.mac": {
    "path": "The destination MAC address: 6 hexadecimal bytes with colons.",
    "set": "The destination MAC addresses.",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "destination.port": {
    "path": "The destination port.",
    "set": "The destination ports.",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "dscp": {
    "path": "The DSCP.",
    "set": "The DSCP values.",
    "type": "integer",
    "maximum": 63,
    "values": []
  },
  "ecn": {
    "path": "The ECN.",
    "set": "The ECN values.",
    "type": "integer",
    "maximum": 3,
    "values": []
  },
  "fragment": {
    "path": "The fragment state.",
    "set": "The fragment states.",
    "type": "string",
    "maximum": null,
    "values": [
      "unfragmented",
      "first",
      "later"
    ]
  },
  "icmp_code": {
    "path": "The ICMP code.",
    "set": "The ICMP codes.",
    "type": "integer",
    "maximum": 255,
    "values": []
  },
  "icmp_type": {
    "path": "The ICMP type: 0 to 255, echo-request or echo-reply.",
    "set": "The ICMP types.",
    "type": "integer",
    "maximum": 255,
    "values": [
      "echo-request",
      "echo-reply"
    ]
  },
  "ingress": {
    "path": "The ingress point as <device>/<interface>. Without it, the attachment records of the source address give the ingress.",
    "set": "The ingress point as <device>/<interface>. Without it, the attachment records of the source addresses give the ingress.",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "l2_priority": {
    "path": "The layer 2 priority. It needs network.vlan.id.",
    "set": "The layer 2 priorities.",
    "type": "integer",
    "maximum": 7,
    "values": []
  },
  "network.iana_number": {
    "path": "The protocol number.",
    "set": "The protocol numbers.",
    "type": "integer",
    "maximum": 255,
    "values": []
  },
  "network.transport": {
    "path": "The protocol name. Give network.iana_number or network.transport.",
    "set": "The protocol names.",
    "type": "string",
    "maximum": null,
    "values": [
      "tcp",
      "udp",
      "icmp",
      "icmpv6"
    ]
  },
  "network.vlan.id": {
    "path": "The VLAN tag.",
    "set": "The VLAN tags.",
    "type": "integer",
    "maximum": 4095,
    "values": []
  },
  "reply": {
    "path": "Run the reply. The default is true.",
    "set": "Run the replies. The default is true.",
    "type": "boolean",
    "maximum": null,
    "values": []
  },
  "source.ip": {
    "path": "The source IP address.",
    "set": "The source addresses.",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "source.mac": {
    "path": "The source MAC address: 6 hexadecimal bytes with colons.",
    "set": "The source MAC addresses.",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "source.port": {
    "path": "The source port.",
    "set": "The source ports.",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "tcp_flags": {
    "path": "The TCP flags that are set.",
    "set": "The TCP flag values: numbers, ranges, or flag names joined with +.",
    "type": "list",
    "maximum": null,
    "values": [
      "fin",
      "syn",
      "rst",
      "psh",
      "ack",
      "urg",
      "ece",
      "cwr"
    ]
  }
} as const;

export type FieldName = keyof typeof FIELD_SCHEMA;
