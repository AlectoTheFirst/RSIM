// The fields of a query, from crates/rsim-api/openapi.json.
// scripts/fields.mjs writes this file: `npm run api`. Do not edit it.

/** The description of a set argument. */
export const SET_SYNTAX = "Set";

/** The description of the fields of a path query and of a set query. */
export const MODE_TEXT = {
  "path": "Path query fields",
  "set": "Set query fields"
} as const;

/**
 * Each field of a path query and of a set query: the description of each
 * mode, null for a mode that does not take the field, the JSON type of
 * the path query value, its largest number, and its names.
 */
export const FIELD_SCHEMA = {
  "destination.ip": {
    "path": "Destination address",
    "set": "Destination addresses",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "destination.mac": {
    "path": "Destination MAC",
    "set": "Destination MACs",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "destination.port": {
    "path": "Destination port",
    "set": "Destination ports",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "dscp": {
    "path": "DSCP",
    "set": "DSCP values",
    "type": "integer",
    "maximum": 63,
    "values": []
  },
  "ecn": {
    "path": "ECN",
    "set": "ECN values",
    "type": "integer",
    "maximum": 3,
    "values": []
  },
  "fragment": {
    "path": "Fragment",
    "set": "Fragments",
    "type": "string",
    "maximum": null,
    "values": [
      "unfragmented",
      "first",
      "later"
    ]
  },
  "icmp_code": {
    "path": "ICMP code",
    "set": "ICMP codes",
    "type": "integer",
    "maximum": 255,
    "values": []
  },
  "icmp_type": {
    "path": "ICMP type",
    "set": "ICMP types",
    "type": "integer",
    "maximum": 255,
    "values": [
      "echo-request",
      "echo-reply"
    ]
  },
  "ingress": {
    "path": "Ingress",
    "set": "Ingress",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "inner_l2_priority": {
    "path": "Inner layer 2 priority",
    "set": "Inner layer 2 priorities",
    "type": "integer",
    "maximum": 7,
    "values": []
  },
  "l2_priority": {
    "path": "Layer 2 priority",
    "set": "Layer 2 priorities",
    "type": "integer",
    "maximum": 7,
    "values": []
  },
  "network.iana_number": {
    "path": "Protocol number",
    "set": "Protocol numbers",
    "type": "integer",
    "maximum": 255,
    "values": []
  },
  "network.inner.vlan.id": {
    "path": "Inner VLAN",
    "set": "Inner VLANs",
    "type": "integer",
    "maximum": 4095,
    "values": []
  },
  "network.inner.vlan.tpid": {
    "path": "Inner TPID",
    "set": "Inner TPIDs",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "network.transport": {
    "path": "Protocol",
    "set": "Protocols",
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
    "path": "VLAN",
    "set": "VLANs",
    "type": "integer",
    "maximum": 4095,
    "values": []
  },
  "network.vlan.tpid": {
    "path": "TPID",
    "set": "TPIDs",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "reply": {
    "path": "Reply",
    "set": "Replies",
    "type": "boolean",
    "maximum": null,
    "values": []
  },
  "source.ip": {
    "path": "Source address",
    "set": "Source addresses",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "source.mac": {
    "path": "Source MAC",
    "set": "Source MACs",
    "type": "string",
    "maximum": null,
    "values": []
  },
  "source.port": {
    "path": "Source port",
    "set": "Source ports",
    "type": "integer",
    "maximum": 65535,
    "values": []
  },
  "tcp_flags": {
    "path": "TCP flags",
    "set": "TCP flags",
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
  },
  "unstated": {
    "path": "Unstated fields",
    "set": null,
    "type": "string",
    "maximum": null,
    "values": [
      "all",
      "defaults"
    ]
  }
} as const;

export type FieldName = keyof typeof FIELD_SCHEMA;
