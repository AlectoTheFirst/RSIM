//! The mask of the secrets in a VeloCloud section.

use crate::mask::{JsonMask, key_like, no_value_records, normalized, secret_key as common};

/// The mask of a VeloCloud section.
pub const MASK: JsonMask = JsonMask {
    key: secret_key,
    subtrees: &[],
    value_records: no_value_records,
};

/// The words of VeloCloud keys that name a secret anywhere in a key, in
/// lower case without `_`, `-`, `.` and spaces.
pub const SECRET_WORDS: &[&str] = &["activationkey", "md5"];

/// True for a VeloCloud key whose value is a secret: a key of the common
/// rule of `crate::mask`, a key with a word of `SECRET_WORDS`, or a key
/// that ends with `key` or `keys` and is not a public key.
pub fn secret_key(key: &str, snmp: bool) -> bool {
    let n = normalized(key);
    common(key, snmp) || SECRET_WORDS.iter().any(|w| n.contains(w)) || key_like(key)
}

/// A key of a coverage report through the mask of the URLs.
pub fn report_key(key: &str) -> String {
    crate::mask::url_secrets(key).unwrap_or_else(|| key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::check;
    use rsim_store::Format;
    use serde_json::json;

    #[test]
    fn a_masked_velocloud_section_shows_no_secret() {
        let v = json!([{
            "logicalId": "e-1",
            "activationKey": "FAKEACTIVATION",
            "configuration": {"enterprise": {"modules": [{
                "name": "deviceSettings",
                "edgeSpecificData": {
                    "segments": [{"bgp": {"neighbors": [{
                        "neighborIp": "192.0.2.1",
                        "md5Password": "FAKEMD5",
                        "md5": "FAKEMD5WORD"
                    }]}}],
                    "snmp": {"snmpv2c": {"community": "FAKECOMMUNITY"}},
                    "radius": {"sharedSecret": "FAKERADIUS"},
                    "vpn": {"preSharedKey": "FAKEPSK"}
                }
            }]}}
        }]);
        let bytes = v.to_string();
        check::masked(
            "velocloud",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &["192.0.2.1", "\"logicalId\": \"e-1\""],
        );
    }

    #[test]
    fn every_listed_place_of_a_velocloud_section_is_masked() {
        let mut listed = serde_json::Map::new();
        for (i, w) in crate::mask::SECRET_KEYS.iter().enumerate() {
            listed.insert(w.to_string(), json!(format!("FAKEK{i}")));
        }
        for (i, w) in crate::mask::SECRET_WORDS
            .iter()
            .chain(SECRET_WORDS)
            .enumerate()
        {
            listed.insert(format!("my_{w}_x"), json!([format!("FAKEW{i}")]));
        }
        listed.insert("url".into(), json!("https://admin:FAKEURLPW@192.0.2.5/x"));
        listed.insert("publicKey".into(), json!("kept-public"));
        let bytes = serde_json::Value::Object(listed).to_string();
        check::masked(
            "velocloud",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &["kept-public", "https://<secret>@192.0.2.5/x"],
        );
    }
}
