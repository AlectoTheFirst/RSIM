//! Addresses and prefixes.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 prefix. The host bits are always zero.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, len: u8) -> Self {
        let max = max_len(addr);
        assert!(len <= max, "prefix length {len} is too long for {addr}");
        let bits = addr_bits(addr) & mask(len, max);
        Self {
            addr: bits_addr(addr, bits),
            len,
        }
    }

    pub fn host(addr: IpAddr) -> Self {
        Self::new(addr, max_len(addr))
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    #[allow(
        clippy::len_without_is_empty,
        reason = "a prefix length, not a container size"
    )]
    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        let max = max_len(ip);
        addr_bits(ip) & mask(self.len, max) == addr_bits(self.addr)
    }

    /// Bit `i` of the prefix address, counted from the most significant bit.
    pub fn bit(&self, i: u8) -> bool {
        addr_bit(self.addr, i)
    }
}

/// Bit `i` of an address, counted from the most significant bit.
pub fn addr_bit(addr: IpAddr, i: u8) -> bool {
    let max = max_len(addr);
    debug_assert!(i < max);
    (addr_bits(addr) >> (max - 1 - i)) & 1 == 1
}

fn max_len(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn addr_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

fn bits_addr(like: IpAddr, bits: u128) -> IpAddr {
    match like {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(bits as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(bits)),
    }
}

fn mask(len: u8, max: u8) -> u128 {
    if len == 0 {
        0
    } else {
        let ones = (!0u128) << (128 - u32::from(len));
        ones >> (128 - u32::from(max))
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePrefixError(pub String);

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a prefix: {}", self.0)
    }
}

impl std::error::Error for ParsePrefixError {}

impl FromStr for Prefix {
    type Err = ParsePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParsePrefixError(s.to_string());
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| err())?;
        let len = match l {
            Some(l) => l.parse::<u8>().map_err(|_| err())?,
            None => max_len(addr),
        };
        if len > max_len(addr) {
            return Err(err());
        }
        if addr_bits(addr) & !mask(len, max_len(addr)) != 0 {
            return Err(err());
        }
        Ok(Prefix::new(addr, len))
    }
}

/// A MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mac(pub [u8; 6]);

impl FromStr for Mac {
    type Err = ParsePrefixError;

    /// Reads `00:00:5e:00:53:01` or `00-00-5e-00-53-01`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParsePrefixError(s.to_string());
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(err());
        }
        let mut m = [0u8; 6];
        for (b, p) in m.iter_mut().zip(parts) {
            if p.len() != 2 {
                return Err(err());
            }
            *b = u8::from_str_radix(p, 16).map_err(|_| err())?;
        }
        Ok(Mac(m))
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parse_and_contains() {
        let p: Prefix = "10.20.0.0/24".parse().unwrap();
        assert!(p.contains("10.20.0.53".parse().unwrap()));
        assert!(!p.contains("10.20.1.1".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
        assert!("10.20.0.1/24".parse::<Prefix>().is_err());
        let d: Prefix = "0.0.0.0/0".parse().unwrap();
        assert!(d.contains("8.8.8.8".parse().unwrap()));
        let v6: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
    }
}
