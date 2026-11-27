//! The routing defaults of each platform.

/// The platform of a device for its routing defaults. VyOS runs FRR, and
/// `FrrTraditional` and `FrrDatacenter` are the 2 defaults profiles of FRR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    Iosxe,
    Iosxr,
    Nxos,
    FrrTraditional,
    FrrDatacenter,
}

/// The origin of a route for its administrative distance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Connected,
    Static,
    Ebgp,
    Ospf,
    Ibgp,
    /// A BGP route that the device originates, for example an aggregate.
    LocalBgp,
}

/// The distance of an origin that the table does not hold. It ranks below
/// each origin of the table.
pub const UNKNOWN_DISTANCE: u8 = 255;

impl Platform {
    /// The administrative distance of a route of `origin` in the main route
    /// table. The values are the defaults of HST `simul/platforms.py`.
    pub fn distance(self, origin: Origin) -> u8 {
        match origin {
            Origin::Connected => 0,
            Origin::Static => 1,
            Origin::Ebgp => 20,
            Origin::Ospf => 110,
            Origin::Ibgp => 200,
            Origin::LocalBgp => match self {
                Platform::Nxos => 220,
                _ => 200,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connected_route_ranks_above_a_static_route_and_nx_os_ranks_a_local_bgp_route_at_220() {
        assert!(
            Platform::Iosxe.distance(Origin::Connected) < Platform::Iosxe.distance(Origin::Static)
        );
        assert_eq!(Platform::Nxos.distance(Origin::LocalBgp), 220);
        assert_eq!(Platform::Iosxr.distance(Origin::LocalBgp), 200);
        assert_eq!(Platform::FrrTraditional.distance(Origin::Ospf), 110);
    }
}
