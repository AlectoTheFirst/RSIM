//! Identifiers. Each identifier is an ordered, cheaply cloned string, so that
//! ordered collections give a deterministic order.

use std::fmt;
use std::sync::Arc;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Arc<str>);

        impl $name {
            pub fn new(s: impl AsRef<str>) -> Self {
                Self(Arc::from(s.as_ref()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), &*self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::new(s)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(Arc::from(s))
            }
        }

        impl From<&$name> for $name {
            fn from(s: &$name) -> Self {
                s.clone()
            }
        }
    };
}

id_type!(
    /// One function instance in the compiled twin.
    FunctionId
);
id_type!(
    /// A device: router, firewall, switch, access point or inline appliance.
    DeviceId
);
id_type!(
    /// A layer 3 interface or a physical port used as an interface.
    InterfaceId
);
id_type!(
    /// A VRF, qualified by its device where the vendor makes it local.
    VrfId
);
id_type!(
    /// A firewall zone.
    ZoneId
);
id_type!(
    /// A bridge domain: one flood domain. Its identity is not a VLAN number.
    BridgeDomainId
);
id_type!(
    /// A layer 2 port.
    PortId
);
id_type!(
    /// An endpoint: a host that sends and receives packets.
    EndpointId
);
id_type!(
    /// A named object that a function reads: address group, route table, policy.
    ObjectId
);
id_type!(
    /// A matched application.
    ApplicationId
);
