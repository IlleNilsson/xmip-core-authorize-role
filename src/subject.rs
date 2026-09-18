//! Who an assignment is for: the fact on an identity a role is granted by.
//!
//! Four facts, each one of the five the record keeps (ADR-0019 clause 6): the
//! Party the identity resolved to, the value the gate recorded under one
//! mechanism, a claim carried as evidence — a group list from a token or a
//! directory — and the organizational unit of a distinguished name.

use context::AuthenticatedIdentity;
use std::fmt;
use xcore::PartyId;

/// The fact a role is granted by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// The identity resolved to this Party.
    Party(PartyId),
    /// The gate recorded this value, under this mechanism or under any.
    Identity {
        mechanism: Option<String>,
        value: String,
    },
    /// The identity carries evidence under this name whose value is this, or
    /// is a comma-separated list holding it — the shape a `groups` claim
    /// takes.
    Claim { name: String, value: String },
    /// The value is a distinguished name with this `OU`.
    Unit(String),
}

impl Subject {
    /// A Party, by the identifier the gate resolved it to.
    #[must_use]
    pub const fn party(party: PartyId) -> Self {
        Self::Party(party)
    }

    /// A recorded value under any mechanism.
    #[must_use]
    pub fn identity(value: impl Into<String>) -> Self {
        Self::Identity {
            mechanism: None,
            value: value.into(),
        }
    }

    /// A recorded value under one mechanism, by the name the catalog declares.
    #[must_use]
    pub fn identity_by(mechanism: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Identity {
            mechanism: Some(mechanism.into()),
            value: value.into(),
        }
    }

    /// A claim carried as evidence.
    #[must_use]
    pub fn claim(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Claim {
            name: name.into(),
            value: value.into(),
        }
    }

    /// An organizational unit of a distinguished name.
    #[must_use]
    pub fn unit(unit: impl Into<String>) -> Self {
        Self::Unit(unit.into())
    }

    /// Whether this identity is the subject.
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Party(party) => identity.party_id == Some(*party),
            Self::Identity { mechanism, value } => {
                mechanism
                    .as_ref()
                    .is_none_or(|name| name == identity.mechanism.name())
                    && *value == identity.value
            }
            Self::Claim { name, value } => identity
                .evidence
                .iter()
                .filter(|(evidence, _)| evidence == name)
                .any(|(_, held)| held.split(',').any(|item| item.trim() == value)),
            Self::Unit(unit) => units_of(&identity.value).any(|held| held == unit),
        }
    }
}

/// Every `OU` of a distinguished name, in order. Not a DN: none.
fn units_of(name: &str) -> impl Iterator<Item = &str> {
    name.split(',').filter_map(|component| {
        let (kind, value) = component.trim().split_once('=')?;
        kind.trim().eq_ignore_ascii_case("OU").then(|| value.trim())
    })
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Party(party) => write!(f, "Party {party}"),
            Self::Identity {
                mechanism: Some(mechanism),
                value,
            } => write!(f, "{mechanism}={value}"),
            Self::Identity {
                mechanism: None,
                value,
            } => f.write_str(value),
            Self::Claim { name, value } => write!(f, "{name}={value}"),
            Self::Unit(unit) => write!(f, "OU={unit}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, mechanism};

    fn certificate() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(1))
        .with_evidence("groups", "shippers, billing-readers")
    }

    #[test]
    fn a_party_and_a_value_each_name_the_identity() {
        assert!(Subject::party(PartyId::new(1)).matches(&certificate()));
        assert!(!Subject::party(PartyId::new(2)).matches(&certificate()));
        assert!(
            Subject::identity("CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X")
                .matches(&certificate())
        );
        assert!(
            Subject::identity_by(
                "mutual-tls",
                "CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X"
            )
            .matches(&certificate())
        );
        assert!(
            !Subject::identity_by(
                "basic",
                "CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X"
            )
            .matches(&certificate())
        );
    }

    #[test]
    fn a_claim_matches_one_item_of_a_comma_separated_list() {
        assert!(Subject::claim("groups", "billing-readers").matches(&certificate()));
        assert!(Subject::claim("groups", "shippers").matches(&certificate()));
        assert!(!Subject::claim("groups", "shipper").matches(&certificate()));
        assert!(!Subject::claim("roles", "shippers").matches(&certificate()));
    }

    #[test]
    fn every_unit_of_a_distinguished_name_counts() {
        assert!(Subject::unit("Logistics").matches(&certificate()));
        assert!(Subject::unit("Nordics").matches(&certificate()));
        assert!(
            !Subject::unit("Partner X").matches(&certificate()),
            "that is O"
        );
        assert_eq!(Subject::unit("Nordics").to_string(), "OU=Nordics");
        assert_eq!(
            Subject::claim("groups", "shippers").to_string(),
            "groups=shippers"
        );
    }
}
