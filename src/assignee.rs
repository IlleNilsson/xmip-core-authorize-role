//! Who an assignment is for: the fact on an identity a role is granted by.
//!
//! Four facts, each one of the five the record keeps (ADR-0019 clause 6): the
//! Party the identity resolved to and the value the gate recorded under one
//! mechanism — the subject every policy names, `authorize::subject::Subject` —
//! and, a role store's own, a claim carried as evidence — a group from a
//! token or a directory — and the organizational unit of a distinguished name.

use authorize::subject::Subject;
use context::AuthenticatedIdentity;
use std::fmt;
use xcore::PartyId;

/// The fact a role is granted by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Assignee {
    /// Who, as every policy names a subject.
    Subject(Subject),
    /// The identity carries evidence under this name with this value among
    /// its values — the shape a `groups` claim takes, one entry per group.
    Claim { name: String, value: String },
    /// The value is a distinguished name with this `OU`.
    Unit(String),
}

impl Assignee {
    /// A Party, by the identifier the gate resolved it to.
    #[must_use]
    pub const fn party(party: PartyId) -> Self {
        Self::Subject(Subject::Party(party))
    }

    /// A recorded value under any mechanism.
    #[must_use]
    pub fn identity(value: impl Into<String>) -> Self {
        Self::Subject(Subject::identity(value))
    }

    /// A recorded value under one mechanism, by the name the catalog declares.
    #[must_use]
    pub fn identity_by(mechanism: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Subject(Subject::identity_by(mechanism, value))
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

    /// Whether this identity is the one assigned.
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Subject(subject) => subject.matches(identity),
            Self::Claim { name, value } => identity.evidence_values(name).any(|held| held == value),
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

/// As a subject is said, and a claim and a unit the same way:
/// `groups='shippers'`, `OU='Logistics'`.
impl fmt::Display for Assignee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject(subject) => subject.fmt(f),
            Self::Claim { name, value } => write!(f, "{name}='{value}'"),
            Self::Unit(unit) => write!(f, "OU='{unit}'"),
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
        .with_evidence("groups", "shippers")
        .with_evidence("groups", "billing-readers")
    }

    #[test]
    fn a_party_and_a_value_each_name_the_identity() {
        assert!(Assignee::party(PartyId::new(1)).matches(&certificate()));
        assert!(!Assignee::party(PartyId::new(2)).matches(&certificate()));
        assert!(
            Assignee::identity("CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X")
                .matches(&certificate())
        );
        assert!(
            Assignee::identity_by(
                "mutual-tls",
                "CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X"
            )
            .matches(&certificate())
        );
        assert!(
            !Assignee::identity_by(
                "basic",
                "CN=partner-x.example, OU=Logistics, OU=Nordics, O=Partner X"
            )
            .matches(&certificate())
        );
    }

    #[test]
    fn a_claim_matches_one_of_its_values() {
        assert!(Assignee::claim("groups", "billing-readers").matches(&certificate()));
        assert!(Assignee::claim("groups", "shippers").matches(&certificate()));
        assert!(!Assignee::claim("groups", "shipper").matches(&certificate()));
        assert!(!Assignee::claim("roles", "shippers").matches(&certificate()));
        let listed = certificate().with_evidence("teams", "a, b");
        assert!(
            !Assignee::claim("teams", "a").matches(&listed),
            "a value is never split"
        );
    }

    #[test]
    fn every_unit_of_a_distinguished_name_counts() {
        assert!(Assignee::unit("Logistics").matches(&certificate()));
        assert!(Assignee::unit("Nordics").matches(&certificate()));
        assert!(
            !Assignee::unit("Partner X").matches(&certificate()),
            "that is O"
        );
        assert_eq!(Assignee::unit("Nordics").to_string(), "OU='Nordics'");
        assert_eq!(
            Assignee::claim("groups", "shippers").to_string(),
            "groups='shippers'"
        );
    }
}
