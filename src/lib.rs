#![forbid(unsafe_code)]

//! The role authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: the roles the identity holds, from a
//! role store (ADR-0050 section 5). A Party is recognized; a role is granted
//! (ADR-0009, ADR-0019 clause 4). The [`RoleStore`] is where the granting is
//! written down: each assignment names a [`Subject`] — a Party, a recorded
//! value, a claim carried as evidence, the organizational unit of a
//! distinguished name — and the roles it holds. [`RoleStore::roles_of`]
//! reads an identity's roles from both layers of the record, because a Party
//! recognized by an ISA06 alone may still be a shipper.
//!
//! **This policy assigns and does not judge.** What a role may do is the
//! `rbac` technology's question, and it decides nothing here: an identity's
//! roles are computed, and the decision is no opinion — unless the store is
//! configured to require a role, in which case an identity holding none is
//! refused by name. The capability's `decide` takes the facts by reference,
//! so the roles computed here do not travel on them; a hook in the
//! capability is what would carry them to `rbac`.

pub mod subject;

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
use xcore::Layer;

pub use subject::Subject;

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "role";

/// Who holds which roles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoleStore {
    assignments: Vec<(Subject, Vec<String>)>,
    required: bool,
}

impl RoleStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant roles to a subject. A subject may appear more than once; the
    /// roles add up.
    #[must_use]
    pub fn assign(mut self, subject: Subject, roles: &[&str]) -> Self {
        self.assignments
            .push((subject, roles.iter().map(ToString::to_string).collect()));
        self
    }

    /// Refuse an identity that holds no role at all. Off by default: an
    /// identity with no role is ordinary, and the next policy's question.
    #[must_use]
    pub const fn require_a_role(mut self) -> Self {
        self.required = true;
        self
    }

    /// The roles this identity holds, sorted, each once. Both layers of the
    /// record are read: the transport identity and, where there is one, the
    /// message identity.
    #[must_use]
    pub fn roles_of(&self, identity: &IdentityFacts) -> Vec<String> {
        let mut roles: Vec<String> = std::iter::once(&identity.transport)
            .chain(identity.message.as_ref())
            .flat_map(|held| {
                self.assignments
                    .iter()
                    .filter(move |(subject, _)| subject.matches(held))
                    .flat_map(|(_, roles)| roles.iter().cloned())
            })
            .collect();

        roles.sort();
        roles.dedup();
        roles
    }
}

impl Authorizer for RoleStore {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
        if !self.required || !self.roles_of(identity).is_empty() {
            return None;
        }

        let accountable = identity.accountable();

        Some(Decision::denied(
            NAME,
            format!(
                "{}={} holds no role, and this store requires one",
                accountable.mechanism.name(),
                accountable.value
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn certificate(party: Option<PartyId>) -> AuthenticatedIdentity {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example, OU=Logistics, O=Partner X",
            Established::Passed,
            Verified::Proven,
        )
        .with_evidence("groups", "shippers");

        match party {
            Some(party) => identity.resolving_to(party),
            None => identity,
        }
    }

    fn isa06() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            "ISA06=PARTNERX",
            Established::Detected,
            Verified::Claimed,
        )
    }

    fn store() -> RoleStore {
        RoleStore::new()
            .assign(Subject::party(PartyId::new(1)), &["partner"])
            .assign(Subject::claim("groups", "shippers"), &["shipper"])
            .assign(Subject::unit("Logistics"), &["shipper", "logistics"])
            .assign(Subject::identity("ISA06=PARTNERX"), &["edi-sender"])
    }

    #[test]
    fn roles_are_read_from_every_fact_on_both_layers_each_once() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            certificate(Some(PartyId::new(1))),
            Some(isa06()),
        );

        assert_eq!(
            store().roles_of(&facts),
            vec!["edi-sender", "logistics", "partner", "shipper"]
        );
    }

    #[test]
    fn assigning_roles_is_no_opinion_and_rbac_judges_what_they_may_do() {
        let facts = IdentityFacts::evaluate(Alignment::None, certificate(None), None);

        assert_eq!(
            store().decide(&facts, &Attempt::new(Action::Receive, "partner-x")),
            None
        );
        assert_eq!(store().name(), "role");
        assert_eq!(store().layer(), Layer::Transport);
    }

    #[test]
    fn a_store_that_requires_a_role_refuses_an_identity_holding_none() {
        let nobody = IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::basic(),
                "alice",
                Established::Passed,
                Verified::Proven,
            ),
            None,
        );
        let decision = store()
            .require_a_role()
            .decide(&nobody, &Attempt::new(Action::Receive, "partner-x"))
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by role: basic=alice holds no role, and this store requires one"
        );
        assert_eq!(
            store().decide(&nobody, &Attempt::new(Action::Receive, "partner-x")),
            None
        );
    }

    #[test]
    fn a_store_that_requires_a_role_is_content_with_one_from_any_fact() {
        // No Party resolved, but the certificate's OU grants a role, and one
        // is enough.
        let facts = IdentityFacts::evaluate(Alignment::None, certificate(None), None);

        assert_eq!(
            store()
                .require_a_role()
                .decide(&facts, &Attempt::new(Action::Send, "Billing")),
            None
        );
        assert_eq!(store().roles_of(&facts), vec!["logistics", "shipper"]);
    }
}
