//! An admin principal item, written by the operator CLI.

use registry_application::{ApplicationError, Principal, Role};
use registry_domain::ReviewerId;

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `PRINCIPAL#<sha256>` / `META`.
pub(crate) struct PrincipalItem;

impl PrincipalItem {
    pub(crate) const KIND: &'static str = "principal";

    pub(crate) fn encode(certificate_sha256: &str, principal: &Principal) -> Item {
        let role = match principal.role() {
            Role::Reviewer => "reviewer",
            Role::Operator => "operator",
        };
        Item::at(Key::principal(certificate_sha256), Self::KIND).set_string("id", principal.id().as_str()).set_string("role", role)
    }

    pub(crate) fn decode(item: &Item) -> Result<Principal, ApplicationError> {
        let role = match item.string("role")? {
            "reviewer" => Role::Reviewer,
            "operator" => Role::Operator,
            other => return Err(ApplicationError::port("dynamodb", format!("unknown role {other}"))),
        };
        Ok(Principal::new(ReviewerId::parse(item.string("id")?)?, role))
    }
}

#[cfg(test)]
mod tests {
    use registry_application::{Principal, Role};
    use registry_domain::ReviewerId;

    use super::PrincipalItem;
    use crate::item::Item;

    #[test]
    fn round_trips_both_roles() {
        for role in [Role::Reviewer, Role::Operator] {
            let principal = Principal::new(ReviewerId::parse("ana").unwrap(), role);
            let item = Item::from_map(PrincipalItem::encode("abc", &principal).into_map());
            assert_eq!(PrincipalItem::decode(&item).unwrap(), principal);
        }
        assert!(PrincipalItem::decode(&Item::default().set_string("id", "ana").set_string("role", "king")).is_err());
    }
}
