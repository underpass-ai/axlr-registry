//! A token item under its publisher: digest, scopes, expiry, revocation.

use registry_application::ApplicationError;
use registry_domain::{PublisherId, Scope, Token, TokenDigest};

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `PUB#<id>` / `TOKEN#<digest>`.
pub(crate) struct TokenItem;

impl TokenItem {
    pub(crate) const KIND: &'static str = "token";
    pub(crate) const PREFIX: &'static str = "TOKEN#";

    /// `position` is the token's place in the publisher's list.
    pub(crate) fn encode(publisher: &PublisherId, token: &Token, position: usize) -> Item {
        Item::at(Key::token(publisher, token.digest().as_str()), Self::KIND)
            .set_number("position", position as u64)
            .set_string("digest", token.digest().as_str())
            .set_strings("scopes", token.scopes().iter().map(|s| String::from(s.clone())))
            .set_optional_timestamp("expires_at", token.expires_at())
            .set_optional_timestamp("revoked_at", token.revoked_at())
    }

    /// The position and the token.
    pub(crate) fn decode(item: &Item) -> Result<(u64, Token), ApplicationError> {
        let digest = TokenDigest::parse(item.string("digest")?)?;
        let scopes = item.strings("scopes")?.iter().map(|s| Scope::parse(s)).collect::<Result<Vec<_>, _>>()?;
        Ok((
            item.number("position")?,
            Token::restore(digest, scopes, item.optional_timestamp("expires_at")?, item.optional_timestamp("revoked_at")?),
        ))
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{PublisherId, Scope, Token, TokenDigest};
    use time::macros::datetime;

    use super::TokenItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let now = datetime!(2026-10-17 10:00 UTC);
        let token = Token::restore(TokenDigest::of("t"), vec![Scope::parse("acme_*").unwrap()], Some(now), None);
        let item = Item::from_map(TokenItem::encode(&PublisherId::parse("acme").unwrap(), &token, 1).into_map());
        assert!(item.sort_key().unwrap().starts_with(TokenItem::PREFIX));
        assert_eq!(TokenItem::decode(&item).unwrap(), (1, token));
        assert!(TokenItem::decode(&Item::default().set_string("digest", "short").set_strings("scopes", [])).is_err());
    }
}
