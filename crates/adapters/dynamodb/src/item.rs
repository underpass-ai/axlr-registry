//! A typed view over a DynamoDB item, so every decoder reads attributes
//! through one place that reports what is missing or malformed.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use registry_application::ApplicationError;
use registry_domain::Timestamp;

use crate::key::Key;
use crate::timestamps::{format_timestamp, parse_timestamp};

/// An item under construction or under inspection.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Item(HashMap<String, AttributeValue>);

impl Item {
    /// An item at a key, tagged with its family.
    pub(crate) fn at(key: Key, kind: &str) -> Self {
        let mut item = Self::default();
        item.0.insert("PK".into(), AttributeValue::S(key.pk));
        item.0.insert("SK".into(), AttributeValue::S(key.sk));
        item.0.insert("kind".into(), AttributeValue::S(kind.to_owned()));
        item
    }

    /// Wraps a read item.
    pub(crate) fn from_map(map: HashMap<String, AttributeValue>) -> Self {
        Self(map)
    }

    /// The attributes, for the SDK.
    pub(crate) fn into_map(self) -> HashMap<String, AttributeValue> {
        self.0
    }

    /// The sort key.
    pub(crate) fn sort_key(&self) -> Result<&str, ApplicationError> {
        self.string("SK")
    }

    /// The partition key.
    pub(crate) fn partition_key(&self) -> Result<&str, ApplicationError> {
        self.string("PK")
    }

    pub(crate) fn set_string(mut self, name: &str, value: impl Into<String>) -> Self {
        self.0.insert(name.to_owned(), AttributeValue::S(value.into()));
        self
    }

    pub(crate) fn set_optional_string(self, name: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.set_string(name, v),
            None => self,
        }
    }

    pub(crate) fn set_number(mut self, name: &str, value: u64) -> Self {
        self.0.insert(name.to_owned(), AttributeValue::N(value.to_string()));
        self
    }

    pub(crate) fn set_optional_number(self, name: &str, value: Option<u64>) -> Self {
        match value {
            Some(v) => self.set_number(name, v),
            None => self,
        }
    }

    pub(crate) fn set_timestamp(self, name: &str, value: Timestamp) -> Self {
        self.set_string(name, format_timestamp(value))
    }

    pub(crate) fn set_optional_timestamp(self, name: &str, value: Option<Timestamp>) -> Self {
        self.set_optional_string(name, value.map(format_timestamp))
    }

    pub(crate) fn set_strings(mut self, name: &str, values: impl IntoIterator<Item = String>) -> Self {
        self.0.insert(name.to_owned(), AttributeValue::L(values.into_iter().map(AttributeValue::S).collect()));
        self
    }

    pub(crate) fn set_string_map(mut self, name: &str, values: impl IntoIterator<Item = (String, String)>) -> Self {
        self.0.insert(name.to_owned(), AttributeValue::M(values.into_iter().map(|(k, v)| (k, AttributeValue::S(v))).collect()));
        self
    }

    pub(crate) fn set_item(mut self, name: &str, value: Item) -> Self {
        self.0.insert(name.to_owned(), AttributeValue::M(value.0));
        self
    }

    pub(crate) fn set_optional_item(self, name: &str, value: Option<Item>) -> Self {
        match value {
            Some(v) => self.set_item(name, v),
            None => self,
        }
    }

    fn missing(name: &str) -> ApplicationError {
        ApplicationError::port("dynamodb", format!("item lacks attribute {name}"))
    }

    pub(crate) fn string(&self, name: &str) -> Result<&str, ApplicationError> {
        self.optional_string(name).ok_or_else(|| Self::missing(name))
    }

    pub(crate) fn optional_string(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(|v| v.as_s().ok()).map(String::as_str)
    }

    pub(crate) fn number(&self, name: &str) -> Result<u64, ApplicationError> {
        self.0
            .get(name)
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| ApplicationError::port("dynamodb", format!("attribute {name} is not a number")))
    }

    pub(crate) fn optional_number(&self, name: &str) -> Result<Option<u64>, ApplicationError> {
        if self.0.contains_key(name) {
            self.number(name).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn timestamp(&self, name: &str) -> Result<Timestamp, ApplicationError> {
        parse_timestamp(self.string(name)?)
    }

    pub(crate) fn optional_timestamp(&self, name: &str) -> Result<Option<Timestamp>, ApplicationError> {
        self.optional_string(name).map(parse_timestamp).transpose()
    }

    pub(crate) fn strings(&self, name: &str) -> Result<Vec<String>, ApplicationError> {
        let list = self.0.get(name).and_then(|v| v.as_l().ok()).ok_or_else(|| Self::missing(name))?;
        list.iter()
            .map(|v| v.as_s().cloned().map_err(|_| ApplicationError::port("dynamodb", format!("attribute {name} holds a non-string"))))
            .collect()
    }

    pub(crate) fn string_map(&self, name: &str) -> Result<Vec<(String, String)>, ApplicationError> {
        let map = self.0.get(name).and_then(|v| v.as_m().ok()).ok_or_else(|| Self::missing(name))?;
        map.iter()
            .map(|(k, v)| {
                v.as_s()
                    .map(|s| (k.clone(), s.clone()))
                    .map_err(|_| ApplicationError::port("dynamodb", format!("attribute {name}.{k} is not a string")))
            })
            .collect()
    }

    pub(crate) fn optional_item(&self, name: &str) -> Option<Item> {
        self.0.get(name).and_then(|v| v.as_m().ok()).map(|m| Item(m.clone()))
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::Item;
    use crate::key::Key;

    #[test]
    fn reads_back_what_it_wrote_and_names_what_is_missing() {
        let at = datetime!(2026-10-17 10:00 UTC);
        let item = Item::at(Key::principal("x"), "principal")
            .set_string("s", "v")
            .set_optional_string("absent", None::<String>)
            .set_number("n", 7)
            .set_optional_number("on", Some(8))
            .set_optional_number("none", None)
            .set_timestamp("t", at)
            .set_optional_timestamp("ot", Some(at))
            .set_strings("l", ["a".to_owned(), "b".to_owned()])
            .set_string_map("m", [("k".to_owned(), "v".to_owned())])
            .set_item("i", Item::default().set_string("inner", "x"))
            .set_optional_item("oi", None);
        let item = Item::from_map(item.into_map());
        assert_eq!((item.partition_key().unwrap(), item.sort_key().unwrap()), ("PRINCIPAL#x", "META"));
        assert_eq!(item.string("s").unwrap(), "v");
        assert_eq!(item.optional_string("absent"), None);
        assert_eq!(item.number("n").unwrap(), 7);
        assert_eq!(item.optional_number("on").unwrap(), Some(8));
        assert_eq!(item.optional_number("none").unwrap(), None);
        assert!(item.optional_number("s").is_err());
        assert_eq!(item.timestamp("t").unwrap(), at);
        assert_eq!(item.optional_timestamp("ot").unwrap(), Some(at));
        assert_eq!(item.optional_timestamp("absent").unwrap(), None);
        assert_eq!(item.strings("l").unwrap(), ["a", "b"]);
        assert_eq!(item.string_map("m").unwrap(), [("k".to_owned(), "v".to_owned())]);
        assert_eq!(item.optional_item("i").unwrap().string("inner").unwrap(), "x");
        assert!(item.optional_item("oi").is_none());
        assert!(item.string("nope").unwrap_err().to_string().contains("nope"));
        assert!(item.number("s").is_err());
        assert!(item.strings("s").is_err());
        assert!(item.string_map("s").is_err());
        assert!(item.timestamp("s").is_err());
    }
}
