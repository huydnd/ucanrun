//! Decoding with Go's `DisallowUnknownFields` rules: an unknown key in any
//! struct, at any depth, is an error, and `null` leaves the zero value.

use serde::Deserialize;
use serde::de::value::BorrowedStrDeserializer;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Error, Value};

pub fn from_value<'a, T: Deserialize<'a>>(v: &'a Value) -> Result<T, Error> {
    T::deserialize(Strict(v))
}

struct Strict<'a>(&'a Value);

struct Map<'a> {
    iter: serde_json::map::Iter<'a>,
    value: Option<&'a Value>,
}

impl<'a> MapAccess<'a> for Map<'a> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'a>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(BorrowedStrDeserializer::new(k)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'a>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let v = self
            .value
            .take()
            .ok_or_else(|| de::Error::custom("value before key"))?;
        seed.deserialize(Strict(v))
    }
}

struct Seq<'a>(std::slice::Iter<'a, Value>);

impl<'a> SeqAccess<'a> for Seq<'a> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'a>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.0.next() {
            Some(v) => seed.deserialize(Strict(v)).map(Some),
            None => Ok(None),
        }
    }
}

static EMPTY: std::sync::LazyLock<serde_json::Map<String, Value>> =
    std::sync::LazyLock::new(serde_json::Map::new);

macro_rules! forward {
    ($($method:ident => $zero:expr),* $(,)?) => {
        $(
            fn $method<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
                if self.0.is_null() {
                    #[allow(clippy::redundant_closure_call)]
                    return ($zero)(visitor);
                }
                self.0.$method(visitor)
            }
        )*
    };
}

impl<'a> Deserializer<'a> for Strict<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
        self.0.deserialize_ignored_any(visitor)
    }

    forward! {
        deserialize_bool => |v: V| v.visit_bool(false),
        deserialize_i8 => |v: V| v.visit_i64(0),
        deserialize_i16 => |v: V| v.visit_i64(0),
        deserialize_i32 => |v: V| v.visit_i64(0),
        deserialize_i64 => |v: V| v.visit_i64(0),
        deserialize_u8 => |v: V| v.visit_u64(0),
        deserialize_u16 => |v: V| v.visit_u64(0),
        deserialize_u32 => |v: V| v.visit_u64(0),
        deserialize_u64 => |v: V| v.visit_u64(0),
        deserialize_f32 => |v: V| v.visit_f64(0.0),
        deserialize_f64 => |v: V| v.visit_f64(0.0),
        deserialize_str => |v: V| v.visit_str(""),
        deserialize_string => |v: V| v.visit_str(""),
        deserialize_char => |v: V| v.visit_char('\0'),
        deserialize_bytes => |v: V| v.visit_bytes(&[]),
        deserialize_byte_buf => |v: V| v.visit_bytes(&[]),
        deserialize_unit => |v: V| v.visit_unit(),
        deserialize_identifier => |v: V| v.visit_str(""),
    }

    fn deserialize_option<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit_struct<V: Visitor<'a>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.0.deserialize_unit_struct(name, visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'a>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(a) => visitor.visit_seq(Seq(a.iter())),
            Value::Null => visitor.visit_seq(Seq([].iter())),
            v => v.deserialize_seq(visitor),
        }
    }

    fn deserialize_tuple<V: Visitor<'a>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'a>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(m) => visitor.visit_map(Map {
                iter: m.iter(),
                value: None,
            }),
            Value::Null => visitor.visit_map(Map {
                iter: EMPTY.iter(),
                value: None,
            }),
            v => v.deserialize_map(visitor),
        }
    }

    fn deserialize_struct<V: Visitor<'a>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        if let Value::Object(m) = self.0 {
            if let Some(k) = m.keys().find(|k| !fields.contains(&k.as_str())) {
                return Err(de::Error::unknown_field(k, fields));
            }
        } else if !self.0.is_null() {
            return self.0.deserialize_struct(name, fields, visitor);
        }
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'a>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.0.deserialize_enum(name, variants, visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Call, Profile};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[derive(Deserialize, Default, Debug)]
    #[serde(default)]
    struct In {
        name: String,
        n: i64,
        params: BTreeMap<String, String>,
        call: Option<Call>,
        list: Vec<Profile>,
    }

    #[test]
    fn unknown_fields_at_any_depth() {
        let ok: In = from_value(&json!({"name": "a", "n": 2, "params": {"x": "y"},
            "call": {"http": {"method": "GET", "url": "https://a"}}, "list": [{"name": "p"}]}))
        .unwrap();
        assert_eq!(
            (ok.name.as_str(), ok.n, ok.list[0].name.as_str()),
            ("a", 2, "p")
        );
        for bad in [
            json!({"nope": 1}),
            json!({"call": {"http": {"method": "GET", "extra": 1}}}),
            json!({"list": [{"name": "p", "http": {"url": "x", "evil": true}}]}),
            json!({"n": "1"}),
        ] {
            assert!(from_value::<In>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn null_keeps_zero_values() {
        let v: In = from_value(
            &json!({"name": null, "n": null, "params": null, "call": null, "list": null}),
        )
        .unwrap();
        assert!(v.name.is_empty() && v.n == 0 && v.params.is_empty() && v.call.is_none());
        let v: In = from_value(&Value::Null).unwrap();
        assert!(v.list.is_empty());
    }

    #[test]
    fn renamed_fields_are_known() {
        let c: crate::policy::Connection =
            from_value(&json!({"name": "a", "base_url": "https://x",
            "auth": {"type": "bearer", "secret": "s"}}))
            .unwrap();
        assert_eq!(c.auth.kind, "bearer");
    }
}
