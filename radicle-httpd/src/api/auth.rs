use radicle::crypto::PublicKey;
use serde::{Serialize, Serializer};
use time::OffsetDateTime;

#[derive(Clone, PartialEq, PartialOrd)]
pub struct DateTime(pub OffsetDateTime);

impl Serialize for DateTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}", self.0))
    }
}

pub enum AuthState {
    Authorized(Session),
    Unauthorized {
        public_key: PublicKey,
        expiration_time: DateTime,
    },
}

// We copy the implementation of siwe::Message here to derive Serialization and Debug
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub public_key: String,
    pub issued_at: DateTime,
    pub expiration_time: DateTime,
}
