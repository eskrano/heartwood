use amplify::{From, Wrapper};
use cyphernet::crypto::{EcPk, EcSk, Ecdh};
use ed25519_compact::x25519;
use ed25519_compact::Error;

use crate::ssh::keystore::MemorySigner;
use crate::{PublicKey, SecretKey, SharedSecret, Signature};

impl EcPk for PublicKey {}

impl cyphernet::crypto::Ecdh for MemorySigner {
    type Pk = PublicKey;
    type Secret = SharedSecret;
    type Err = Error;

    fn ecdh(&self, pk: &Self::Pk) -> Result<SharedSecret, Self::Err> {
        crate::Ecdh::ecdh(self, pk)
    }
}
