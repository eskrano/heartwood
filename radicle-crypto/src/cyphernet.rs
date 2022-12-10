use cyphernet::crypto::ed25519::SharedSecret;
use cyphernet::crypto::EcPk;
use cyphernet::crypto::Ecdh;
use ed25519_compact::Error;

use crate::ssh::keystore::MemorySigner;
use crate::PublicKey;

impl EcPk for PublicKey {}

impl cyphernet::crypto::Ecdh for MemorySigner {
    type Pk = PublicKey;
    type Secret = SharedSecret;
    type Err = Error;

    fn ecdh(&self, pk: &Self::Pk) -> Result<SharedSecret, Self::Err> {
        Ecdh::ecdh(self, pk)
    }
}
