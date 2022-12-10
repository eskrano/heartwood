use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;
use std::iter;
use std::ops::RangeBounds;

use crypto::test::signer::MockSigner;
use crypto::{PublicKey, Signer, Unverified, Verified};
use nonempty::NonEmpty;
use qcheck::Arbitrary;

use crate::collections::HashMap;
use crate::git;
use crate::identity::{project::Delegate, project::Doc, Did, Id};
use crate::storage;
use crate::storage::refs::{Refs, SignedRefs};
use crate::test::storage::MockStorage;

pub fn set<T: Eq + Hash + Arbitrary>(range: impl RangeBounds<usize>) -> HashSet<T> {
    let size = fastrand::usize(range);
    let mut set = HashSet::with_capacity(size);
    let mut g = qcheck::Gen::new(size);

    while set.len() < size {
        set.insert(T::arbitrary(&mut g));
    }
    set
}

pub fn vec<T: Eq + Arbitrary>(size: usize) -> Vec<T> {
    let mut vec = Vec::with_capacity(size);
    let mut g = qcheck::Gen::new(size);

    for _ in 0..vec.capacity() {
        vec.push(T::arbitrary(&mut g));
    }
    vec
}

pub fn gen<T: Arbitrary>(size: usize) -> T {
    let mut gen = qcheck::Gen::new(size);

    T::arbitrary(&mut gen)
}

impl Arbitrary for storage::Remotes<crypto::Verified> {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let remotes: HashMap<storage::RemoteId, storage::Remote<crypto::Verified>> =
            Arbitrary::arbitrary(g);

        storage::Remotes::new(remotes)
    }
}

impl Arbitrary for Did {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        Self::from(PublicKey::arbitrary(g))
    }
}

impl Arbitrary for Delegate {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        Self {
            name: String::arbitrary(g),
            id: Did::arbitrary(g),
        }
    }
}

impl Arbitrary for Doc<Unverified> {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let name = String::arbitrary(g);
        let description = String::arbitrary(g);
        let default_branch = git::RefString::try_from(String::arbitrary(g)).unwrap();
        let delegate = Delegate::arbitrary(g);

        Self::initial(name, description, default_branch, delegate)
    }
}

impl Arbitrary for Doc<Verified> {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let rng = fastrand::Rng::with_seed(u64::arbitrary(g));
        let name = iter::repeat_with(|| rng.alphanumeric())
            .take(rng.usize(1..16))
            .collect();
        let description = iter::repeat_with(|| rng.alphanumeric())
            .take(rng.usize(0..32))
            .collect();
        let default_branch: git::RefString = iter::repeat_with(|| rng.alphanumeric())
            .take(rng.usize(1..16))
            .collect::<String>()
            .try_into()
            .unwrap();
        let delegates: NonEmpty<_> = iter::repeat_with(|| Delegate {
            name: iter::repeat_with(|| rng.alphanumeric())
                .take(rng.usize(1..16))
                .collect(),
            id: Did::arbitrary(g),
        })
        .take(rng.usize(1..6))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
        let threshold = delegates.len() / 2 + 1;
        let doc: Doc<Unverified> =
            Doc::new(name, description, default_branch, delegates, threshold);

        doc.verified().unwrap()
    }
}

impl Arbitrary for SignedRefs<Unverified> {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let bytes: [u8; 64] = Arbitrary::arbitrary(g);
        let signature = crypto::Signature::from(bytes);
        let refs = Refs::arbitrary(g);

        Self::new(refs, signature)
    }
}

impl Arbitrary for Refs {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let mut refs: BTreeMap<git::RefString, storage::Oid> = BTreeMap::new();
        let mut bytes: [u8; 20] = [0; 20];
        let names = &[
            "heads/master",
            "heads/feature/1",
            "heads/feature/2",
            "heads/feature/3",
            "rad/id",
            "tags/v1.0",
            "tags/v2.0",
            "notes/1",
        ];

        for _ in 0..g.size().min(names.len()) {
            if let Some(name) = g.choose(names) {
                for byte in &mut bytes {
                    *byte = u8::arbitrary(g);
                }
                let oid = storage::Oid::try_from(&bytes[..]).unwrap();
                let name = git::RefString::try_from(*name).unwrap();

                refs.insert(name, oid);
            }
        }
        Self::from(refs)
    }
}

impl Arbitrary for MockStorage {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let inventory = Arbitrary::arbitrary(g);
        MockStorage::new(inventory)
    }
}

impl Arbitrary for storage::Remote<crypto::Verified> {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let refs = Refs::arbitrary(g);
        let signer = MockSigner::arbitrary(g);
        let signed = refs.signed(&signer).unwrap();

        storage::Remote::new(*signer.public_key(), signed)
    }
}

impl Arbitrary for Id {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        let bytes = <[u8; 20]>::arbitrary(g);
        let oid = git::Oid::try_from(bytes.as_slice()).unwrap();

        Id::from(oid)
    }
}
