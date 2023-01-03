use std::{ops::Deref, str::FromStr};

use crypto::{PublicKey, Signature};
use once_cell::sync::Lazy;
use radicle_cob::{ObjectId, TypeName};
use radicle_crdt::{clock, GMap, Gate, LWWMap, LWWReg, Max, Redactable, Semilattice};
use radicle_crypto::{Signer, Verified};
use radicle_git_ext::Oid;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    cob::{
        self,
        common::Timestamp,
        store::{self, FromHistory as _, Transaction},
    },
    identity::{doc::DocError, Identity},
    prelude::Doc,
    storage::{git as storage, RemoteId},
};

use super::{
    thread::{self, Thread},
    Author, OpId,
};

/// The logical clock we use to order operations to patches.
pub use clock::Lamport as Clock;

/// Type name of a patch.
pub static TYPENAME: Lazy<TypeName> =
    Lazy::new(|| FromStr::from_str("xyz.radicle.identity.proposal").expect("type name is valid"));

pub type Op = cob::Op<Action>;

pub type ProposalId = ObjectId;

pub type RevisionId = OpId;

/// Proposal operation.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Action {
    Accept {
        revision: RevisionId,
        signature: Signature,
    },
    Edit {
        title: String,
        description: String,
    },
    Publish,
    Redact {
        revision: RevisionId,
    },
    Reject {
        revision: RevisionId,
    },
    Revision {
        proposed: Doc<Verified>,
        previous: Identity<Oid>,
    },
    Thread {
        revision: RevisionId,
        action: thread::Action,
    },
}

/// Error applying an operation onto a state.
#[derive(Error, Debug)]
pub enum ApplyError {
    /// Causal dependency missing.
    ///
    /// This error indicates that the operations are not being applied
    /// in causal order, which is a requirement for this CRDT.
    ///
    /// For example, this can occur if an operation references anothern operation
    /// that hasn't happened yet.
    #[error("causal dependency {0:?} missing")]
    Missing(OpId),
    #[error("the proposal is published")]
    Published,
    #[error(transparent)]
    Publish(#[from] PublishError),
    #[error("the revision {0:?} is redacted")]
    Redacted(OpId),
    /// Error applying an op to the patch thread.
    #[error("thread apply failed: {0}")]
    Thread(#[from] thread::OpError),
}

/// Error publishing the proposal.
#[derive(Error, Debug)]
pub enum PublishError {
    #[error("the revision {0:?} is missing")]
    Missing(OpId),
    #[error("the revision {0:?} is already published")]
    Published(OpId),
    #[error("the revision {0:?} is redacted")]
    Redacted(OpId),
    #[error(transparent)]
    Doc(#[from] DocError),
    #[error("signatures did not reach quorum threshold: {0}")]
    Quorum(usize),
}

/// Error updating or creating proposals.
#[derive(Error, Debug)]
pub enum Error {
    #[error("apply failed: {0}")]
    Apply(#[from] ApplyError),
    #[error("store: {0}")]
    Store(#[from] store::Error),
}

/// Propose a new [`Doc`] for an [`Identity`]. The proposal can be
/// reviewed by gathering [`Signature`]s for accepting the changes, or
/// rejecting them.
///
/// Once a proposal has reached the quourum threshold for the previous
/// [`Identity`] then it may be published to the person's local
/// storage using [`Proposal::publish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Title of the proposal.
    title: LWWReg<Max<String>>,
    /// Description of the proposal.
    description: LWWReg<Max<String>>,
    /// List of revisions for this proposal.
    revisions: Gate<GMap<RevisionId, Redactable<Revision>>>,
}

pub struct Published {
    pub title: String,
    pub description: Option<String>,
}

impl Semilattice for Proposal {
    fn merge(&mut self, other: Self) {
        self.description.merge(other.description);
        self.revisions.merge(other.revisions);
    }
}

impl Default for Proposal {
    fn default() -> Self {
        Self {
            title: Max::from(String::default()).into(),
            description: Max::from(String::default()).into(),
            revisions: Gate::open(GMap::default()),
        }
    }
}

impl Proposal {
    /// Publish the [`Doc`], found at the given `revision`, to the
    /// provided `remote`.
    ///
    /// # Errors
    ///
    /// This operation will fail if:
    ///   * The `revision` is missing
    ///   * The `revision` is redacted
    ///   * The number of signatures for this revision does not reach
    ///     the quorum for the previous [`Doc`].
    pub fn publish(
        &self,
        revision: &RevisionId,
        remote: &RemoteId,
        repo: &git2::Repository,
    ) -> Result<Identity<Oid>, PublishError> {
        let revision = self
            .revision(revision)
            .get()
            .ok_or_else(|| PublishError::Published(*revision))?
            .ok_or_else(|| PublishError::Missing(*revision))?
            .get()
            .ok_or_else(|| PublishError::Redacted(*revision))?;
        let doc = &revision.proposed;

        if !revision.reaches_quorum() {
            return Err(PublishError::Quorum(doc.threshold));
        }

        let signatures = revision.signatures();
        let msg = format!(
            "{}\n\n{}",
            self.title(),
            self.description().unwrap_or_default()
        );
        let current = doc.update(remote, &msg, &signatures.collect::<Vec<_>>(), repo)?;

        Ok(Identity {
            head: current,
            root: revision.previous.root,
            current,
            revision: revision.previous.revision + 1,
            doc: doc.clone(),
            signatures: revision
                .signatures()
                .map(|(key, sig)| (*key, sig))
                .collect(),
        })
    }

    pub fn is_published(&self) -> bool {
        self.revisions.is_closed()
    }

    pub fn published(&self) -> Option<Published> {
        if self.revisions.is_closed() {
            Some(Published {
                title: self.title().to_string(),
                description: self.description().map(|d| d.to_string()),
            })
        } else {
            None
        }
    }

    /// The most recent title for the proposal.
    pub fn title(&self) -> &str {
        self.title.get().get()
    }

    /// The most recent description for the proposal, if present.
    pub fn description(&self) -> Option<&str> {
        Some(self.description.get().get())
    }

    /// A specific [`Revision`], that may be redacted.
    pub fn revision(&self, revision: &RevisionId) -> Gate<Option<&Redactable<Revision>>> {
        self.revisions
            .as_ref()
            .map(|revisions| revisions.get(revision))
    }

    /// All the [`Revision`]s that have not been redacted.
    pub fn revisions(&self) -> impl DoubleEndedIterator<Item = (&RevisionId, &Revision)> {
        self.revisions.iter().flat_map(|rs| rs.iter()).filter_map(
            |(rid, r)| -> Option<(&RevisionId, &Revision)> { r.get().map(|r| (rid, r)) },
        )
    }

    pub fn latest_by(&self, who: &PublicKey) -> Option<(&RevisionId, &Revision)> {
        self.revisions().rev().find_map(|(rid, r)| {
            if r.author.id() == who {
                Some((rid, r))
            } else {
                None
            }
        })
    }

    pub fn latest(&self) -> Option<(&RevisionId, &Revision)> {
        self.revisions().next_back()
    }
}

impl store::FromHistory for Proposal {
    type Action = Action;
    type Error = ApplyError;

    fn type_name() -> &'static TypeName {
        &*TYPENAME
    }

    fn apply(&mut self, ops: impl IntoIterator<Item = Op>) -> Result<(), Self::Error> {
        for op in ops {
            let id = op.id();
            let author = Author::new(op.author);
            let timestamp = op.timestamp;

            match op.action {
                Action::Accept {
                    revision,
                    signature,
                } => {
                    let revisions = self.revisions.get_mut().ok_or(ApplyError::Published)?;

                    match revisions.get_mut(&revision) {
                        Some(Redactable::Present(revision)) => {
                            revision.accept(op.author, signature, op.clock)
                        }
                        Some(Redactable::Redacted) => return Err(ApplyError::Redacted(revision)),
                        None => return Err(ApplyError::Missing(revision)),
                    }
                }
                Action::Edit { title, description } => {
                    self.title.set(title, op.clock);
                    self.description.set(description, op.clock);
                }
                Action::Publish => self.revisions.merge(Gate::closed()),
                Action::Redact { revision } => {
                    let revisions = self.revisions.get_mut().ok_or(ApplyError::Published)?;

                    if let Some(revision) = revisions.get_mut(&revision) {
                        revision.merge(Redactable::Redacted);
                    } else {
                        return Err(ApplyError::Missing(revision));
                    }
                }
                Action::Reject { revision } => {
                    let revisions = self.revisions.get_mut().ok_or(ApplyError::Published)?;

                    match revisions.get_mut(&revision) {
                        Some(Redactable::Present(revision)) => revision.reject(op.author, op.clock),
                        Some(Redactable::Redacted) => return Err(ApplyError::Redacted(revision)),
                        None => return Err(ApplyError::Missing(revision)),
                    }
                }
                Action::Revision { proposed, previous } => {
                    let revisions = self.revisions.get_mut().ok_or(ApplyError::Published)?;

                    revisions.insert(
                        id,
                        Redactable::Present(Revision::new(author, previous, proposed, timestamp)),
                    )
                }
                Action::Thread { revision, action } => {
                    let revisions = self.revisions.get_mut().ok_or(ApplyError::Published)?;

                    match revisions.get_mut(&revision) {
                        Some(Redactable::Present(revision)) => revision
                            .discussion
                            .apply([cob::Op::new(action, op.author, op.timestamp, op.clock)])?,
                        Some(Redactable::Redacted) => return Err(ApplyError::Redacted(revision)),
                        None => return Err(ApplyError::Missing(revision)),
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// An accepting verdict must supply the [`Signature`] over the
    /// new proposed [`Doc`].
    Accept(Signature),
    /// Rejecting the proposed [`Doc`].
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    /// Author of this proposed revision.
    pub author: Author,
    /// Previous [`Identity`] that is going to be updated.
    pub previous: Identity<Oid>,
    /// New [`Doc`] that will replace `previous`' document.
    pub proposed: Doc<Verified>,
    /// Discussion thread for this revision.
    pub discussion: Thread,
    /// [`Verdict`]s given by the delegates.
    pub verdicts: LWWMap<PublicKey, Redactable<Verdict>>,
    /// Physical timestamp of this proposal revision.
    pub timestamp: Timestamp,
}

impl Revision {
    pub fn new(
        author: Author,
        previous: Identity<Oid>,
        proposed: Doc<Verified>,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            author,
            previous,
            proposed,
            discussion: Thread::default(),
            verdicts: LWWMap::default(),
            timestamp,
        }
    }

    pub fn signatures(&self) -> impl Iterator<Item = (&PublicKey, Signature)> {
        self.verdicts().filter_map(|(key, verdict)| match verdict {
            Verdict::Accept(sig) => Some((key, *sig)),
            Verdict::Reject => None,
        })
    }

    pub fn verdicts(&self) -> impl Iterator<Item = (&PublicKey, &Verdict)> {
        self.verdicts
            .iter()
            .filter_map(|(key, verdict)| verdict.get().map(|verdict| (key, verdict)))
    }

    pub fn accepted(&self) -> Vec<PublicKey> {
        self.verdicts()
            .filter_map(|(key, v)| match v {
                Verdict::Accept(_) => Some(*key),
                Verdict::Reject => None,
            })
            .collect()
    }

    pub fn rejected(&self) -> Vec<PublicKey> {
        self.verdicts()
            .filter_map(|(key, v)| match v {
                Verdict::Accept(_) => None,
                Verdict::Reject => Some(*key),
            })
            .collect()
    }

    pub fn reaches_quorum(&self) -> bool {
        let votes_for = self
            .verdicts
            .iter()
            .fold(0, |count, (_, verdict)| match verdict.get() {
                Some(Verdict::Accept(_)) => count + 1,
                Some(Verdict::Reject) => count,
                None => count,
            });
        votes_for >= self.previous.doc.threshold
    }

    fn accept(&mut self, key: PublicKey, signature: Signature, clock: Clock) {
        self.verdicts
            .insert(key, Redactable::Present(Verdict::Accept(signature)), clock);
    }

    fn reject(&mut self, key: PublicKey, clock: Clock) {
        self.verdicts
            .insert(key, Redactable::Present(Verdict::Reject), clock)
    }
}

impl store::Transaction<Proposal> {
    pub fn accept(&mut self, revision: RevisionId, signature: Signature) -> OpId {
        self.push(Action::Accept {
            revision,
            signature,
        })
    }

    pub fn reject(&mut self, revision: RevisionId) -> OpId {
        self.push(Action::Reject { revision })
    }

    pub fn edit(&mut self, title: impl ToString, description: impl ToString) -> OpId {
        self.push(Action::Edit {
            title: title.to_string(),
            description: description.to_string(),
        })
    }

    pub fn publish(&mut self) -> OpId {
        self.push(Action::Publish)
    }

    pub fn redact(&mut self, revision: RevisionId) -> OpId {
        self.push(Action::Redact { revision })
    }

    pub fn revision(&mut self, proposed: Doc<Verified>, previous: Identity<Oid>) -> OpId {
        self.push(Action::Revision { proposed, previous })
    }

    /// Start a patch revision discussion.
    pub fn thread<S: ToString>(&mut self, revision: RevisionId, body: S) -> OpId {
        self.push(Action::Thread {
            revision,
            action: thread::Action::Comment {
                body: body.to_string(),
                reply_to: None,
            },
        })
    }

    /// Comment on a proposal revision.
    pub fn comment<S: ToString>(
        &mut self,
        revision: RevisionId,
        body: S,
        reply_to: thread::CommentId,
    ) -> OpId {
        self.push(Action::Thread {
            revision,
            action: thread::Action::Comment {
                body: body.to_string(),
                reply_to: Some(reply_to),
            },
        })
    }

    /// Update a proposal with a new revision.
    pub fn update(
        &mut self,
        description: impl ToString,
        proposed: Doc<Verified>,
        previous: Identity<Oid>,
    ) -> (OpId, OpId) {
        let revision = self.revision(proposed, previous);
        let comment = self.thread(revision, description);

        (revision, comment)
    }
}

pub struct ProposalMut<'a, 'g> {
    pub id: ObjectId,

    proposal: Proposal,
    clock: clock::Lamport,
    store: &'g mut Proposals<'a>,
}

impl<'a, 'g> ProposalMut<'a, 'g> {
    pub fn new(
        id: ObjectId,
        proposal: Proposal,
        clock: clock::Lamport,
        store: &'g mut Proposals<'a>,
    ) -> Self {
        Self {
            id,
            clock,
            proposal,
            store,
        }
    }

    pub fn transaction<G, F, T>(
        &mut self,
        message: &str,
        signer: &G,
        operations: F,
    ) -> Result<T, Error>
    where
        G: Signer,
        F: FnOnce(&mut Transaction<Proposal>) -> T,
    {
        let mut tx = Transaction::new(*signer.public_key(), self.clock);
        let output = operations(&mut tx);
        let (ops, clock) = tx.commit(message, self.id, &mut self.store.raw, signer)?;

        self.proposal.apply(ops)?;
        self.clock = clock;

        Ok(output)
    }

    /// Get the internal logical clock.
    pub fn clock(&self) -> &clock::Lamport {
        &self.clock
    }

    pub fn accept<G: Signer>(
        &mut self,
        revision: RevisionId,
        signature: Signature,
        signer: &G,
    ) -> Result<OpId, Error> {
        self.transaction("Accept", signer, |tx| tx.accept(revision, signature))
    }

    pub fn reject<G: Signer>(&mut self, revision: RevisionId, signer: &G) -> Result<OpId, Error> {
        self.transaction("Reject", signer, |tx| tx.reject(revision))
    }

    /// Edit patch metadata.
    pub fn edit<G: Signer>(
        &mut self,
        title: String,
        description: String,
        signer: &G,
    ) -> Result<OpId, Error> {
        self.transaction("Edit", signer, |tx| tx.edit(title, description))
    }

    pub fn publish<G: Signer>(&mut self, signer: &G) -> Result<OpId, Error> {
        self.transaction("Publish", signer, |tx| tx.publish())
    }

    /// Comment on a patch revision.
    pub fn comment<G: Signer, S: ToString>(
        &mut self,
        revision: RevisionId,
        body: S,
        reply_to: thread::CommentId,
        signer: &G,
    ) -> Result<thread::CommentId, Error> {
        self.transaction("Comment", signer, |tx| tx.comment(revision, body, reply_to))
    }

    /// Update a patch with a new revision.
    pub fn update<G: Signer>(
        &mut self,
        description: impl ToString,
        proposed: Doc<Verified>,
        previous: Identity<Oid>,
        signer: &G,
    ) -> Result<(OpId, OpId), Error> {
        self.transaction("Add revision", signer, |tx| {
            let r = tx.revision(proposed, previous);
            let c = tx.thread(r, description);

            (r, c)
        })
    }
}

impl<'a, 'g> Deref for ProposalMut<'a, 'g> {
    type Target = Proposal;

    fn deref(&self) -> &Self::Target {
        &self.proposal
    }
}

pub struct Proposals<'a> {
    raw: store::Store<'a, Proposal>,
}

impl<'a> Deref for Proposals<'a> {
    type Target = store::Store<'a, Proposal>;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl<'a> Proposals<'a> {
    /// Open an patches store.
    pub fn open(
        whoami: PublicKey,
        repository: &'a storage::Repository,
    ) -> Result<Self, store::Error> {
        let raw = store::Store::open(whoami, repository)?;

        Ok(Self { raw })
    }

    /// Create a patch.
    pub fn create<'g, G: Signer>(
        &'g mut self,
        title: impl ToString,
        description: impl ToString,
        proposed: Doc<Verified>,
        previous: Identity<Oid>,
        signer: &G,
    ) -> Result<ProposalMut<'a, 'g>, Error> {
        let (id, patch, clock) =
            Transaction::initial("Create proposal", &mut self.raw, signer, |tx| {
                tx.revision(proposed, previous);
                tx.edit(title, description);
            })?;
        // Just a sanity check that our clock is advancing as expected.
        debug_assert_eq!(clock.get(), 3);

        Ok(ProposalMut::new(id, patch, clock, self))
    }

    /// Get a patch.
    pub fn get(&self, id: &ObjectId) -> Result<Option<Proposal>, store::Error> {
        self.raw.get(id).map(|r| r.map(|(p, _)| p))
    }

    /// Get a patch mutably.
    pub fn get_mut<'g>(&'g mut self, id: &ObjectId) -> Result<ProposalMut<'a, 'g>, store::Error> {
        let (proposal, clock) = self
            .raw
            .get(id)?
            .ok_or_else(move || store::Error::NotFound(TYPENAME.clone(), *id))?;

        Ok(ProposalMut {
            id: *id,
            clock,
            proposal,
            store: self,
        })
    }
}
