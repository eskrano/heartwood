// Copyright © 2022 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::convert::TryFrom;

use git_commit::{self as commit, Commit};
use git_ext::Oid;
use git_trailers::OwnedTrailer;

use crate::history::entry::Timestamp;
use crate::{
    change::{self, store, Change},
    history::entry,
    signatures::{Signature, Signatures},
    trailers,
};

const MANIFEST_BLOB_NAME: &str = "manifest";
const CHANGE_BLOB_NAME: &str = "change";

pub mod error {
    use std::str::Utf8Error;
    use std::string::FromUtf8Error;

    use git_ext::Oid;
    use git_trailers::Error as TrailerError;
    use thiserror::Error;

    use crate::signatures::error::Signatures;

    #[derive(Debug, Error)]
    pub enum Create {
        #[error(transparent)]
        FromUtf8(#[from] FromUtf8Error),
        #[error(transparent)]
        Git(#[from] git2::Error),
        #[error(transparent)]
        Signer(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
        #[error(transparent)]
        Utf8(#[from] Utf8Error),
    }

    #[derive(Debug, Error)]
    pub enum Load {
        #[error(transparent)]
        Read(#[from] git_commit::error::Read),
        #[error(transparent)]
        Signatures(#[from] Signatures),
        #[error(transparent)]
        Git(#[from] git2::Error),
        #[error("a 'manifest' file was expected be found in '{0}'")]
        NoManifest(Oid),
        #[error("the 'manifest' found at '{0}' was not a blob")]
        ManifestIsNotBlob(Oid),
        #[error("the 'manifest' found at '{id}' was invalid: {err}")]
        InvalidManifest {
            id: Oid,
            #[source]
            err: serde_json::Error,
        },
        #[error("a 'change' file was expected be found in '{0}'")]
        NoChange(Oid),
        #[error("the 'change' found at '{0}' was not a blob")]
        ChangeNotBlob(Oid),
        #[error("the 'change' found at '{0}' was not signed")]
        ChangeNotSigned(Oid),
        #[error("the 'change' found at '{0}' has more than one signature")]
        TooManySignatures(Oid),
        #[error(transparent)]
        ResourceTrailer(#[from] super::trailers::error::InvalidResourceTrailer),
        #[error("non utf-8 characters in commit message")]
        Utf8(#[from] FromUtf8Error),
        #[error(transparent)]
        Trailer(#[from] TrailerError),
    }
}

impl change::Storage for git2::Repository {
    type CreateError = error::Create;
    type LoadError = error::Load;

    type ObjectId = Oid;
    type Resource = Oid;
    type Signatures = Signature;

    fn create<Signer>(
        &self,
        resource: Self::Resource,
        signer: &Signer,
        spec: store::Create<Self::ObjectId>,
    ) -> Result<Change, Self::CreateError>
    where
        Signer: crypto::Signer,
    {
        let change::Create {
            typename,
            history_type,
            tips,
            message,
            contents,
        } = spec;
        let manifest = store::Manifest {
            typename,
            history_type,
        };

        let revision = write_manifest(self, &manifest, &contents)?;
        let tree = self.find_tree(revision)?;

        let signature = {
            let sig = signer.sign(revision.as_bytes());
            let key = signer.public_key();
            Signature::from((*key, sig))
        };

        let (id, timestamp) = write_commit(self, resource, tips, message, signature.clone(), tree)?;
        Ok(Change {
            id,
            revision: revision.into(),
            signature,
            resource,
            manifest,
            contents,
            timestamp,
        })
    }

    fn load(&self, id: Self::ObjectId) -> Result<Change, Self::LoadError> {
        let commit = Commit::read(self, id.into())?;
        let timestamp = git2::Time::from(commit.committer().time).seconds() as u64;
        let resource = parse_resource_trailer(commit.trailers())?;
        let mut signatures = Signatures::try_from(&commit)?
            .into_iter()
            .collect::<Vec<_>>();
        let Some(signature) = signatures.pop() else {
            return Err(error::Load::ChangeNotSigned(id));
        };
        if !signatures.is_empty() {
            return Err(error::Load::TooManySignatures(id));
        }

        let tree = self.find_tree(commit.tree())?;
        let manifest = load_manifest(self, &tree)?;
        let contents = load_contents(self, &tree)?;

        Ok(Change {
            id,
            revision: tree.id().into(),
            signature: signature.into(),
            resource,
            manifest,
            contents,
            timestamp,
        })
    }
}

fn parse_resource_trailer<'a>(
    trailers: impl Iterator<Item = &'a OwnedTrailer>,
) -> Result<Oid, error::Load> {
    for trailer in trailers {
        match trailers::ResourceCommitTrailer::try_from(trailer) {
            Err(trailers::error::InvalidResourceTrailer::WrongToken) => {
                continue;
            }
            Err(err) => return Err(err.into()),
            Ok(resource) => return Ok(resource.oid().into()),
        }
    }
    Err(error::Load::from(
        trailers::error::InvalidResourceTrailer::NoTrailer,
    ))
}

fn load_manifest(
    repo: &git2::Repository,
    tree: &git2::Tree,
) -> Result<store::Manifest, error::Load> {
    let manifest_tree_entry = tree
        .get_name(MANIFEST_BLOB_NAME)
        .ok_or_else(|| error::Load::NoManifest(tree.id().into()))?;
    let manifest_object = manifest_tree_entry.to_object(repo)?;
    let manifest_blob = manifest_object
        .as_blob()
        .ok_or_else(|| error::Load::ManifestIsNotBlob(tree.id().into()))?;
    serde_json::from_slice(manifest_blob.content()).map_err(|err| error::Load::InvalidManifest {
        id: tree.id().into(),
        err,
    })
}

fn load_contents(
    repo: &git2::Repository,
    tree: &git2::Tree,
) -> Result<entry::Contents, error::Load> {
    let contents_tree_entry = tree
        .get_name(CHANGE_BLOB_NAME)
        .ok_or_else(|| error::Load::NoChange(tree.id().into()))?;
    let contents_object = contents_tree_entry.to_object(repo)?;
    let contents_blob = contents_object
        .as_blob()
        .ok_or_else(|| error::Load::ChangeNotBlob(tree.id().into()))?;
    Ok(contents_blob.content().to_owned())
}

fn write_commit<O>(
    repo: &git2::Repository,
    resource: O,
    tips: Vec<O>,
    message: String,
    signature: Signature,
    tree: git2::Tree,
) -> Result<(Oid, Timestamp), error::Create>
where
    O: AsRef<git2::Oid>,
{
    let resource = *resource.as_ref();

    let mut parents = tips.iter().map(|o| *o.as_ref()).collect::<Vec<_>>();
    parents.push(resource);

    let trailers: Vec<OwnedTrailer> = vec![trailers::ResourceCommitTrailer::from(resource).into()];

    {
        let author = repo.signature()?;
        let timestamp = author.when().seconds() as Timestamp;
        let mut headers = commit::Headers::new();
        headers.push(
            "gpgsig",
            &String::from_utf8(crypto::ssh::ExtendedSignature::from(signature).to_armored())?,
        );
        let author = commit::Author::try_from(&author)?;
        let oid = Commit::new(
            tree.id(),
            parents,
            author.clone(),
            author,
            headers,
            message,
            trailers,
        )
        .write(repo)?;

        Ok((Oid::from(oid), timestamp))
    }
}

fn write_manifest(
    repo: &git2::Repository,
    manifest: &store::Manifest,
    contents: &entry::Contents,
) -> Result<git2::Oid, git2::Error> {
    let mut tb = repo.treebuilder(None)?;
    // SAFETY: we're serializing to an in memory buffer so the only source of
    // errors here is a programming error, which we can't recover from
    let serialized_manifest = serde_json::to_vec(manifest).unwrap();
    let manifest_oid = repo.blob(&serialized_manifest)?;
    tb.insert(
        MANIFEST_BLOB_NAME,
        manifest_oid,
        git2::FileMode::Blob.into(),
    )?;

    let change_blob = repo.blob(contents.as_ref())?;
    tb.insert(CHANGE_BLOB_NAME, change_blob, git2::FileMode::Blob.into())?;

    tb.write()
}
