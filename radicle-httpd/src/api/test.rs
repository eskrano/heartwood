use std::path::Path;
use std::sync::Arc;
use std::{env, fs};

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use serde_json::Value;
use tower::ServiceExt;

use radicle::cob::issue::Issues;
use radicle::git::raw as git2;
use radicle::storage::WriteStorage;
use radicle_cli::commands::rad_init;
use radicle_crypto::ssh::keystore::MemorySigner;
use radicle_crypto::Signer;

use crate::api::Context;

pub const HEAD: &str = "1e978d19f251cd9821d9d9a76d1bd436bf0690d5";
pub const HEAD_1: &str = "f604ce9fd5b7cc77b7609beda45ea8760bee78f7";

const PASSWORD: &str = "radicle";

pub fn seed(dir: &Path) -> Context {
    let workdir = dir.join("hello-world");
    let rad_home = dir.join("radicle");

    env::set_var("RAD_PASSPHRASE", PASSWORD);
    env::set_var("RAD_DEBUG", "1");

    fs::create_dir_all(&workdir).unwrap();
    fs::create_dir_all(&rad_home).unwrap();

    // add commits to workdir (repo)
    let repo = git2::Repository::init(&workdir).unwrap();
    let tree =
        radicle::git::write_tree(Path::new("README"), "Hello World!\n".as_bytes(), &repo).unwrap();

    let sig_time = git2::Time::new(1673001014, 0);
    let sig = git2::Signature::new("Alice Liddell", "alice@radicle.xyz", &sig_time).unwrap();

    let oid = repo
        .commit(Some("HEAD"), &sig, &sig, "Initial commit\n", &tree, &[])
        .unwrap();
    let commit = repo.find_commit(oid).unwrap();

    repo.checkout_tree(tree.as_object(), None).unwrap();

    fs::create_dir(workdir.join("dir1")).unwrap();
    fs::write(
        workdir.join("dir1").join("README"),
        "Hello World from dir1!\n",
    )
    .unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_all(["."], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();

    let oid = index.write_tree().unwrap();
    let tree = repo.find_tree(oid).unwrap();

    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "Add another folder\n",
        &tree,
        &[&commit],
    )
    .unwrap();

    // eq. rad auth
    let profile = radicle::Profile::init(rad_home.into(), PASSWORD.to_owned()).unwrap();

    // rad init
    rad_init::init(
        rad_init::Options {
            path: Some(workdir.clone()),
            name: Some("hello-world".to_string()),
            description: Some("Rad repository for tests".to_string()),
            branch: None,
            interactive: false.into(),
            setup_signing: false,
            set_upstream: false,
        },
        &profile,
    )
    .unwrap();

    // eq. rad issue new
    env::set_var("RAD_COMMIT_TIME", "1673001014");

    let signer = MemorySigner::load(&profile.keystore, PASSWORD.to_owned().into()).unwrap();
    let storage = &profile.storage;
    let (_, id) = radicle::rad::repo(&workdir).unwrap();
    let repo = storage.repository(id).unwrap();
    let mut issues = Issues::open(*signer.public_key(), &repo).unwrap();
    issues
        .create(
            "Issue #1".to_string(),
            "Change 'hello world' to 'hello everyone'".to_string(),
            &[],
            &signer,
        )
        .unwrap();

    Context {
        profile: Arc::new(profile),
        sessions: Default::default(),
    }
}

pub async fn request(app: &Router, path: impl ToString) -> Response {
    Response(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(path.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
}

pub struct Response(axum::response::Response);

impl Response {
    pub async fn json(self) -> Value {
        let body = hyper::body::to_bytes(self.0.into_body()).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    pub fn status(&self) -> axum::http::StatusCode {
        self.0.status()
    }
}
