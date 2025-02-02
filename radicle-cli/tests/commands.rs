use std::env;
use std::path::Path;

use radicle::profile::{Home, Profile};
use radicle::test::fixtures;

mod framework;
use framework::TestFormula;

/// Run a CLI test file.
fn test(
    test: impl AsRef<Path>,
    cwd: impl AsRef<Path>,
    profile: Option<&Profile>,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = tempfile::tempdir().unwrap();
    let home = if let Some(profile) = profile {
        profile.home().to_path_buf()
    } else {
        tmp.path().to_path_buf()
    };

    TestFormula::new()
        .env("GIT_AUTHOR_DATE", "1671125284")
        .env("GIT_AUTHOR_EMAIL", "radicle@localhost")
        .env("GIT_AUTHOR_NAME", "radicle")
        .env("GIT_COMMITTER_DATE", "1671125284")
        .env("GIT_COMMITTER_EMAIL", "radicle@localhost")
        .env("GIT_COMMITTER_NAME", "radicle")
        .env("RAD_DEBUG", "1")
        .env("RAD_HOME", home.to_string_lossy())
        .env("RAD_PASSPHRASE", "radicle")
        .env("TZ", "Etc/GMT")
        .env(radicle_cob::git::RAD_COMMIT_TIME, "1671125284")
        .cwd(cwd)
        .file(base.join(test))?
        .run()?;

    Ok(())
}

/// Create a new user profile.
fn profile(home: &Path) -> Profile {
    // Set debug mode, to make test output more predictable.
    env::set_var("RAD_DEBUG", "1");
    // Setup a new user.
    Profile::init(Home::new(home.to_path_buf()), "radicle".to_owned()).unwrap()
}

#[test]
fn rad_auth() {
    test("examples/rad-auth.md", Path::new("."), None).unwrap();
}

#[test]
fn rad_issue() {
    let home = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let profile = profile(home.path());

    // Setup a test repository.
    fixtures::repository(working.path());
    // Set a fixed commit time.
    env::set_var(radicle_cob::git::RAD_COMMIT_TIME, "1671125284");

    test("examples/rad-init.md", working.path(), Some(&profile)).unwrap();
    test("examples/rad-issue.md", working.path(), Some(&profile)).unwrap();
}

#[test]
fn rad_init() {
    let home = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let profile = profile(home.path());

    // Setup a test repository.
    fixtures::repository(working.path());

    test("examples/rad-init.md", working.path(), Some(&profile)).unwrap();
}

#[test]
fn rad_delegate() {
    let home = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let profile = profile(home.path());

    // Setup a test repository.
    fixtures::repository(working.path());

    test("examples/rad-init.md", working.path(), Some(&profile)).unwrap();
    test("examples/rad-delegate.md", working.path(), Some(&profile)).unwrap();
}

#[test]
#[ignore]
fn rad_patch() {
    let home = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let profile = profile(home.path());

    // Setup a test repository.
    fixtures::repository(working.path());

    test("examples/rad-init.md", working.path(), Some(&profile)).unwrap();
    test("examples/rad-issue.md", working.path(), Some(&profile)).unwrap();
    test("examples/rad-patch.md", working.path(), Some(&profile)).unwrap();
}
