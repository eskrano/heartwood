use std::path::Path;

use radicle::storage::WriteStorage;

fn main() -> anyhow::Result<()> {
    let cwd = Path::new(".").canonicalize()?;
    let repo = radicle::git::raw::Repository::open(&cwd)?;
    let profile = radicle::Profile::load()?;
    let (_, id) = radicle::rad::remote(&repo)?;

    let output = radicle::git::run(&cwd, &["push", "rad"])?;
    println!("{}", output);

    let project = profile.storage.repository(&id)?;
    let sigrefs = profile.storage.sign_refs(&project, &profile.signer)?;
    println!("ok: {}", sigrefs.signature);

    Ok(())
}
