use std::env;
use std::path::Path;
use std::str::FromStr;

use radicle::identity::Id;

fn main() -> anyhow::Result<()> {
    let cwd = Path::new(".").canonicalize()?;
    let profile = radicle::Profile::load()?;
    let signer = profile.signer()?;

    if let Some(id) = env::args().nth(1) {
        let id = Id::from_str(&id)?;
        let node = radicle::node::connect(profile.node())?;
        let repo = radicle::rad::clone(id, &cwd, &signer, &profile.storage, &node)?;

        println!(
            "ok: project {id} cloned into `{}`",
            repo.workdir().unwrap().display()
        );
    } else {
        anyhow::bail!("Error: a project id must be specified");
    }

    Ok(())
}
