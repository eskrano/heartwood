use std::ffi::OsString;

use anyhow::anyhow;
use radicle::crypto::Signer;

use crate::terminal as term;
use crate::terminal::args::{Args, Error, Help};

pub const HELP: Help = Help {
    name: "web",
    description: "Connect web with node",
    version: env!("CARGO_PKG_VERSION"),
    usage: r#"
Usage

    rad web [<options>...]

Options

    --host, -h             httpd host to bind to
    --web, -w              interface host to bind to
    --verbose, -v          Verbose output
    --help                 Print help
"#,
};

#[derive(Debug)]
pub struct Options {
    pub host: String,
    pub web: String,
    pub verbose: bool,
}

impl Args for Options {
    fn from_args(args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let mut parser = lexopt::Parser::from_args(args);
        let mut host = None;
        let mut web = None;
        let mut verbose = false;

        while let Some(arg) = parser.next()? {
            match arg {
                Long("verbose") | Short('v') => verbose = true,
                Long("host") | Short('h') => {
                    host = Some(parser.value()?.to_string_lossy().to_string())
                }
                Long("web") | Short('w') => {
                    web = Some(parser.value()?.to_string_lossy().to_string())
                }
                Long("help") => {
                    return Err(Error::Help.into());
                }
                _ => {
                    return Err(anyhow!(arg.unexpected()));
                }
            }
        }

        Ok((
            Options {
                verbose,
                host: host.unwrap_or(String::from("http://0.0.0.0:8080")),
                web: web.unwrap_or(String::from("http://localhost:3000")),
            },
            vec![],
        ))
    }
}

pub fn run(options: Options, ctx: impl term::Context) -> anyhow::Result<()> {
    let session_id = ureq::post(&format!("{}/api/v1/sessions", options.host))
        .call()?
        .into_string()?;
    let profile = ctx.profile()?;
    let public_key = profile.id();
    let signer = profile.signer()?;
    let payload = format!("{}:{}", session_id, public_key);
    let signature = signer.try_sign(payload.as_bytes())?;
    term::info!(
        "{}/session/{}?pk={}&sig={}",
        options.web,
        session_id,
        public_key,
        signature,
    );

    Ok(())
}
