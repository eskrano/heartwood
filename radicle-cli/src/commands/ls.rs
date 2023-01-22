use std::ffi::OsString;

use crate::terminal as term;
use crate::terminal::args::{Args, Error, Help};

use radicle::storage::{ReadRepository, WriteStorage};

pub const HELP: Help = Help {
    name: "ls",
    description: "List projects",
    version: env!("CARGO_PKG_VERSION"),
    usage: r#"
Usage

    rad ls [<option>...]

Options

    --help    Print help
"#,
};

pub struct Options {}

impl Args for Options {
    fn from_args(args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let mut parser = lexopt::Parser::from_args(args);

        if let Some(arg) = parser.next()? {
            match arg {
                Long("help") => {
                    return Err(Error::Help.into());
                }
                _ => return Err(anyhow::anyhow!(arg.unexpected())),
            }
        }

        Ok((Options {}, vec![]))
    }
}

pub fn run(_options: Options, ctx: impl term::Context) -> anyhow::Result<()> {
    let profile = ctx.profile()?;
    let storage = &profile.storage;
    let mut table = term::Table::default();

    storage.projects()?.into_iter().for_each(|id| {
        let Ok(repo) = storage.repository(id) else { return };
        let Ok((_, head)) = repo.head() else { return };
        let Ok(proj) = repo.project_of(profile.id()) else { return };
        let head = term::format::oid(head);
        table.push([
            term::format::bold(proj.name()),
            term::format::tertiary(id.urn()),
            term::format::secondary(head),
            term::format::italic(proj.description()),
        ]);
    });
    table.render();

    Ok(())
}
