use std::{ffi::OsString, str::FromStr as _};

use anyhow::{anyhow, Context as _};
use radicle::cob::identity::{self, Proposal, ProposalId, Proposals};
use radicle::identity::Identity;
use radicle::prelude::Doc;
use radicle::storage::{WriteRepository, WriteStorage as _};
use radicle_crypto::Verified;

use crate::terminal as term;
use crate::terminal::args::{Args, Error, Help};

pub const HELP: Help = Help {
    name: "proposal",
    description: "Manage identity proposals",
    version: env!("CARGO_PKG_VERSION"),
    usage: r#"
Usage

    rad proposal create [--title|-t] [--description|-d]
    rad proposal list
    rad proposal (accept|reject|show|publish) <id>

Options

        --help                 Print help
"#,
};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct Metadata {
    title: String,
    description: String,
    proposed: Doc<Verified>,
}

#[derive(Clone, Debug, Default)]
pub enum Operation {
    Accept {
        id: ProposalId,
    },
    Reject {
        id: ProposalId,
    },
    Create {
        title: Option<String>,
        description: Option<String>,
    },
    Show {
        id: ProposalId,
    },
    #[default]
    List,
    Publish {
        id: ProposalId,
    },
}

#[derive(Default, PartialEq, Eq)]
pub enum OperationName {
    Accept,
    Reject,
    Create,
    Show,
    #[default]
    List,
    Publish,
}

pub struct Options {
    pub op: Operation,
}

impl Args for Options {
    fn from_args(args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let mut parser = lexopt::Parser::from_args(args);
        let mut op: Option<OperationName> = None;
        let mut id: Option<ProposalId> = None;
        let mut title: Option<String> = None;
        let mut description: Option<String> = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Long("help") => {
                    return Err(Error::Help.into());
                }
                Long("title") if op == Some(OperationName::Create) => {
                    title = Some(parser.value()?.to_string_lossy().into());
                }
                Long("description") if op == Some(OperationName::Create) => {
                    description = Some(parser.value()?.to_string_lossy().into());
                }
                Value(val) if op.is_none() => match val.to_string_lossy().as_ref() {
                    "c" | "create" => op = Some(OperationName::Create),
                    "l" | "list" => op = Some(OperationName::List),
                    "s" | "show" => op = Some(OperationName::Show),
                    "a" | "accept" => op = Some(OperationName::Accept),
                    "r" | "reject" => op = Some(OperationName::Reject),
                    "p" | "publish" => op = Some(OperationName::Publish),

                    unknown => anyhow::bail!("unknown operation '{}'", unknown),
                },
                Value(val) if op.is_some() => {
                    let val = val
                        .to_str()
                        .ok_or_else(|| anyhow!("proposal id specified is not UTF-8"))?;

                    id = Some(
                        ProposalId::from_str(val)
                            .map_err(|_| anyhow!("invalid proposal id '{}'", val))?,
                    );
                }
                _ => {
                    return Err(anyhow!(arg.unexpected()));
                }
            }
        }

        let op = match op.unwrap_or_default() {
            OperationName::Accept => Operation::Accept {
                id: id.ok_or_else(|| anyhow!("a proposal id must be provided"))?,
            },
            OperationName::Reject => Operation::Reject {
                id: id.ok_or_else(|| anyhow!("a proposal id must be provided"))?,
            },
            OperationName::Create => Operation::Create { title, description },
            OperationName::Show => Operation::Show {
                id: id.ok_or_else(|| anyhow!("a proposal id must be provided"))?,
            },
            OperationName::List => Operation::List,
            OperationName::Publish => Operation::Publish {
                id: id.ok_or_else(|| anyhow!("a proposal id must be provided"))?,
            },
        };
        Ok((Options { op }, vec![]))
    }
}

pub fn run(options: Options, ctx: impl term::Context) -> anyhow::Result<()> {
    let profile = ctx.profile()?;
    let signer = term::signer(&profile)?;
    let storage = &profile.storage;
    let (_, id) = radicle::rad::cwd()?;
    let repo = storage.repository(id)?;
    let mut proposals = Proposals::open(*signer.public_key(), &repo)?;
    let previous = Identity::load(signer.public_key(), &repo)?;

    match options.op {
        Operation::Accept { id } => {
            let mut proposal = proposals.get_mut(&id)?;
            let (revision_id, revision) = term::proposal::revision_select(&proposal).unwrap();
            let (_, signature) = revision.proposed.sign(&signer)?;
            proposal.accept(*revision_id, signature, &signer)?;
        }
        Operation::Reject { id } => {
            let mut proposal = proposals.get_mut(&id)?;
            let (revision_id, _) = term::proposal::revision_select(&proposal).unwrap();
            proposal.reject(*revision_id, &signer)?;
        }
        Operation::Create {
            title: Some(title),
            description: Some(description),
        } => {
            proposals.create(title, description, previous.doc.clone(), previous, &signer)?;
        }
        Operation::Create { title, description } => {
            let meta = Metadata {
                title: title.unwrap_or("Enter a title".to_owned()),
                description: description.unwrap_or("Enter a description".to_owned()),
                proposed: previous.doc.clone(),
            };
            let yaml = serde_yaml::to_string(&meta)?;
            let create: Metadata = match term::Editor::new().edit(&yaml)? {
                Some(meta) => {
                    serde_yaml::from_str(&meta).context("failed to parse proposal meta")?
                }
                None => return Err(anyhow!("Operation aborted!")),
            };

            proposals.create(
                create.title,
                create.description,
                create.proposed,
                previous,
                &signer,
            )?;
        }
        Operation::List => {
            let mut t = term::Table::new(term::table::TableOptions::default());
            for result in proposals.all()? {
                let (id, proposal, _) = result?;
                let published = if proposal.is_published() {
                    term::format::badge_positive("published")
                } else {
                    term::format::dim("open")
                };
                t.push([
                    term::format::yellow(id.to_string()),
                    term::format::italic(format!("{:?}", proposal.title())),
                    published,
                ]);
            }
            t.render();
        }
        Operation::Publish { id } => {
            let mut proposal = proposals.get_mut(&id)?;
            let (revision_id, _) = term::proposal::revision_merge_select(&proposal).unwrap();
            let published =
                Proposal::publish(&proposal, revision_id, signer.public_key(), repo.raw())?;
            proposal.publish(&signer)?;
            term::success!(
                "Published new identity '{}'",
                term::format::yellow(published.current)
            );
        }
        Operation::Show { id } => {
            let proposal = proposals
                .get(&id)?
                .context("No proposal with the given ID exists")?;
            show_proposal(&proposal)?;
        }
    }
    Ok(())
}

fn show_proposal(proposal: &identity::Proposal) -> anyhow::Result<()> {
    // Check that the proposal is published first, otherwise there
    // will be no latest revision.
    match proposal.published() {
        Some(published) => {
            term::info!("title: {}", published.title);
            term::info!(
                "description: {}",
                published
                    .description
                    .unwrap_or("No description provided".to_string())
            );
            term::info!("{}", term::format::badge_positive("published"));
        }
        None => {
            let (_, revision) = proposal
                .latest()
                .context("No latest proposal revision to show")?;
            term::info!("title: {}", proposal.title());
            term::info!(
                "description: {}",
                proposal.description().unwrap_or_default()
            );

            // TODO: how do we render a discussion thread?
            term::info!("author: {}", revision.author.id());
            print!(
                "{}",
                term::TextBox::new(format!(
                    "{}\n{}",
                    term::format::dim("diff"),
                    term::proposal::diff(revision)?
                ))
            );

            let accepted = revision.accepted();
            print!(
                "{}",
                term::format::positive(term::TextBox::new(format!(
                    "{}\ntotal: {}\nkeys: {}",
                    "accepted",
                    accepted.len(),
                    serde_json::to_string_pretty(&accepted)?,
                )))
            );

            let rejected = revision.rejected();
            print!(
                "{}",
                term::format::negative(term::TextBox::new(format!(
                    "{}\ntotal: {}\nkeys: {}",
                    "rejected",
                    rejected.len(),
                    serde_json::to_string_pretty(&rejected)?,
                )))
            );

            print!(
                "{}",
                term::TextBox::new(format!(
                    "{}: {}",
                    term::format::dim("quorum reached"),
                    if revision.reaches_quorum() {
                        term::format::positive("yes")
                    } else {
                        term::format::negative("no")
                    }
                ))
            );
        }
    }
    Ok(())
}
