mod api;
mod cache;
mod cli;
mod engine;
mod entropy;
mod format;
mod model;
mod parser;
mod resolver;
mod rules;
mod scanner;
mod slop;
mod taint;

use std::path::PathBuf;
use std::process::ExitCode;
use clap::Parser;

fn main() -> ExitCode {
    let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
    let code = runtime.block_on(async {
        let cli = cli::Cli::parse();
        match run(&cli).await {
            Ok(report) => {
                print!("{}", format::render(&report, cli.json));
                ExitCode::from(report.exit_code(cli.fail_on.as_deref()))
            }
            Err(e) => {
                eprintln!("error: {e:?}");
                ExitCode::from(2)
            }
        }
    });
    code
}

async fn run(cli: &cli::Cli) -> Result<model::Report, anyhow::Error> {
    let cwd = std::env::current_dir().unwrap_or_else(|e| {
        eprintln!("warning: cannot access current directory: {e:?}");
        PathBuf::from(".")
    });
    let root = cli.source_dir.clone().unwrap_or(cwd);

    let slop_enabled = cli.all || cli.slop || cli.slop_only;

    // Standalone slop audit: no manifest, no dependency resolution needed.
    if cli.slop_only {
        let files = scanner::collect_source_files(&root)?;
        let slop = slop::audit(&root, &files);
        return Ok(model::Report {
            source_dir: root,
            scanned_files: files.len(),
            dependencies: 0,
            vulnerabilities: 0,
            hits: Vec::new(),
            cache_status: model::CacheStatus { queried: 0, used_cached: 0, fetched: 0 },
            slop,
            slop_only: true,
        });
    }

    let mut parsed = parser::parse_project(&root)?;

    let deps = if cli.dev {
        parsed.deps
    } else {
        parsed.deps.retain(|d| !d.is_dev);
        parsed.deps
    };


    let (imported, files) = scanner::scan(
        &root,
        deps.iter().map(|d| model::normalize_name(&d.name)).collect(),
    )?;
    let mut report = resolver::resolve(
        &deps,
        &parsed.graph,
        &imported,
        cli.update,
        cli.package.clone(),
        files.len(),
        root.clone(),
    )
    .await?;

    if slop_enabled {
        report.slop = slop::audit(&root, &files);
    }

    Ok(report)
}
