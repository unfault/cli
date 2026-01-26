//! # Addon Commands
//!
//! "Addons" are optional external tools that integrate with Unfault.
//!
//! Today this is intentionally narrow and first-party:
//! - `fault` CLI binary (downloaded from GitHub releases)

use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use futures_util::StreamExt;
use reqwest::header;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

use crate::exit_codes::*;

const FAULT_REPO: &str = "fault-project/fault-cli";
const FAULT_BIN_NAME: &str = "fault";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonStatus {
    Installed,
    Missing,
}

#[derive(Debug, Clone)]
pub struct FaultAddonInfo {
    pub status: AddonStatus,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
}

pub fn detect_fault() -> FaultAddonInfo {
    // Try PATH first.
    if let Ok(output) = Command::new(FAULT_BIN_NAME).arg("--version").output() {
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let path = which_in_path(FAULT_BIN_NAME);
            return FaultAddonInfo {
                status: AddonStatus::Installed,
                version: if version.is_empty() {
                    None
                } else {
                    Some(version)
                },
                path,
            };
        }
    }

    // Also consider ~/.local/bin/fault even if PATH isn't updated.
    if let Some(p) = default_user_bin_dir().map(|d| d.join(FAULT_BIN_NAME)) {
        if p.exists() {
            return FaultAddonInfo {
                status: AddonStatus::Installed,
                version: None,
                path: Some(p),
            };
        }
    }

    FaultAddonInfo {
        status: AddonStatus::Missing,
        version: None,
        path: None,
    }
}

pub async fn install_fault(force: bool) -> Result<i32> {
    if cfg!(windows) {
        eprintln!(
            "{} fault addon install is not implemented on Windows yet.",
            "✗".red().bold()
        );
        return Ok(EXIT_CONFIG_ERROR);
    }

    let detected = detect_fault();
    if detected.status == AddonStatus::Installed && !force {
        println!(
            "{} fault: {}",
            "✓".bright_green().bold(),
            "Already installed".green()
        );
        if let Some(v) = detected.version {
            println!("  {} {}", "version:".dimmed(), v.dimmed());
        }
        if let Some(p) = detected.path {
            println!(
                "  {} {}",
                "path:".dimmed(),
                p.display().to_string().dimmed()
            );
        }
        return Ok(EXIT_SUCCESS);
    }

    let install_dir =
        default_user_bin_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    tokio::fs::create_dir_all(&install_dir)
        .await
        .with_context(|| format!("Failed to create {}", install_dir.display()))?;

    let client = reqwest::Client::new();
    let release = fetch_latest_fault_release(&client).await?;
    let target_asset = select_fault_asset(&release)?;

    println!(
        "{} Downloading fault {} ({})",
        "→".cyan(),
        release.tag_name.cyan(),
        target_asset.name.dimmed()
    );

    let tmp_path = install_dir.join(format!("{}.tmp-{}", FAULT_BIN_NAME, Uuid::new_v4()));
    download_with_sha256_check(&client, &target_asset, &tmp_path).await?;

    // Make executable (unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&tmp_path).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&tmp_path, perms).await?;
    }

    let final_path = install_dir.join(FAULT_BIN_NAME);
    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .with_context(|| format!("Failed to move binary to {}", final_path.display()))?;

    println!(
        "{} fault installed: {}",
        "✓".bright_green().bold(),
        final_path.display().to_string().green()
    );

    if !is_dir_on_path(&install_dir) {
        println!();
        println!(
            "{} Add this to your PATH (example for bash/zsh):",
            "ℹ".blue()
        );
        println!("  export PATH=\"{}:$PATH\"", install_dir.display());
    }

    Ok(EXIT_SUCCESS)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

async fn fetch_latest_fault_release(client: &reqwest::Client) -> Result<GithubRelease> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        FAULT_REPO
    );
    let resp = client
        .get(url)
        .header(header::USER_AGENT, "unfault-cli")
        .send()
        .await
        .context("Failed to query GitHub Releases")?;

    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("GitHub API returned {}", status));
    }

    let release = resp
        .json::<GithubRelease>()
        .await
        .context("Failed to parse GitHub release JSON")?;
    Ok(release)
}

fn select_fault_asset(release: &GithubRelease) -> Result<GithubAsset> {
    let target_triple = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        (os, arch) => {
            return Err(anyhow!(
                "Unsupported platform for fault addon install: {} {}",
                os,
                arch
            ));
        }
    };

    let expected_name = format!("fault-cli-{}-{}", release.tag_name, target_triple);
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == expected_name)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "Could not find release asset '{}' (available: {})",
                expected_name,
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    Ok(asset)
}

async fn download_with_sha256_check(
    client: &reqwest::Client,
    asset: &GithubAsset,
    dest_path: &Path,
) -> Result<()> {
    let expected = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .ok_or_else(|| anyhow!("No sha256 digest available for asset {}", asset.name))?;

    let resp = client
        .get(&asset.browser_download_url)
        .header(header::USER_AGENT, "unfault-cli")
        .send()
        .await
        .context("Failed to download fault binary")?;

    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("Download failed with {}", status));
    }

    let mut file = tokio::fs::File::create(dest_path)
        .await
        .with_context(|| format!("Failed to create {}", dest_path.display()))?;

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read download stream")?;
        hasher.update(&chunk);
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .context("Failed to write downloaded file")?;
    }
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .context("Failed to flush downloaded file")?;

    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        // Best-effort cleanup.
        let _ = tokio::fs::remove_file(dest_path).await;
        return Err(anyhow!(
            "SHA256 mismatch for {} (expected {}, got {})",
            asset.name,
            expected,
            actual
        ));
    }

    Ok(())
}

fn default_user_bin_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local").join("bin"))
}

fn is_dir_on_path(dir: &Path) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|p| p == dir)
}

fn which_in_path(bin: &str) -> Option<PathBuf> {
    let Ok(path) = std::env::var("PATH") else {
        return None;
    };
    for p in std::env::split_paths(&path) {
        let candidate = p.join(bin);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
