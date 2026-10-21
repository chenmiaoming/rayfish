//! illumos: take over `/etc/resolv.conf` directly.
//!
//! A non-global zone's `resolv.conf` is regenerated from the zone config at
//! boot only, so a file written here stays until the next zone boot. We list
//! our resolver first and the captured upstreams behind it, so the host keeps
//! resolving if the daemon stops answering.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::resolv_file::{
    backup_resolv_file, exists_no_follow, restore_resolv_backup, write_resolv_file,
};
use super::{DnsConfigurator, SearchDomain, resolver_addr};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const BACKUP: &str = "/etc/resolv.conf.before-rayfish";
const MARKER: &str = "# Managed by rayfish.";
/// illumos' resolver reads at most six search domains.
const MAX_SEARCH: usize = 6;

fn parse_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split('#').next()?.split_whitespace();
            (f.next()? == "nameserver").then_some(())?;
            f.next()?.parse().ok()
        })
        .collect()
}

fn parse_search(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split('#').next()?.split_whitespace();
            matches!(f.next()?, "search" | "domain").then(|| f.map(str::to_owned).collect())
        })
        .last()
        .unwrap_or_default()
}

fn is_ours(contents: &str) -> bool {
    contents.lines().any(|l| l.trim() == MARKER)
}

fn render(search: &[String], fallbacks: &[IpAddr]) -> String {
    let mut out = format!("{MARKER}\n");
    if !search.is_empty() {
        out.push_str(&format!("search {}\n", search.join(" ")));
    }
    out.push_str(&format!("nameserver {}\n", resolver_addr()));
    for ip in fallbacks {
        out.push_str(&format!("nameserver {ip}\n"));
    }
    out
}

/// The file without the lines we wrote: marker, our nameserver and the search line.
fn strip_ours(contents: &str) -> String {
    let ours = resolver_addr();
    contents
        .lines()
        .filter(|l| {
            let t = l.trim();
            t != MARKER
                && !t.starts_with("search ")
                && !(t.starts_with("nameserver ")
                    && t["nameserver ".len()..].trim().parse::<IpAddr>().ok() == Some(ours))
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

fn merge_search(host: &[String], ours: &[SearchDomain]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in ours
        .iter()
        .map(SearchDomain::as_str)
        .chain(host.iter().map(String::as_str))
    {
        if !d.is_empty() && !out.iter().any(|x| x == d) {
            out.push(d.to_owned());
        }
    }
    out.truncate(MAX_SEARCH);
    out
}

pub(crate) struct IllumosResolvConf {
    captured_upstreams: Vec<IpAddr>,
    /// The host's own search domains, kept so a later join/leave re-merges
    /// against them instead of piling ours on the previous render.
    captured_search: Vec<String>,
    search: Mutex<Vec<String>>,
}

impl IllumosResolvConf {
    pub(crate) async fn new() -> Self {
        let contents = tokio::fs::read_to_string(RESOLV_CONF)
            .await
            .unwrap_or_default();
        // A file we wrote earlier is not "the host's": ignore it.
        let (nameservers, search) = if is_ours(&contents) {
            (Vec::new(), Vec::new())
        } else {
            (parse_nameservers(&contents), parse_search(&contents))
        };
        // Only servers that answer are worth betting the zone's DNS on.
        let live = crate::dns::resolver::live_upstreams(&nameservers).await;
        Self {
            captured_upstreams: live,
            search: Mutex::new(search.clone()),
            captured_search: search,
        }
    }
}

#[async_trait]
impl DnsConfigurator for IllumosResolvConf {
    async fn apply(&self) -> Result<()> {
        anyhow::ensure!(
            !self.captured_upstreams.is_empty(),
            "no working DNS server found in /etc/resolv.conf, so taking it over would leave \
             this zone unable to resolve anything"
        );
        let path = Path::new(RESOLV_CONF);
        let backup = Path::new(BACKUP);
        if !exists_no_follow(backup) {
            let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
            if !current.is_empty() && !is_ours(&current) {
                backup_resolv_file(path, backup).context("backing up /etc/resolv.conf")?;
            }
        }
        let search = self.search.lock().unwrap().clone();
        write_resolv_file(path, render(&search, &self.captured_upstreams).as_bytes())
            .context("writing /etc/resolv.conf")?;
        tracing::info!(upstreams = ?self.captured_upstreams, "configured /etc/resolv.conf directly");
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        let path = Path::new(RESOLV_CONF);
        let backup = Path::new(BACKUP);
        if exists_no_follow(backup) {
            restore_resolv_backup(backup, path).context("restoring /etc/resolv.conf")?;
            if exists_no_follow(backup) {
                let _ = tokio::fs::remove_file(backup).await;
            }
            return Ok(());
        }
        // No backup: strip our lines in place rather than deleting the file.
        if let Ok(current) = tokio::fs::read_to_string(path).await
            && is_ours(&current)
        {
            write_resolv_file(path, strip_ours(&current).as_bytes())
                .context("removing our entries from /etc/resolv.conf")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "illumos-resolv.conf"
    }

    fn captured_upstreams(&self) -> Vec<IpAddr> {
        self.captured_upstreams.clone()
    }

    fn fallback_upstreams(&self) -> Vec<IpAddr> {
        self.captured_upstreams.clone()
    }

    async fn set_search_domains(&self, domains: &[SearchDomain], _tun_name: &str) -> Result<()> {
        let merged = merge_search(&self.captured_search, domains);
        *self.search.lock().unwrap() = merged.clone();
        let path = Path::new(RESOLV_CONF);
        // Only rewrite a file that is still ours.
        let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
        if !is_ours(&current) {
            return Ok(());
        }
        write_resolv_file(path, render(&merged, &self.captured_upstreams).as_bytes())
            .context("writing search domains to /etc/resolv.conf")
    }
}
