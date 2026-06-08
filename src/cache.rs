//! Optional on-disk cache for normalized source findings.
//!
//! The cache is keyed by `(source, indicator)` and stores the normalized
//! `Vec<SourceFinding>` a source returned, plus the time it was written. Entries
//! older than the configured TTL are ignored (and treated as a miss). The cache
//! is intentionally *outside* the source modules: source code stays
//! cache-unaware and `cached_lookup` wraps each call.
//!
//! Storage is a plain JSON file per `(source, indicator)` pair under a cache
//! directory (default `~/.cache/ioccheck/`). All cache I/O is best-effort: a
//! read error or malformed entry is a miss, and a write error is ignored, so the
//! cache can never turn a successful lookup into a failure. API keys are never
//! part of a finding, so nothing secret is ever written.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::indicator::Indicator;
use crate::output::SourceFinding;

/// A single cached source result.
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    /// Unix timestamp (seconds) at which the entry was written.
    cached_at: u64,
    /// The normalized findings the source returned at that time.
    findings: Vec<SourceFinding>,
}

/// A best-effort, TTL-bounded JSON cache of source findings.
pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
}

impl Cache {
    /// Build a cache rooted at the default directory (`$XDG_CACHE_HOME/ioccheck`
    /// or `$HOME/.cache/ioccheck`, falling back to the system temp dir).
    pub fn new(ttl_secs: u64) -> Self {
        Self::with_dir(default_cache_dir(), ttl_secs)
    }

    /// Build a cache rooted at an explicit directory. Used by tests.
    pub fn with_dir(dir: PathBuf, ttl_secs: u64) -> Self {
        Self {
            dir,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Return cached findings for `(source, indicator)` if a fresh entry exists.
    /// Any I/O error, parse error, or expired entry is reported as a miss.
    pub fn get(&self, source: &str, indicator: &Indicator) -> Option<Vec<SourceFinding>> {
        let path = self.entry_path(source, indicator);
        let raw = std::fs::read_to_string(&path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&raw).ok()?;

        let age = now_unix_secs().checked_sub(entry.cached_at)?;
        // Inclusive boundary so `--cache-ttl 0` disables reuse entirely.
        if Duration::from_secs(age) >= self.ttl {
            return None;
        }
        Some(entry.findings)
    }

    /// Store findings for `(source, indicator)`. Errors are ignored: the cache
    /// must never break a successful lookup.
    pub fn put(&self, source: &str, indicator: &Indicator, findings: &[SourceFinding]) {
        let entry = CacheEntry {
            cached_at: now_unix_secs(),
            findings: findings.to_vec(),
        };
        let Ok(serialized) = serde_json::to_string(&entry) else {
            return;
        };
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let _ = std::fs::write(self.entry_path(source, indicator), serialized);
    }

    /// Deterministic file path for a `(source, indicator)` pair. The components
    /// are hashed into a hex filename so arbitrary URL/domain characters never
    /// reach the filesystem.
    fn entry_path(&self, source: &str, indicator: &Indicator) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        source.hash(&mut hasher);
        indicator.kind.as_str().hash(&mut hasher);
        indicator.value.hash(&mut hasher);
        self.dir.join(format!("{:016x}.json", hasher.finish()))
    }
}

/// Run a source lookup, consulting the cache first when one is configured.
///
/// On a fresh cache hit the closure is never invoked. On a miss the closure
/// runs and its `Ok` result is written back; errors are propagated unchanged and
/// never cached.
pub async fn cached_lookup<F, Fut>(
    cache: Option<&Cache>,
    source: &str,
    indicator: &Indicator,
    lookup: F,
) -> anyhow::Result<Vec<SourceFinding>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<SourceFinding>>>,
{
    if let Some(cache) = cache {
        if let Some(findings) = cache.get(source, indicator) {
            return Ok(findings);
        }
    }

    let findings = lookup().await?;

    if let Some(cache) = cache {
        cache.put(source, indicator, &findings);
    }
    Ok(findings)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn default_cache_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Path::new(&xdg).join("ioccheck");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Path::new(&home).join(".cache").join("ioccheck");
        }
    }
    std::env::temp_dir().join("ioccheck")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorType;
    use crate::output::Severity;

    fn sample_indicator() -> Indicator {
        Indicator::new("8.8.8.8", IndicatorType::Ip)
    }

    fn sample_findings() -> Vec<SourceFinding> {
        vec![SourceFinding {
            source: "ThreatFox".to_string(),
            severity: Severity::High,
            summary: "Listed as C2 infrastructure".to_string(),
            details: None,
        }]
    }

    #[test]
    fn miss_then_hit_round_trips_findings() {
        let dir = std::env::temp_dir().join(format!("ioccheck-test-{}", now_unix_secs()));
        let cache = Cache::with_dir(dir.clone(), 3600);
        let indicator = sample_indicator();

        assert!(cache.get("ThreatFox", &indicator).is_none());

        cache.put("ThreatFox", &indicator, &sample_findings());
        let hit = cache
            .get("ThreatFox", &indicator)
            .expect("expected cache hit");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].source, "ThreatFox");
        assert_eq!(hit[0].severity, Severity::High);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let dir = std::env::temp_dir().join(format!("ioccheck-ttl-{}", now_unix_secs()));
        let cache = Cache::with_dir(dir.clone(), 0);
        let indicator = sample_indicator();

        cache.put("ThreatFox", &indicator, &sample_findings());
        // TTL of zero means any stored entry is already stale.
        assert!(cache.get("ThreatFox", &indicator).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn distinct_sources_and_indicators_do_not_collide() {
        let dir = std::env::temp_dir().join(format!("ioccheck-key-{}", now_unix_secs()));
        let cache = Cache::with_dir(dir.clone(), 3600);
        let indicator = sample_indicator();
        let other = Indicator::new("1.1.1.1", IndicatorType::Ip);

        cache.put("ThreatFox", &indicator, &sample_findings());

        assert!(cache.get("AbuseIPDB", &indicator).is_none());
        assert!(cache.get("ThreatFox", &other).is_none());
        assert!(cache.get("ThreatFox", &indicator).is_some());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cached_lookup_only_calls_source_on_miss() {
        let dir = std::env::temp_dir().join(format!("ioccheck-wrap-{}", now_unix_secs()));
        let cache = Cache::with_dir(dir.clone(), 3600);
        let indicator = sample_indicator();

        let calls = std::cell::Cell::new(0);
        let run = || async {
            calls.set(calls.get() + 1);
            Ok(sample_findings())
        };

        let first = cached_lookup(Some(&cache), "ThreatFox", &indicator, run)
            .await
            .expect("first lookup");
        let second = cached_lookup(Some(&cache), "ThreatFox", &indicator, run)
            .await
            .expect("second lookup");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(calls.get(), 1, "source closure should run only once");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cached_lookup_with_no_cache_always_calls_source() {
        let indicator = sample_indicator();
        let calls = std::cell::Cell::new(0);
        let run = || async {
            calls.set(calls.get() + 1);
            Ok(sample_findings())
        };

        cached_lookup(None, "ThreatFox", &indicator, run)
            .await
            .expect("lookup");
        cached_lookup(None, "ThreatFox", &indicator, run)
            .await
            .expect("lookup");

        assert_eq!(calls.get(), 2);
    }
}
