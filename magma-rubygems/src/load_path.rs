//! Lockfile → deterministic `$LOAD_PATH` resolution against on-disk gems.
//!
//! The **standardization** piece of the embedded-CRuby gem story. The
//! Gemfile.lock is the single source of truth for the dependency
//! closure; this module turns it into the exact, dependency-ordered,
//! deduplicated `$LOAD_PATH` the embedded evaluator must set — the
//! same closure `bundle exec` would inject, but computed by a typed
//! interpreter instead of shelled out.
//!
//! ## Why this exists
//!
//! The operator's embedded compile path historically prepended gem
//! `lib/` dirs to `$LOAD_PATH` in *arbitrary order*, registered
//! gem-by-gem out of band, with no completeness check. When a gem the
//! lockfile requires was absent (or a transitive `require` resolved to
//! the wrong copy), the failure surfaced deep inside Ruby as
//! `uninitialized constant Pangea::Architectures` — a mysterious
//! `LoadError` mid-compile, far from its cause.
//!
//! [`resolve_load_path`] makes that bug class **structurally
//! impossible**: a gem the lockfile names but no locator can host
//! surfaces as a typed [`LoadPathError::MissingGems`] at *resolve*
//! time, aggregating *every* missing gem (not just the first) so the
//! operator reports the complete gap in one shot.
//!
//! ## What it deliberately does NOT do
//!
//! It does not fetch or build gems — that is [`crate::tree::materialize`]
//! (M4). It resolves against gems **already on disk**: the operator's
//! gem-cache clones plus its baked `RUBYLIB` closure. The [`GemLocator`]
//! trait abstracts over *where* gems live, so the planner is pure +
//! testable with a mock and reusable across every gem source.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::lockfile::{Lockfile, ResolvedGem};

/// Resolves a lockfile gem to its on-disk `lib/` directory.
///
/// Abstracts over *where* gems live (gem-cache clones, baked
/// `RUBYLIB`, a future materialized tree) so [`resolve_load_path`] is
/// pure + testable with a mock and reusable across every gem source.
/// This IS the testability contract per the org's TYPED-SPEC +
/// INTERPRETER triplet rule: the interpreter's side effect
/// (touching the filesystem to find a gem) lives behind a trait the
/// tests mock.
///
/// The whole [`ResolvedGem`] is passed (not just the name) so a
/// locator can discriminate on `version` and `source` kind — a
/// path-sourced gem and a rubygems-sourced gem of the same name live
/// in different on-disk layouts.
pub trait GemLocator {
    /// The `lib/` directory for `gem`, or `None` if this locator does
    /// not host it. Must be deterministic for a given on-disk state.
    fn locate(&self, gem: &ResolvedGem) -> Option<PathBuf>;
}

/// A lockfile gem no locator could host — the typed witness of the
/// `uninitialized constant` bug class, captured at resolve time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingGem {
    pub name: String,
    pub version: String,
    /// Human-readable source tag (`path`/`git`/`rubygems`) for the
    /// operator's error report — which kind of gem went missing
    /// usually points straight at the cause.
    pub source: String,
}

/// Resolution failure. Aggregates **every** missing gem so the
/// operator surfaces the complete gap in one reconcile rather than
/// whack-a-mole one `LoadError` per compile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadPathError {
    #[error(
        "{} lockfile gem(s) absent on disk: {}",
        .0.len(),
        .0.iter().map(|m| format!("{}-{} ({})", m.name, m.version, m.source))
            .collect::<Vec<_>>().join(", ")
    )]
    MissingGems(Vec<MissingGem>),
}

impl From<LoadPathError> for crate::RubygemsError {
    fn from(e: LoadPathError) -> Self {
        crate::RubygemsError::Resolver(e.to_string())
    }
}

/// A resolved, deterministic `$LOAD_PATH` plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadPathPlan {
    /// Dependency-respecting (deps before dependents), deduplicated
    /// list of gem `lib/` dirs — the exact `$LOAD_PATH` to set, in
    /// order. Deterministic for a given (lockfile, on-disk state).
    pub load_path: Vec<PathBuf>,
    /// BLAKE3 over the canonical `[(name, version, lib_path)]`
    /// projection (sorted, order-independent). Two structurally
    /// identical resolutions attest identically — the operator logs
    /// which closure it ran against, and drift is detectable.
    pub attestation: String,
}

/// Resolve a parsed [`Lockfile`] into a deterministic [`LoadPathPlan`]
/// against on-disk gems located via `locator`.
///
/// Gems are emitted in **dependency-respecting order** (a gem appears
/// after the gems it `depends_on`) via a Kahn topological sort with an
/// alphabetical tiebreak among ready nodes, so the order is total +
/// deterministic. A dependency cycle (or a `depends_on` edge into a
/// gem the lockfile doesn't list) cannot deadlock the sort: any gems
/// left unplaced after the topo pass are appended alphabetically.
/// `$LOAD_PATH` completeness — not order — is what Ruby `require`
/// resolution needs, so the fallback is safe; the order is principled
/// where it can be and deterministic always.
///
/// Returns [`LoadPathError::MissingGems`] listing **every** lockfile
/// gem no locator could host. No silent skips — a missing gem is the
/// bug, surfaced typed and complete.
pub fn resolve_load_path(
    lock: &Lockfile,
    locator: &dyn GemLocator,
) -> Result<LoadPathPlan, LoadPathError> {
    plan_from_ordered(&dependency_order(&lock.gems), locator)
}

/// Like [`resolve_load_path`] but resolves **only the transitive
/// closure of `roots`** (gem names) over the lockfile's `depends_on`
/// edges.
///
/// This is the operator's entry point. A workspace `Gemfile.lock`
/// carries dev/test-group gems (rspec, simplecov, …) that a *compile*
/// never loads and the operator image never bundles; resolving the
/// whole lock would return a spurious [`LoadPathError::MissingGems`]
/// for them. Passing the declared required gems (e.g.
/// `["pangea-architectures"]` from the WorkspaceCatalog) as `roots`
/// restricts resolution to exactly what the compile needs — the
/// composer and its transitive provider/runtime deps — so test gems
/// are never visited.
///
/// `roots` absent from the lockfile are skipped (a declared-required
/// gem missing from the lock is a workspace bug the resolver can't
/// speak to). Gems inside the closure that no locator hosts are still
/// a loud [`LoadPathError::MissingGems`].
pub fn resolve_load_path_for_roots(
    lock: &Lockfile,
    locator: &dyn GemLocator,
    roots: &[String],
) -> Result<LoadPathPlan, LoadPathError> {
    let closure = transitive_closure(&lock.gems, roots);
    plan_from_ordered(&dependency_order(&closure), locator)
}

/// Locate every gem in `ordered`, dedup lib dirs (keep first), and
/// attest — aggregating every gem no locator hosts into a single
/// [`LoadPathError::MissingGems`]. Shared by the whole-lock and
/// closure-restricted entry points.
fn plan_from_ordered(
    ordered: &[ResolvedGem],
    locator: &dyn GemLocator,
) -> Result<LoadPathPlan, LoadPathError> {
    let mut load_path: Vec<PathBuf> = Vec::with_capacity(ordered.len());
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut missing: Vec<MissingGem> = Vec::new();
    // (name, version, lib_path) projection for the attestation.
    let mut projection: Vec<(String, String, String)> = Vec::with_capacity(ordered.len());

    for gem in ordered {
        match locator.locate(gem) {
            Some(lib) => {
                projection.push((
                    gem.name.clone(),
                    gem.version.clone(),
                    lib.to_string_lossy().into_owned(),
                ));
                // Dedup shared lib dirs (path-sourced gems sharing a
                // root, double-listed transitive closures): keep first.
                if seen.insert(lib.clone()) {
                    load_path.push(lib);
                }
            }
            None => missing.push(MissingGem {
                name: gem.name.clone(),
                version: gem.version.clone(),
                source: source_tag(gem),
            }),
        }
    }

    if !missing.is_empty() {
        // Stable order for the report (and for `==` in tests).
        missing.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        return Err(LoadPathError::MissingGems(missing));
    }

    Ok(LoadPathPlan {
        attestation: attest_projection(&projection),
        load_path,
    })
}

/// The subset of `gems` reachable from `roots` by following
/// `depends_on` edges (roots included). Order of the returned Vec is
/// unspecified — [`dependency_order`] re-sorts it. Edges into gems not
/// present in `gems` (default/stdlib gems) are simply not followed.
fn transitive_closure(gems: &[ResolvedGem], roots: &[String]) -> Vec<ResolvedGem> {
    let by_name: BTreeMap<&str, &ResolvedGem> = gems.iter().map(|g| (g.name.as_str(), g)).collect();
    let mut keep: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = roots
        .iter()
        .map(String::as_str)
        .filter(|r| by_name.contains_key(r))
        .collect();
    while let Some(name) = stack.pop() {
        if !keep.insert(name) {
            continue;
        }
        for dep in &by_name[name].depends_on {
            if by_name.contains_key(dep.as_str()) && !keep.contains(dep.as_str()) {
                stack.push(dep.as_str());
            }
        }
    }
    keep.iter().map(|n| by_name[n].clone()).collect()
}

/// Order gems deps-before-dependents (Kahn topo sort, alphabetical
/// tiebreak); unplaceable remainder (cycles / dangling edges) appended
/// alphabetically. Pure + total + deterministic.
fn dependency_order(gems: &[ResolvedGem]) -> Vec<ResolvedGem> {
    // Index by name; the lockfile can in principle list a name twice
    // (different platforms) — last wins for ordering purposes, which
    // is deterministic given a fixed lockfile.
    let by_name: BTreeMap<&str, &ResolvedGem> = gems.iter().map(|g| (g.name.as_str(), g)).collect();

    // Remaining unplaced gem names, alphabetical for determinism.
    let mut remaining: BTreeSet<&str> = by_name.keys().copied().collect();
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    let mut order: Vec<ResolvedGem> = Vec::with_capacity(by_name.len());

    // A gem is ready when every in-lockfile dep is already placed.
    // Deps referencing gems absent from the lockfile (stdlib, default
    // gems) never block — they can't be ordered against.
    loop {
        let ready: Vec<&str> = remaining
            .iter()
            .copied()
            .filter(|name| {
                by_name[*name]
                    .depends_on
                    .iter()
                    .all(|dep| !by_name.contains_key(dep.as_str()) || placed.contains(dep.as_str()))
            })
            .collect();

        if ready.is_empty() {
            break;
        }
        // `remaining` is a BTreeSet so `ready` is already alphabetical
        // → fully deterministic tiebreak among same-readiness gems.
        for name in ready {
            order.push(by_name[name].clone());
            placed.insert(name);
            remaining.remove(name);
        }
    }

    // Cycle / dangling-edge remainder: append alphabetically. Safe
    // because $LOAD_PATH completeness, not order, drives `require`.
    for name in &remaining {
        order.push(by_name[name].clone());
    }
    order
}

/// `path` / `git` / `rubygems` tag for a gem's source, for error
/// reports. Best-effort string view of the typed [`crate::source::Source`].
fn source_tag(gem: &ResolvedGem) -> String {
    match serde_json::to_value(&gem.source) {
        Ok(serde_json::Value::Object(map)) => map
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        Ok(serde_json::Value::String(s)) => s,
        _ => "unknown".to_string(),
    }
}

/// BLAKE3 over the sorted `[(name, version, lib_path)]` projection.
/// Order-independent (mirrors [`crate::attestation::attest_lockfile`]).
fn attest_projection(projection: &[(String, String, String)]) -> String {
    let mut sorted: Vec<&(String, String, String)> = projection.iter().collect();
    sorted.sort();
    let canonical = serde_json::json!({ "load_path_closure": sorted });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Concrete [`GemLocator`] over a list of root directories whose
/// children are gem trees — the operator's gem-cache shape
/// (`<cache>/<name>-<ref>/lib`) and any directory of unpacked gems.
///
/// For a gem named `n`, matches a child dir named exactly `n` or
/// prefixed `n-` (e.g. `pangea-architectures-main`,
/// `terraform-synthesizer-0.4.2`) whose `lib/` is a directory, and
/// returns that `lib/`. Filesystem I/O is confined here; the planner
/// stays pure.
pub struct GemRootsLocator {
    roots: Vec<PathBuf>,
}

impl GemRootsLocator {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            roots: roots.into_iter().collect(),
        }
    }

    fn match_in_root(root: &Path, name: &str) -> Option<PathBuf> {
        let entries = std::fs::read_dir(root).ok()?;
        // Collect + sort candidates so the choice is deterministic when
        // multiple dirs match the prefix (e.g. two cached refs).
        let mut candidates: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|fname| fname == name || fname.starts_with(&format!("{name}-")))
            })
            .collect();
        candidates.sort();
        candidates
            .into_iter()
            .map(|p| p.join("lib"))
            .find(|lib| lib.is_dir())
    }
}

impl GemLocator for GemRootsLocator {
    fn locate(&self, gem: &ResolvedGem) -> Option<PathBuf> {
        self.roots
            .iter()
            .find_map(|root| Self::match_in_root(root, &gem.name))
    }
}

/// Concrete [`GemLocator`] backed by an explicit `gem-name -> lib-dir`
/// map.
///
/// This is the locator for a **pre-resolved, flat closure** whose lib
/// dirs cannot be reverse-mapped to gem names by path inspection — the
/// canonical case being a Nix-built `RUBYLIB`, where a path-gem's lib
/// lives at `/nix/store/<hash>-<derivation>/lib` (the dir basename is a
/// store hash, not the gem name) and bundler gems at
/// `<env>/gems/<name>-<ver>/lib`. The builder that produced the closure
/// (e.g. the operator's flake, which keys its inputs by gem name)
/// already knows the mapping; it emits this map rather than forcing the
/// resolver to guess from paths.
#[derive(Debug, Clone, Default)]
pub struct ManifestLocator {
    map: BTreeMap<String, PathBuf>,
}

impl ManifestLocator {
    pub fn new(map: impl IntoIterator<Item = (String, PathBuf)>) -> Self {
        Self {
            map: map.into_iter().collect(),
        }
    }

    /// Parse a JSON object `{ "gem-name": "/abs/lib/dir", … }` — the
    /// shape a build step (the operator's flake) emits next to the
    /// image. Errors are surfaced as `LockfileParse` for one error
    /// surface across the crate.
    pub fn from_json(s: &str) -> crate::Result<Self> {
        let raw: BTreeMap<String, String> = serde_json::from_str(s)
            .map_err(|e| crate::RubygemsError::LockfileParse(format!("gem manifest: {e}")))?;
        Ok(Self {
            map: raw
                .into_iter()
                .map(|(k, v)| (k, PathBuf::from(v)))
                .collect(),
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl GemLocator for ManifestLocator {
    fn locate(&self, gem: &ResolvedGem) -> Option<PathBuf> {
        self.map.get(&gem.name).cloned()
    }
}

/// A [`GemLocator`] that consults an ordered list of inner locators,
/// returning the first hit. The composition the operator uses: a
/// [`ManifestLocator`] over the baked closure (highest priority) then a
/// [`GemRootsLocator`] over the per-CR gem-cache (the ArchitectureGem
/// clones in the `<name>-<ref>/lib` shape). Order is significant — the
/// first locator to host a gem wins, so place the most-specific /
/// most-trusted source first.
pub struct CompositeLocator {
    inner: Vec<Box<dyn GemLocator + Send + Sync>>,
}

impl CompositeLocator {
    pub fn new(inner: Vec<Box<dyn GemLocator + Send + Sync>>) -> Self {
        Self { inner }
    }

    /// Push a locator onto the end (lowest priority of those so far).
    pub fn push(mut self, loc: Box<dyn GemLocator + Send + Sync>) -> Self {
        self.inner.push(loc);
        self
    }
}

impl GemLocator for CompositeLocator {
    fn locate(&self, gem: &ResolvedGem) -> Option<PathBuf> {
        self.inner.iter().find_map(|l| l.locate(gem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Source;
    use std::collections::HashMap;

    fn gem(name: &str, deps: &[&str]) -> ResolvedGem {
        ResolvedGem {
            name: name.into(),
            version: "0.1.0".into(),
            source: Source::default_rubygems(),
            depends_on: deps.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// In-memory locator: a name→lib map. The mock that proves the
    /// planner needs no filesystem.
    struct MapLocator(HashMap<String, PathBuf>);
    impl MapLocator {
        fn hosting(names: &[(&str, &str)]) -> Self {
            Self(
                names
                    .iter()
                    .map(|(n, p)| ((*n).to_string(), PathBuf::from(*p)))
                    .collect(),
            )
        }
    }
    impl GemLocator for MapLocator {
        fn locate(&self, g: &ResolvedGem) -> Option<PathBuf> {
            self.0.get(&g.name).cloned()
        }
    }

    fn lock_of(gems: Vec<ResolvedGem>) -> Lockfile {
        Lockfile {
            gems,
            ..Lockfile::default()
        }
    }

    #[test]
    fn resolves_in_dependency_order_deps_before_dependents() {
        // c depends on b depends on a.
        let lock = lock_of(vec![gem("c", &["b"]), gem("a", &[]), gem("b", &["a"])]);
        let loc = MapLocator::hosting(&[("a", "/g/a/lib"), ("b", "/g/b/lib"), ("c", "/g/c/lib")]);
        let plan = resolve_load_path(&lock, &loc).expect("all gems hosted");
        let names: Vec<_> = plan
            .load_path
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/g/a/lib", "/g/b/lib", "/g/c/lib"]);
    }

    #[test]
    fn alphabetical_tiebreak_among_independent_gems() {
        let lock = lock_of(vec![gem("zebra", &[]), gem("alpha", &[]), gem("mid", &[])]);
        let loc = MapLocator::hosting(&[
            ("zebra", "/g/zebra/lib"),
            ("alpha", "/g/alpha/lib"),
            ("mid", "/g/mid/lib"),
        ]);
        let plan = resolve_load_path(&lock, &loc).unwrap();
        let names: Vec<_> = plan
            .load_path
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/g/alpha/lib", "/g/mid/lib", "/g/zebra/lib"]);
    }

    /// THE bug-class test: a lockfile gem absent on disk is a typed
    /// resolve-time error, not a silent skip that later explodes as
    /// `uninitialized constant` inside Ruby.
    #[test]
    fn missing_gem_is_a_loud_typed_error() {
        let lock = lock_of(vec![gem("pangea-core", &[]), gem("pangea-gcp", &[])]);
        let loc = MapLocator::hosting(&[("pangea-core", "/g/core/lib")]); // gcp absent
        let err = resolve_load_path(&lock, &loc).unwrap_err();
        match err {
            LoadPathError::MissingGems(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].name, "pangea-gcp");
            }
        }
    }

    /// Every missing gem is aggregated, not just the first.
    #[test]
    fn aggregates_all_missing_gems() {
        let lock = lock_of(vec![gem("a", &[]), gem("b", &[]), gem("c", &[])]);
        let loc = MapLocator::hosting(&[("b", "/g/b/lib")]); // a + c absent
        let err = resolve_load_path(&lock, &loc).unwrap_err();
        let LoadPathError::MissingGems(m) = err;
        let names: Vec<_> = m.iter().map(|x| x.name.clone()).collect();
        assert_eq!(names, vec!["a", "c"], "both missing gems reported, sorted");
    }

    #[test]
    fn deterministic_across_runs() {
        let lock = lock_of(vec![gem("b", &["a"]), gem("a", &[])]);
        let loc = MapLocator::hosting(&[("a", "/g/a/lib"), ("b", "/g/b/lib")]);
        let p1 = resolve_load_path(&lock, &loc).unwrap();
        let p2 = resolve_load_path(&lock, &loc).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1.attestation.len(), 64);
    }

    #[test]
    fn dedups_shared_lib_paths() {
        // Two path-sourced gems resolving to the same shared lib root.
        let lock = lock_of(vec![gem("a", &[]), gem("b", &[])]);
        let loc = MapLocator::hosting(&[("a", "/shared/lib"), ("b", "/shared/lib")]);
        let plan = resolve_load_path(&lock, &loc).unwrap();
        assert_eq!(
            plan.load_path,
            vec![PathBuf::from("/shared/lib")],
            "shared lib listed once"
        );
    }

    #[test]
    fn cycle_falls_back_to_alphabetical_without_panic() {
        // a ↔ b mutual dependency. Must not deadlock; must be total.
        let lock = lock_of(vec![gem("b", &["a"]), gem("a", &["b"])]);
        let loc = MapLocator::hosting(&[("a", "/g/a/lib"), ("b", "/g/b/lib")]);
        let plan = resolve_load_path(&lock, &loc).unwrap();
        let names: Vec<_> = plan
            .load_path
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["/g/a/lib", "/g/b/lib"],
            "cycle → alphabetical, no panic"
        );
    }

    #[test]
    fn dangling_dependency_edge_does_not_block() {
        // `a` depends on `stdlib` which is NOT in the lockfile (default
        // gem). Must not stall the sort.
        let lock = lock_of(vec![gem("a", &["stdlib"])]);
        let loc = MapLocator::hosting(&[("a", "/g/a/lib")]);
        let plan = resolve_load_path(&lock, &loc).unwrap();
        assert_eq!(plan.load_path, vec![PathBuf::from("/g/a/lib")]);
    }

    #[test]
    fn attestation_changes_with_lib_path() {
        let lock = lock_of(vec![gem("a", &[])]);
        let p1 = resolve_load_path(&lock, &MapLocator::hosting(&[("a", "/g/a1/lib")])).unwrap();
        let p2 = resolve_load_path(&lock, &MapLocator::hosting(&[("a", "/g/a2/lib")])).unwrap();
        assert_ne!(
            p1.attestation, p2.attestation,
            "different lib path → different attestation"
        );
    }

    // ── GemRootsLocator (filesystem) ──
    use tempfile::TempDir;

    fn touch_gem_tree(root: &Path, dir_name: &str) {
        let lib = root.join(dir_name).join("lib");
        std::fs::create_dir_all(&lib).unwrap();
    }

    #[test]
    fn gem_roots_locator_matches_exact_and_prefixed_dirs() {
        let td = TempDir::new().unwrap();
        let root = td.path();
        touch_gem_tree(root, "pangea-architectures-main"); // prefixed (cache shape)
        touch_gem_tree(root, "pangea-core"); // exact

        let loc = GemRootsLocator::new([root.to_path_buf()]);
        assert_eq!(
            loc.locate(&gem("pangea-core", &[])),
            Some(root.join("pangea-core").join("lib"))
        );
        assert_eq!(
            loc.locate(&gem("pangea-architectures", &[])),
            Some(root.join("pangea-architectures-main").join("lib"))
        );
        assert_eq!(loc.locate(&gem("absent-gem", &[])), None);
    }

    #[test]
    fn gem_roots_locator_end_to_end_with_resolver() {
        let td = TempDir::new().unwrap();
        let root = td.path();
        touch_gem_tree(root, "pangea-core");
        touch_gem_tree(root, "pangea-gcp");
        touch_gem_tree(root, "pangea-architectures-main");

        // architectures depends on core + gcp.
        let lock = lock_of(vec![
            gem("pangea-architectures", &["pangea-core", "pangea-gcp"]),
            gem("pangea-core", &[]),
            gem("pangea-gcp", &["pangea-core"]),
        ]);
        let loc = GemRootsLocator::new([root.to_path_buf()]);
        let plan = resolve_load_path(&lock, &loc).expect("all three hosted");
        assert_eq!(plan.load_path.len(), 3);
        // core before gcp before architectures (deps-first).
        let arch = root.join("pangea-architectures-main").join("lib");
        let core = root.join("pangea-core").join("lib");
        let gcp = root.join("pangea-gcp").join("lib");
        assert_eq!(plan.load_path, vec![core, gcp, arch]);
    }

    // ── ManifestLocator (the flat-closure / baked-RUBYLIB case) ──

    #[test]
    fn manifest_locator_maps_names_to_lib_dirs() {
        // Mirrors the Nix RUBYLIB shape: store-hash dir basenames that a
        // path-scan could never reverse-map to a gem name.
        let loc = ManifestLocator::new([
            (
                "pangea-core".into(),
                PathBuf::from("/nix/store/abc123-pangea-core-src/lib"),
            ),
            (
                "dry-struct".into(),
                PathBuf::from("/nix/store/def-env/gems/dry-struct-1.6.0/lib"),
            ),
        ]);
        assert_eq!(
            loc.locate(&gem("pangea-core", &[])),
            Some(PathBuf::from("/nix/store/abc123-pangea-core-src/lib"))
        );
        assert_eq!(loc.locate(&gem("absent", &[])), None);
    }

    #[test]
    fn manifest_locator_from_json_roundtrips() {
        let json = r#"{"pangea-core":"/g/core/lib","pangea-gcp":"/g/gcp/lib"}"#;
        let loc = ManifestLocator::from_json(json).expect("valid manifest json");
        assert_eq!(loc.len(), 2);
        assert_eq!(
            loc.locate(&gem("pangea-gcp", &[])),
            Some(PathBuf::from("/g/gcp/lib"))
        );
    }

    #[test]
    fn manifest_locator_from_json_rejects_garbage() {
        assert!(ManifestLocator::from_json("not json").is_err());
    }

    // ── CompositeLocator (manifest over baked closure + gem cache) ──

    #[test]
    fn composite_locator_first_hit_wins() {
        // Baked manifest hosts pangea-core; gem cache hosts the
        // architectures composer the image doesn't bake.
        let manifest = ManifestLocator::new([(
            "pangea-core".into(),
            PathBuf::from("/baked/pangea-core/lib"),
        )]);

        let td = TempDir::new().unwrap();
        let cache = td.path();
        touch_gem_tree(cache, "pangea-architectures-main");
        let roots = GemRootsLocator::new([cache.to_path_buf()]);

        let composite = CompositeLocator::new(vec![Box::new(manifest), Box::new(roots)]);

        // pangea-core resolves from the baked manifest…
        assert_eq!(
            composite.locate(&gem("pangea-core", &[])),
            Some(PathBuf::from("/baked/pangea-core/lib"))
        );
        // …pangea-architectures from the gem cache (prefix match).
        assert_eq!(
            composite.locate(&gem("pangea-architectures", &[])),
            Some(cache.join("pangea-architectures-main").join("lib"))
        );
        assert_eq!(composite.locate(&gem("nowhere", &[])), None);
    }

    #[test]
    fn composite_priority_is_order_sensitive() {
        let a = ManifestLocator::new([("g".into(), PathBuf::from("/from/a"))]);
        let b = ManifestLocator::new([("g".into(), PathBuf::from("/from/b"))]);
        let ab = CompositeLocator::new(vec![Box::new(a.clone()), Box::new(b.clone())]);
        let ba = CompositeLocator::new(vec![Box::new(b), Box::new(a)]);
        assert_eq!(ab.locate(&gem("g", &[])), Some(PathBuf::from("/from/a")));
        assert_eq!(ba.locate(&gem("g", &[])), Some(PathBuf::from("/from/b")));
    }

    /// End-to-end: the operator-shaped composition resolves the real
    /// pleme-io-opensource gem set (path-gems from the baked manifest,
    /// the composer from the gem cache) into a complete ordered closure.
    #[test]
    fn composite_resolves_pleme_io_opensource_shape() {
        let td = TempDir::new().unwrap();
        let cache = td.path();
        touch_gem_tree(cache, "pangea-architectures-main");

        // Baked manifest = every PATH-sourced pangea-* gem + rubygems deps,
        // as the operator flake would emit (name -> store lib dir).
        let baked = ManifestLocator::new(
            [
                "pangea-core",
                "pangea-gcp",
                "pangea-aws",
                "pangea-azure",
                "pangea-cloudflare",
                "pangea-datadog",
                "pangea-akeyless",
                "dry-struct",
                "dry-types",
                "terraform-synthesizer",
                "base64",
            ]
            .into_iter()
            .map(|n| (n.to_string(), PathBuf::from(format!("/baked/{n}/lib")))),
        );
        let loc = CompositeLocator::new(vec![
            Box::new(baked),
            Box::new(GemRootsLocator::new([cache.to_path_buf()])),
        ]);

        // architectures depends on the providers, providers depend on core.
        let lock = lock_of(vec![
            gem(
                "pangea-architectures",
                &["pangea-core", "pangea-gcp", "pangea-aws"],
            ),
            gem("pangea-core", &["dry-struct", "terraform-synthesizer"]),
            gem("pangea-gcp", &["pangea-core"]),
            gem("pangea-aws", &["pangea-core"]),
            gem("dry-struct", &["dry-types"]),
            gem("dry-types", &[]),
            gem("terraform-synthesizer", &[]),
        ]);
        let plan = resolve_load_path(&lock, &loc).expect("complete closure");
        assert_eq!(plan.load_path.len(), 7, "all 7 gems located");
        // architectures (the composer) resolves to the gem-cache clone.
        assert!(
            plan.load_path
                .contains(&cache.join("pangea-architectures-main").join("lib"))
        );
        // dependency order: core's deps precede core precede the providers
        // precede architectures.
        let pos = |needle: &str| {
            plan.load_path
                .iter()
                .position(|p| p.to_string_lossy().contains(needle))
                .unwrap()
        };
        assert!(pos("dry-types") < pos("dry-struct"));
        assert!(pos("pangea-core") < pos("pangea-gcp"));
        assert!(pos("pangea-gcp") < pos("architectures"));
    }

    // ── transitive-closure-from-roots (test-gem exclusion) ──

    /// THE operator-shaped test: a workspace lock with test-group gems
    /// (rspec/simplecov) the operator does NOT bundle. Whole-lock
    /// resolution would fail MissingGems on them; root-restricted
    /// resolution to ["pangea-architectures"] visits only the compile
    /// closure, so the test gems are neither required nor missing.
    #[test]
    fn roots_closure_excludes_unbundled_test_gems() {
        let lock = lock_of(vec![
            gem("pangea-architectures", &["pangea-core"]),
            gem("pangea-core", &["dry-struct"]),
            gem("dry-struct", &[]),
            // dev/test group — NOT reachable from pangea-architectures:
            gem("rspec", &["rspec-core"]),
            gem("rspec-core", &[]),
            gem("simplecov", &["docile"]),
            gem("docile", &[]),
        ]);
        // Locator hosts ONLY the runtime closure (mirrors the operator,
        // which doesn't bundle rspec/simplecov).
        let loc = MapLocator::hosting(&[
            ("pangea-architectures", "/g/arch/lib"),
            ("pangea-core", "/g/core/lib"),
            ("dry-struct", "/g/dry/lib"),
        ]);

        // Whole-lock resolution FAILS on the unbundled test gems.
        let whole = resolve_load_path(&lock, &loc);
        assert!(
            matches!(whole, Err(LoadPathError::MissingGems(_))),
            "whole-lock hits test gems"
        );

        // Root-restricted resolution succeeds — test gems never visited.
        let roots = vec!["pangea-architectures".to_string()];
        let plan = resolve_load_path_for_roots(&lock, &loc, &roots).expect("closure resolves");
        let names: Vec<_> = plan
            .load_path
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["/g/dry/lib", "/g/core/lib", "/g/arch/lib"],
            "closure, dep-ordered"
        );
    }

    #[test]
    fn roots_absent_from_lockfile_are_skipped() {
        let lock = lock_of(vec![gem("present", &[])]);
        let loc = MapLocator::hosting(&[("present", "/g/p/lib")]);
        // "ghost" isn't in the lock → skipped, not an error; "present"
        // also isn't reachable from "ghost", so the closure is empty.
        let plan =
            resolve_load_path_for_roots(&lock, &loc, &["ghost".into()]).expect("empty closure ok");
        assert!(plan.load_path.is_empty());
    }

    #[test]
    fn roots_closure_still_loud_on_missing_runtime_gem() {
        // A gem INSIDE the closure that no locator hosts is still loud.
        let lock = lock_of(vec![
            gem("pangea-architectures", &["pangea-core"]),
            gem("pangea-core", &[]),
        ]);
        let loc = MapLocator::hosting(&[("pangea-architectures", "/g/arch/lib")]); // core absent
        let err =
            resolve_load_path_for_roots(&lock, &loc, &["pangea-architectures".into()]).unwrap_err();
        let LoadPathError::MissingGems(m) = err;
        assert_eq!(
            m.iter().map(|x| x.name.clone()).collect::<Vec<_>>(),
            vec!["pangea-core"]
        );
    }
}
