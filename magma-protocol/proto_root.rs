use std::path::{Path, PathBuf};

pub const PROTOS: [&str; 2] = ["tfplugin5.proto", "tfplugin6.proto"];

pub fn proto_root(manifest_dir: &Path, member: &str) -> Result<PathBuf, String> {
    let candidates = [
        manifest_dir.join("proto"),
        manifest_dir.join(member).join("proto"),
    ];
    candidates
        .iter()
        .find(|dir| PROTOS.iter().all(|proto| dir.join(proto).is_file()))
        .cloned()
        .ok_or_else(|| {
            format!(
                "{} not all present in {} or {}",
                PROTOS.join(" + "),
                candidates[0].display(),
                candidates[1].display()
            )
        })
}
