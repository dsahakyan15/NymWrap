use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use nw_net::bridges::BridgeConfig;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Manifest {
    artifacts: Vec<Pin>,
}
#[derive(Deserialize)]
struct Pin {
    platform: String,
    binary_sha256: String,
    bytes: u64,
}
pub(super) struct VerifiedBinary {
    pub path: PathBuf,
    _file: File,
}

fn verify(path: &Path, pin: &Pin) -> Result<VerifiedBinary, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "transport_binary_missing")?;
    if !metadata.is_file()
        || metadata.is_symlink()
        || metadata.len() != pin.bytes
        || pin.bytes > 32 * 1024 * 1024
    {
        return Err("transport_binary_untrusted");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("transport_binary_untrusted");
        }
        options.share_mode(1);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "transport_binary_untrusted")?;
    let after = file.metadata().map_err(|_| "transport_binary_untrusted")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.mode() & 0o022 != 0
        {
            return Err("transport_binary_untrusted");
        }
    }
    if !after.is_file() || after.len() != pin.bytes {
        return Err("transport_binary_untrusted");
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 32768];
    let mut size = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "transport_binary_untrusted")?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or("transport_binary_untrusted")?;
        if size > pin.bytes {
            return Err("transport_binary_untrusted");
        }
        hash.update(&buffer[..read]);
    }
    if size != pin.bytes || format!("{:x}", hash.finalize()) != pin.binary_sha256 {
        return Err("transport_binary_untrusted");
    }
    Ok(VerifiedBinary {
        path: path.to_path_buf(),
        _file: file,
    })
}
fn installed() -> Result<VerifiedBinary, &'static str> {
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../scripts/transport-binaries.json"))
            .map_err(|_| "transport_binary_manifest_invalid")?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let pin = manifest
        .artifacts
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or("transport_binary_unsupported_platform")?;
    let binary = std::env::current_exe().map_err(|_| "transport_binary_missing")?;
    let directory = binary
        .parent()
        .ok_or("transport_binary_missing")?
        .join("transports");
    let metadata = std::fs::symlink_metadata(&directory).map_err(|_| "transport_binary_missing")?;
    if !metadata.is_dir() || metadata.is_symlink() {
        return Err("transport_binary_untrusted");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("transport_binary_untrusted");
        }
    }
    verify(
        &directory.join(format!("lyrebird{}", std::env::consts::EXE_SUFFIX)),
        pin,
    )
}
pub(super) fn configure(
    builder: &mut TorClientConfigBuilder,
    settings: &BridgeConfig,
) -> Result<VerifiedBinary, &'static str> {
    settings.validate()?;
    let binary = installed()?;
    configure_builder(builder, settings, &binary.path)?;
    Ok(binary)
}
fn configure_builder(
    builder: &mut TorClientConfigBuilder,
    settings: &BridgeConfig,
    path: &Path,
) -> Result<(), &'static str> {
    settings.validate()?;
    builder
        .bridges()
        .enabled(arti_client::config::BoolOrAuto::Explicit(true));
    for line in &settings.lines {
        let bridge: BridgeConfigBuilder =
            line.parse().map_err(|_| "invalid_bridge_configuration")?;
        builder.bridges().bridges().push(bridge);
    }
    let mut transport = tor_ptmgr::config::TransportConfigBuilder::default();
    transport
        .protocols(vec![
            settings
                .transport
                .name()
                .parse()
                .map_err(|_| "invalid_bridge_configuration")?,
        ])
        .path(CfgPath::new_literal(path))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    Ok(())
}

#[cfg(test)]
pub(super) fn configure_fixture(
    builder: &mut TorClientConfigBuilder,
    settings: &BridgeConfig,
    path: &Path,
) -> Result<VerifiedBinary, &'static str> {
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../scripts/transport-binaries.json")).unwrap();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let pin = manifest
        .artifacts
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or("unsupported_fixture_platform")?;
    let binary = verify(path, pin)?;
    configure_builder(builder, settings, &binary.path)?;
    Ok(binary)
}

#[cfg(test)]
#[path = "../../../tests/leak/src/netd_bridges.rs"]
mod tests;
