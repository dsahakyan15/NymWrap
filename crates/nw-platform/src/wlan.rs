//! Bounded WLAN XML. Only documented, namespace-bound SSID and MAC settings leave here.
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use std::io;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
const V1: &str = "http://www.microsoft.com/networking/WLAN/profile/v1";
const V3: &str = "http://www.microsoft.com/networking/WLAN/profile/v3";
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Profile {
    pub ssid: String,
    pub randomized: Option<bool>,
}
fn invalid() -> io::Error {
    io::Error::other("invalid_wlan_profile")
}
pub(crate) fn parse(text: &str) -> io::Result<Profile> {
    if text.len() > 65536 {
        return Err(invalid());
    }
    let mut reader = NsReader::from_str(text);
    let mut stack: Vec<(String, u8)> = Vec::new();
    let mut ssid = Zeroizing::new(String::new());
    let mut randomized = None;
    let mut seen_ssid = false;
    let mut seen_random = false;
    let mut root = false;
    for _ in 0..4096 {
        let (namespace, event) = reader.read_resolved_event().map_err(|_| invalid())?;
        let ns = match namespace {
            ResolveResult::Bound(value) if value.as_ref() == V1 => 1,
            ResolveResult::Bound(value) if value.as_ref() == V3 => 3,
            ResolveResult::Unknown(_) => return Err(invalid()),
            _ => 0,
        };
        match event {
            Event::Start(start) => {
                if stack.len() >= 32 {
                    return Err(invalid());
                }
                let local = start.local_name().as_ref().to_owned();
                if stack.is_empty() {
                    if root || local != "WLANProfile" || ns != 1 {
                        return Err(invalid());
                    }
                    root = true;
                }
                stack.push((local, ns));
            }
            Event::End(_) => {
                if stack.pop().is_none() {
                    return Err(invalid());
                }
            }
            Event::Text(value) => {
                if stack.is_empty() && !value.as_ref().trim().is_empty() {
                    return Err(invalid());
                }
                let path = stack
                    .iter()
                    .map(|(name, ns)| (name.as_str(), *ns))
                    .collect::<Vec<_>>();
                if path
                    == [
                        ("WLANProfile", 1),
                        ("SSIDConfig", 1),
                        ("SSID", 1),
                        ("hex", 1),
                    ]
                {
                    if seen_ssid {
                        return Err(invalid());
                    }
                    seen_ssid = true;
                    let hex = value.as_ref().trim();
                    if hex.is_empty()
                        || hex.len() > 64
                        || hex.len() % 2 != 0
                        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(invalid());
                    }
                    let bytes = Zeroizing::new(
                        (0..hex.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| invalid()))
                            .collect::<io::Result<Vec<_>>>()?,
                    );
                    *ssid = std::str::from_utf8(&bytes)
                        .map_err(|_| invalid())?
                        .to_owned();
                } else if path
                    == [
                        ("WLANProfile", 1),
                        ("MacRandomization", 3),
                        ("enableRandomization", 3),
                    ]
                {
                    if seen_random {
                        return Err(invalid());
                    }
                    seen_random = true;
                    randomized = Some(match value.as_ref().trim() {
                        "true" | "1" => true,
                        "false" | "0" => false,
                        _ => return Err(invalid()),
                    });
                }
            }
            Event::DocType(_) | Event::GeneralRef(_) | Event::CData(_) => return Err(invalid()),
            Event::Eof => {
                if !root || !stack.is_empty() || !seen_ssid {
                    return Err(invalid());
                }
                return Ok(Profile {
                    ssid: std::mem::take(&mut *ssid),
                    randomized,
                });
            }
            Event::Empty(empty)
                if stack.is_empty()
                    || matches!(
                        empty.local_name().as_ref(),
                        "SSID" | "hex" | "enableRandomization"
                    ) =>
            {
                return Err(invalid());
            }
            _ => {}
        }
    }
    Err(invalid())
}

#[cfg(test)]
#[path = "../../../tests/leak/src/wlan_profile.rs"]
mod tests;
