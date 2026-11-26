// Synthetic audit probes for ADR 0104. No application state or real home paths are read.
// Run: node supply-chain/desktop/review-tests-2026-11-26-desktop-4.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root = process.cwd();
const output = path.join(root, 'target', 'desktop4', 'probes');
const registry = path.join(process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'), 'registry');
const source = path.join(registry, 'src', 'index.crates.io-1949cf8c6b5b557f');
const cache = path.join(registry, 'cache', 'index.crates.io-1949cf8c6b5b557f');
const prior = JSON.parse(fs.readFileSync(path.join(root, 'supply-chain/desktop/review-2026-11-26-desktop-3.json')));
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
fs.mkdirSync(output, {recursive: true});
const commands = [];
function run(exe, args) {
  const stdout = execFileSync(exe, args, {cwd: root, windowsHide: true, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024});
  const normalize = s => s.replaceAll(root, '$REPOSITORY').replaceAll(registry, '$CARGO_REGISTRY').replaceAll(os.homedir(), '$USERPROFILE');
  commands.push({exe: normalize(exe), args: args.map(normalize), exit_code: 0, stdout: normalize(stdout)});
  process.stdout.write(stdout);
  return stdout;
}
function verified(name, version, files) {
  const id = `${name}-${version}`;
  const archive = path.join(cache, id + '.crate');
  const record = prior.registry_verification.releases.find(r => r.name === name && r.version === version);
  const lockEntry = fs.readFileSync(path.join(root, 'app/src-tauri/Cargo.lock'), 'utf8').split('[[package]]')
    .find(p => p.includes(`name = "${name}"\n`) && p.includes(`version = "${version}"\n`));
  const checksum = lockEntry?.match(/checksum = "([a-f0-9]{64})"/)?.[1];
  if (!checksum || (record && record.archive_sha256 !== checksum) || digest(fs.readFileSync(archive)) !== checksum) throw Error('archive checksum: ' + id);
  for (const file of files) {
    const member = execFileSync('tar', ['-xOf', archive, `${id}/${file}`], {windowsHide: true, maxBuffer: 4 * 1024 * 1024});
    if (!member.equals(fs.readFileSync(path.join(source, id, file)))) throw Error('source differs: ' + id + '/' + file);
  }
  return path.join(source, id);
}
const rustc = execFileSync('rustup', ['which', 'rustc'], {encoding: 'utf8', windowsHide: true}).trim();
const exe = name => path.join(output, name + (process.platform === 'win32' ? '.exe' : ''));
const versionSource = verified('version-compare', '0.2.1', ['src/lib.rs', 'src/cmp.rs', 'src/compare.rs', 'src/manifest.rs', 'src/part.rs', 'src/version.rs', 'src/test.rs']);
run(rustc, ['--edition=2021', '--test', '--crate-name', 'version_compare', path.join(versionSource, 'src/lib.rs'), '-o', exe('version-upstream')]);
run(exe('version-upstream'), []);
const rlib = path.join(output, 'libversion_compare.rlib');
run(rustc, ['--edition=2021', '--crate-type=lib', '--crate-name', 'version_compare', path.join(versionSource, 'src/lib.rs'), '-o', rlib]);
const versionProbe = `
extern crate version_compare;
use version_compare::{Version, Cmp, Manifest};
#[test] fn hostile_versions_and_bounds() {
    for s in ["", " ", "1.2.3", "1.0β", "1.00000000000000000000000000000000a", "1.１２", "9999999999999999999999999", "1.💾.2", "1.0\\0x"] {
        if let Some(v) = Version::from(s) {
            assert_eq!(v.compare(&v), Cmp::Eq);
            assert!(v.part(usize::MAX).is_err());
        }
    }
    for scalar in 0..=0xffff {
        if let Some(c) = char::from_u32(scalar) {
            let s = format!("1.123{c}456.0");
            let _ = Version::from(&s);
        }
    }
    let mut m = Manifest::default();
    m.max_depth = Some(1);
    assert_eq!(Version::from_manifest("1.2.3", &m).unwrap().parts().len(), 1);
    assert_eq!(Version::from("1.0.0").unwrap().compare(Version::from("1").unwrap()), Cmp::Eq);
}
`;
fs.writeFileSync(path.join(output, 'version-probe.rs'), versionProbe);
run(rustc, ['--edition=2021', '--test', path.join(output, 'version-probe.rs'), '--extern', `version_compare=${rlib}`, '-o', exe('version-probe')]);
run(exe('version-probe'), []);
const dirsSource = verified('dirs-sys', '0.5.0', ['src/xdg_user_dirs.rs']);
let parser = fs.readFileSync(path.join(dirsSource, 'src/xdg_user_dirs.rs'), 'utf8');
// Windows cannot import the Unix OsString extension. Only that import is replaced.
// The parser, slicing expressions, and upstream tests remain byte-for-byte unchanged.
// The shim accepts ASCII only; these probes never claim native Unix execution.
const unixImport = 'use std::os::unix::ffi::OsStringExt;';
const asciiShim = `
trait AsciiOsStringExt { fn from_vec(v: Vec<u8>) -> Self; }
impl AsciiOsStringExt for OsString {
    fn from_vec(v: Vec<u8>) -> Self { assert!(v.is_ascii()); String::from_utf8(v).unwrap().into() }
}`;
if (process.platform === 'win32') {
  if (!parser.includes(unixImport)) throw Error('Unix import not found');
  parser = parser.replace(unixImport, asciiShim);
}
parser += `
#[test] fn reproduced_short_xdg_key() {
    assert!(std::panic::catch_unwind(|| parse_user_dirs(Path::new("/synthetic"), None, b"XDG_DIR=\\\"/safe\\\"")).is_err());
}
#[test] fn reproduced_single_quote_value() {
    assert!(std::panic::catch_unwind(|| parse_user_dirs(Path::new("/synthetic"), Some("DOWNLOAD"), b"XDG_DOWNLOAD_DIR=\\\"")).is_err());
}
`;
// The upstream relative-path tests assume Unix PathBuf semantics. Run only our
// two named reproductions on Windows; run the unmodified suite on Unix as well.
fs.writeFileSync(path.join(output, 'dirs-parser.rs'), parser);
const optionSource = verified('option-ext', '0.2.0', ['src/lib.rs', 'src/impl.rs']);
const optionLib = path.join(output, 'liboption_ext.rlib');
run(rustc, ['--edition=2015', '--crate-name', 'option_ext', '--crate-type=lib', path.join(optionSource, 'src/lib.rs'), '-o', optionLib]);
run(rustc, ['--edition=2018', '--test', path.join(output, 'dirs-parser.rs'), '--extern', `option_ext=${optionLib}`, '-o', exe('dirs-parser')]);
run(exe('dirs-parser'), process.platform === 'win32' ? ['reproduced_'] : []);
const macroSource = verified('foreign-types-macros', '0.2.4', ['src/lib.rs', 'src/build.rs', 'src/parse.rs']);
const harness = path.join(output, 'foreign-harness');
fs.mkdirSync(path.join(harness, 'src'), {recursive: true});
const tomlPath = p => JSON.stringify(p.replaceAll('\\', '/'));
fs.writeFileSync(path.join(harness, 'Cargo.toml'), `[package]
name = "desktop4-foreign-probe"
version = "0.0.0"
edition = "2021"
[workspace]
[dependencies]
foreign-types = { version = "=0.5.0", path = ${tomlPath(path.join(source, 'foreign-types-0.5.0'))} }
[patch.crates-io]
foreign-types-macros = { path = ${tomlPath(macroSource)} }
`);
fs.writeFileSync(path.join(harness, 'src/lib.rs'), `
#[cfg(test)] mod tests {
    use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    unsafe fn free(p: *mut u32) { drop(Box::from_raw(p)); DROPS.fetch_add(1, Ordering::SeqCst); }
    unsafe fn duplicate(p: *mut u32) -> *mut u32 { Box::into_raw(Box::new(*p)) }
    foreign_type! {
        pub unsafe type Owned: Send + Sync {
            type CType = u32;
            fn drop = free;
            fn clone = duplicate;
        }
    }
    #[test] fn generated_owner_borrow_clone_and_drop() {
        let mut a = unsafe { Owned::from_ptr(Box::into_raw(Box::new(7))) };
        let b = a.clone();
        assert_ne!(a.as_ptr(), b.as_ptr());
        unsafe { *OwnedRef::as_ptr(&mut *a) = 11; }
        assert_eq!(unsafe { *b.as_ptr() }, 7);
        let c = (&*a).to_owned();
        assert_eq!(unsafe { *c.as_ptr() }, 11);
        drop(a); drop(b); drop(c);
        assert_eq!(DROPS.load(Ordering::SeqCst), 3);
    }
}
`);
// Only this ignored synthetic harness gets a generated lockfile. Tracked locks are untouched.
run('cargo', ['test', '--offline', '--manifest-path', path.join(harness, 'Cargo.toml')]);
fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({
  execution: process.platform + '-' + process.arch,
  dirs_transform: process.platform === 'win32' ? 'Unix OsStringExt import replaced with ASCII-only shim; no parser changes' : 'none',
  limitations: 'No native Unix XDG runtime, cross-platform suite, Miri or timing validation on Windows; no application secrets or real configuration read.',
  commands,
}, null, 2) + '\n');
