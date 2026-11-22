#!/usr/bin/env bash
# Only an ephemeral GitHub runner; never changes the developer's filesystems.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test -d "${RUNNER_TEMP:?}"
fixture_root=$(mktemp -d "${RUNNER_TEMP}/nymwrap-pt.XXXXXXXX")
mounted=false
cleanup() {
  result=$?
  trap - EXIT
  if "$mounted"; then sudo umount -- "$fixture_root/mount" || exit 1; fi
  rm -f -- "$fixture_root/state.img" "$fixture_root/fscrypt-fixture"
  rmdir -- "$fixture_root/mount" "$fixture_root"
  exit "$result"
}
trap cleanup EXIT
mkdir -- "$fixture_root/mount"
truncate -s 256M -- "$fixture_root/state.img"
mkfs.ext4 -q -O encrypt -- "$fixture_root/state.img"
sudo mount -o loop -- "$fixture_root/state.img" "$fixture_root/mount"
mounted=true
sudo chown "$(id -u):$(id -g)" -- "$fixture_root/mount"
mkdir -m 700 -- "$fixture_root/mount/private"
cc -O2 -Wall -Wextra -Werror scripts/ci/fscrypt-state.c -o "$fixture_root/fscrypt-fixture"
"$fixture_root/fscrypt-fixture" "$fixture_root/mount" "$fixture_root/mount/private"
export NW_TEST_PT_STATE="$fixture_root/mount/private"
export NW_TEST_PT_BINARY="$PWD/daemons/nw-netd/target/debug/transports/lyrebird"
cargo test --manifest-path daemons/nw-netd/Cargo.toml --lib actual_installed_pt --locked -- --ignored
