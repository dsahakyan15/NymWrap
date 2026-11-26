#!/usr/bin/env bash
# A private Tor network and provider, with no route to the public network.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -s)" = Linux
test "$(id -u)" != 0
mode=${NW_TEST_TOR_MODE:-tor}
case "$mode" in tor|obfs4) ;; *) exit 1 ;; esac
umask 077
project_root=$(pwd -P)
fixture_root=$(mktemp -d "${RUNNER_TEMP:?}/nymwrap-tor.XXXXXXXX")
test "$(realpath "$fixture_root")" = "$fixture_root"
runner_uid=$(id -u)
runner_gid=$(id -g)
client_ns="nw-client-${BASHPID}"
relay_ns="nw-relays-${BASHPID}"
client_if="nwc${BASHPID}"
relay_if="nwr${BASHPID}"
client_created=false
relay_created=false
link_created=false
mounted=false
capture_client=
capture_provider=
test_pid=
analysis_root=
output="$project_root/target/pcap"
mkdir -p -- "$output"
cleanup() {
  result=$?
  trap - EXIT
  set +e
  failed=0
  if test -n "$test_pid"; then kill -TERM "$test_pid" 2>/dev/null; wait "$test_pid"; fi
  for namespace in "$client_ns" "$relay_ns"; do
    if { test "$namespace" = "$client_ns" && "$client_created"; } || { test "$namespace" = "$relay_ns" && "$relay_created"; }; then
      # Only PIDs in namespaces this invocation successfully created.
      while read -r process_id; do
        test -n "$process_id" && sudo kill -KILL "$process_id"
      done < <(sudo ip netns pids "$namespace")
      sudo ip netns delete "$namespace" || failed=1
    fi
  done
  for process_id in "$capture_client" "$capture_provider"; do
    if test -n "$process_id"; then sudo kill -INT "$process_id" 2>/dev/null; wait "$process_id"; fi
  done
  if "$link_created" && ip link show "$client_if" >/dev/null 2>&1; then sudo ip link delete "$client_if" || failed=1; fi
  for file in client.pcap provider.pcap; do
    if test -f "$fixture_root/$file" && test ! -L "$fixture_root/$file"; then sudo chown --no-dereference "$runner_uid:$runner_gid" -- "$fixture_root/$file" || failed=1; fi
  done
  for file in test.log worker.log daemon.log build.log provider.log tcpdump-client.log tcpdump-provider.log arti.json client.pcap provider.pcap provider.pdml client.tsv rust-result.json daemon-result.json circuit-receipt.json worker-state.json provider-receipt.json health-after-stop.json provider-ca.pem tls.keys tools.txt cover-week.json bridge-evidence.json; do
    if test -f "$fixture_root/$file"; then cp -- "$fixture_root/$file" "$output/$file" || failed=1; fi
  done
  for log in "$fixture_root/chutney/nodes"/*/notice.log; do
    if test -f "$log"; then tail -n 80 -- "$log" >> "$output/chutney-notices.log"; fi
  done
  if test -n "$analysis_root"; then
    if test ! -L "$analysis_root" && test "$(realpath "$analysis_root")" = "$analysis_root" && [[ "$analysis_root" == /tmp/nymwrap-pcap.* ]]; then
      rm -rf -- "$analysis_root" || failed=1
    else
      failed=1
    fi
  fi
  if "$mounted"; then
    if sudo umount -- "$fixture_root/mount"; then mounted=false; else failed=1; fi
  fi
  if ! "$mounted" && test ! -L "$fixture_root" && test "$(realpath "$fixture_root")" = "$fixture_root" && [[ "$fixture_root" == "${RUNNER_TEMP}/nymwrap-tor."* ]]; then
    rm -rf -- "$fixture_root" || failed=1
  else
    failed=1
  fi
  if test "$result" = 0 && test "$failed" = 0; then
    node --input-type=module -e 'import fs from "node:fs";const path=process.argv[1];const report=JSON.parse(fs.readFileSync(path,"utf8"));report.teardown_complete=true;fs.writeFileSync(path,JSON.stringify(report,null,2)+"\n");' "$output/report.json" || result=1
  else
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT

chutney="$project_root/target/tools/chutney"
test "$(git -C "$chutney" rev-parse HEAD)" = 62b54a55215c94eb14adc22c5acd17b2ada04b76
chutney_python=$(realpath "${NW_CHUTNEY_PYTHON:?}")
"$chutney_python" -c 'import cgitb,sys; assert sys.version_info[:2] == (3,12)'
git -C "$chutney" diff --exit-code
git -C "$chutney" apply --check "$project_root/scripts/ci/chutney-python312.patch"
git -C "$chutney" apply "$project_root/scripts/ci/chutney-python312.patch"
PYTHONPATH="$chutney/lib" "$chutney_python" -c 'import chutney.TorNet'
cargo test --manifest-path daemons/nw-netd/Cargo.toml --lib --no-run --message-format=json --locked > "$fixture_root/build.jsonl" 2> "$fixture_root/build.log"
cargo build --manifest-path daemons/nw-netd/Cargo.toml --bin nw-netd --locked >> "$fixture_root/build.log" 2>&1
cargo build -p nw-core -p nw-api --bins --locked >> "$fixture_root/build.log" 2>&1
cargo test -p nw-core --example core-cover-egress --locked >> "$fixture_root/build.log" 2>&1
cargo build -p nw-core --example core-cover-egress --locked >> "$fixture_root/build.log" 2>&1
test_binary=$(node scripts/pcap-report.mjs --binary "$fixture_root/build.jsonl")
node_binary=$(command -v node)
{ "$chutney_python" --version; sha256sum scripts/ci/chutney-python312.patch; tor --version; tcpdump --version; tshark --version; } > "$fixture_root/tools.txt" 2>&1

mkdir -- "$fixture_root/mount"
truncate -s 256M -- "$fixture_root/state.img"
mkfs.ext4 -q -O encrypt -- "$fixture_root/state.img"
sudo mount -o loop -- "$fixture_root/state.img" "$fixture_root/mount"
mounted=true
sudo chown "$runner_uid:$runner_gid" -- "$fixture_root/mount"
mkdir -m 700 -- "$fixture_root/mount/private"
cc -O2 -Wall -Wextra -Werror scripts/ci/fscrypt-state.c -o "$fixture_root/fscrypt-fixture"
"$fixture_root/fscrypt-fixture" "$fixture_root/mount" "$fixture_root/mount/private"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture_root/ca-key.pem" -out "$fixture_root/provider-ca.pem" -days 1 -subj /CN=NymWrap-Synthetic-PCAP-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$fixture_root/provider-key.pem" -out "$fixture_root/provider.csr" -subj /CN=api.example.test >/dev/null 2>&1
cat > "$fixture_root/provider.ext" <<'CERT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.example.test
CERT
openssl x509 -req -in "$fixture_root/provider.csr" -CA "$fixture_root/provider-ca.pem" -CAkey "$fixture_root/ca-key.pem" -CAcreateserial -out "$fixture_root/provider-cert.pem" -days 1 -extfile "$fixture_root/provider.ext" >/dev/null 2>&1
printf 'nameserver 127.0.0.1\n' > "$fixture_root/resolv.conf"

sudo ip netns add "$client_ns"
client_created=true
sudo ip netns add "$relay_ns"
relay_created=true
sudo ip link add "$client_if" type veth peer name "$relay_if"
link_created=true
sudo ip link set "$client_if" netns "$client_ns"
sudo ip link set "$relay_if" netns "$relay_ns"
# This fixture has only IPv4 addresses. Suppress kernel link-local IPv6
# router solicitations in these owned namespaces, before either veth is up.
ipv4_only() {
  local namespace=$1 interface=$2 scope
  sudo ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 "net.ipv6.conf.$interface.disable_ipv6=1"
  for scope in all default "$interface"; do
    test "$(sudo ip netns exec "$namespace" sysctl -n "net.ipv6.conf.$scope.disable_ipv6")" = 1
  done
}
ipv4_only "$client_ns" "$client_if"
ipv4_only "$relay_ns" "$relay_if"
sudo ip -n "$client_ns" address add 192.0.2.1/30 dev "$client_if"
sudo ip -n "$relay_ns" address add 192.0.2.2/30 dev "$relay_if"
sudo ip -n "$client_ns" link set lo up
sudo ip -n "$relay_ns" link set lo up
sudo ip -n "$client_ns" link set "$client_if" up
sudo ip -n "$relay_ns" link set "$relay_if" up
sudo ip netns exec "$relay_ns" sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
tor_ports='5000-5099, 7000-7099'
if test "$mode" = obfs4; then tor_ports=9905; fi
cat > "$fixture_root/client.nft" <<RULES
table inet nymwrap_ci {
  chain output { type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ip daddr 192.0.2.2 tcp dport { $tor_ports } accept
  }
  chain input { type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }
}
RULES
sudo ip netns exec "$client_ns" nft -f "$fixture_root/client.nft"
test -z "$(sudo ip -n "$client_ns" route show default)"
test -z "$(sudo ip -n "$relay_ns" route show default)"
netns_cookie=$(sudo ip netns exec "$client_ns" readlink /proc/self/ns/net)
relay_env=(env -i PATH="$fixture_root/bin:/usr/bin:/bin" PYTHON="$chutney_python" TZ=UTC LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_TEMP="$RUNNER_TEMP" RUNNER_TRACKING_ID="${RUNNER_TRACKING_ID:-}" CHUTNEY_PATH="$chutney" CHUTNEY_DATA_DIR="$fixture_root/chutney" CHUTNEY_LISTEN_ADDRESS=192.0.2.2 CHUTNEY_DNS_CONF="$fixture_root/resolv.conf" CHUTNEY_START_TIME=180)
relay() { sudo ip netns exec "$relay_ns" setpriv --reuid "$runner_uid" --regid "$runner_gid" --init-groups "${relay_env[@]}" "$@"; }
relay "$node_binary" "$project_root/scripts/ci/tor-provider.mjs" "$fixture_root" > "$fixture_root/provider.log" 2>&1 &
for attempt in $(seq 1 100); do test -f "$fixture_root/provider-ready" && break; sleep 0.1; done
test -f "$fixture_root/provider-ready"
network="$chutney/networks/basic-min"
mkdir -m 700 -- "$fixture_root/bin"
if test "$mode" = obfs4; then
  network="$project_root/scripts/ci/chutney-obfs4"
  pinned_lyrebird="$project_root/daemons/nw-netd/target/debug/transports/lyrebird"
  cp -- "$pinned_lyrebird" "$fixture_root/bin/lyrebird"
  cp -- "$pinned_lyrebird" "$fixture_root/bin/obfs4proxy"
  cmp -- "$pinned_lyrebird" "$fixture_root/bin/lyrebird"
  cmp -- "$pinned_lyrebird" "$fixture_root/bin/obfs4proxy"
  chmod 700 -- "$fixture_root/bin/lyrebird" "$fixture_root/bin/obfs4proxy"
fi
relay "$chutney/chutney" configure "$network"
"$chutney_python" - "$fixture_root" <<'PY'
import json,pathlib,sys,tomllib
root=pathlib.Path(sys.argv[1])
config=tomllib.loads((root/'chutney/nodes/arti.toml').read_text())
config['storage']={'cache_dir':str(root/'mount/private/cache'),'state_dir':str(root/'mount/private/state')}
(root/'arti.json').write_text(json.dumps(config))
PY
if test "$mode" = obfs4; then
  # Preserve Tor's pre-log startup diagnostics for the managed bridge. Chutney
  # otherwise appends --quiet, hiding failures that occur before notice.log.
  relay env CHUTNEY_DEBUG=1 "$chutney/chutney" start "$network"
else
  relay "$chutney/chutney" start "$network"
fi
# Arti can bootstrap from an early consensus containing only the authorities.
# Require Chutney's full network/descriptor readiness, including the sole exit.
relay "$chutney/chutney" wait_for_bootstrap "$network"
# Chutney considers its client bootstrapped after an internal circuit, which can
# precede the first signed consensus that carries an Exit flag. Starting Arti in
# that window makes the production preflight correctly fail closed. Bound the
# fixture-only wait by the existing 180-second Chutney bootstrap budget.
exit_consensus_ready=false
for attempt in $(seq 1 1800); do
  if grep -Eqs '^s .*Exit( |$)' "$fixture_root"/chutney/nodes/*c/cached-microdesc-consensus; then
    exit_consensus_ready=true
    break
  fi
  sleep 0.1
done
test "$exit_consensus_ready" = true
if test "$mode" = obfs4; then
  "$chutney_python" - "$fixture_root" <<'PY'
import json,pathlib,re,sys,time
root=pathlib.Path(sys.argv[1]); bridge=root/'chutney/nodes/005br'
for _ in range(100):
    path=bridge/'pt_state/obfs4_bridgeline.txt'
    if path.is_file() and 'cert=' in path.read_text(): break
    time.sleep(.1)
match=re.search(r'cert=([A-Za-z0-9+/=]+)\s+iat-mode=([012])',path.read_text()); assert match
fingerprint=(bridge/'fingerprint').read_text().split()[-1]; assert re.fullmatch('[A-Fa-f0-9]{40}',fingerprint)
(root/'bridge.json').write_text(json.dumps({'transport':'obfs4','lines':[f'obfs4 192.0.2.2:9905 {fingerprint} cert={match[1]} iat-mode={match[2]}']}))
PY
fi
# Smoke the actual production executable and its real idle netd/API children.
# This is distinct from the private-CA transport worker used for packet evidence.
sudo env -i PATH=/usr/bin:/bin GITHUB_ACTIONS=true RUNNER_TEMP="$RUNNER_TEMP" "$chutney_python" "$project_root/scripts/ci/core-netns.py" "$fixture_root" "$project_root/target/debug/nymwrapd" "/run/netns/$client_ns" "$runner_uid" "$runner_gid" > "$fixture_root/daemon.log" 2>&1
{
  printf '#!/bin/bash\nset -euo pipefail\ntest "$#" = 2 && test "$1" = --socket\n'
  printf 'export GITHUB_ACTIONS=true NW_TEST_SOCKET="$2"\n'
  printf 'export NW_TEST_TOR_FIXTURE=%q NW_TEST_NETNS_COOKIE=%q SSLKEYLOGFILE=%q\n' "$fixture_root" "$netns_cookie" "$fixture_root/tls.keys"
  printf 'exec %q --exact local_tor_tests::netd_process_worker --ignored --test-threads=1 > %q 2>&1\n' "$test_binary" "$fixture_root/worker.log"
} > "$fixture_root/bin/nw-netd"
chmod 700 -- "$fixture_root/bin/nw-netd"
sudo ip netns exec "$client_ns" tcpdump -Z root -i "$client_if" -s 0 -U -w "$fixture_root/client.pcap" > "$fixture_root/tcpdump-client.log" 2>&1 &
capture_client=$!
sudo ip netns exec "$relay_ns" tcpdump -Z root -i lo -s 0 -U -w "$fixture_root/provider.pcap" 'tcp port 443' > "$fixture_root/tcpdump-provider.log" 2>&1 &
capture_provider=$!
sleep 1
timeout --signal=TERM --kill-after=10 1200s sudo env -i PATH=/usr/bin:/bin HOME="$fixture_root" TZ=UTC LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_TRACKING_ID="${RUNNER_TRACKING_ID:-}" "$project_root/target/debug/examples/core-cover-egress" "$fixture_root" "/run/netns/$client_ns" "$runner_uid" "$runner_gid" > "$fixture_root/test.log" 2>&1 &
test_pid=$!
for attempt in $(seq 1 1020); do
  test -f "$fixture_root/ready-to-stop" && break
  if ! ps -p "$test_pid" -o pid= >/dev/null; then wait "$test_pid"; exit 1; fi
  sleep 1
done
test -f "$fixture_root/ready-to-stop"
if test "$mode" = obfs4; then
  sudo env GITHUB_ACTIONS=true RUNNER_TEMP="$RUNNER_TEMP" "$chutney_python" "$project_root/scripts/ci/pt-isolation.py" "$fixture_root" "$runner_uid"
  # The namespace observer must run as root; hand only its sealed evidence back
  # to the unprivileged fixture owner without broadening the 0600 mode.
  bridge_evidence="$fixture_root/bridge-evidence.json"
  test -f "$bridge_evidence" && test ! -L "$bridge_evidence"
  test "$(stat -c '%a' -- "$bridge_evidence")" = 600
  sudo chown --no-dereference "${runner_uid}:${runner_gid}" -- "$bridge_evidence"
  test "$(stat -c '%u:%g:%a' -- "$bridge_evidence")" = "${runner_uid}:${runner_gid}:600"
  relay "$chutney_python" - "$fixture_root" <<'PY'
import json,pathlib,socket,sys
with socket.create_connection(('192.0.2.2',5004),timeout=5): pass
path=pathlib.Path(sys.argv[1])/'bridge-evidence.json'
value=json.loads(path.read_text()); value['tor_relay_alive_after_pt_stop']=True
path.write_text(json.dumps(value))
PY
else
  relay "$chutney/chutney" stop "$network"
fi
relay "$node_binary" "$project_root/scripts/ci/tor-provider.mjs" --health "$fixture_root"
printf stopped > "$fixture_root/transport-stopped"
wait "$test_pid"
test_pid=
test -f "$fixture_root/rust-result.json"
sudo kill -INT "$capture_client" "$capture_provider"
wait "$capture_client"
wait "$capture_provider"
capture_client=
capture_provider=
sudo chown "$runner_uid:$runner_gid" -- "$fixture_root/client.pcap" "$fixture_root/provider.pcap"
# Ubuntu 26.04's tshark AppArmor profile permits user-tmp, not RUNNER_TEMP
# under /home. Keep the profile enforced and stage only synthetic evidence.
analysis_root=$(mktemp -d /tmp/nymwrap-pcap.XXXXXXXX)
test "$(realpath "$analysis_root")" = "$analysis_root"
for file in provider.pcap client.pcap tls.keys; do
  cp -- "$fixture_root/$file" "$analysis_root/$file"
  cmp -- "$fixture_root/$file" "$analysis_root/$file"
done
tshark -r "$analysis_root/provider.pcap" -o "tls.keylog_file:$analysis_root/tls.keys" -Y http.request -T pdml > "$analysis_root/provider.pdml"
tshark -r "$analysis_root/client.pcap" -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.dstport -e udp.dstport > "$analysis_root/client.tsv"
cp -- "$analysis_root/provider.pdml" "$analysis_root/client.tsv" "$fixture_root/"
node scripts/pcap-report.mjs --fixture "$fixture_root" --out "$output"
