#!/usr/bin/env bash
# A private Tor network and provider, with no route to the public network.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -s)" = Linux
test "$(id -u)" != 0
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
output="$project_root/target/pcap"
mkdir -p -- "$output"
cleanup() {
  result=$?
  trap - EXIT
  set +e
  failed=0
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
  for file in test.log build.log provider.log tcpdump-client.log tcpdump-provider.log arti.json client.pcap provider.pcap provider.pdml client.tsv rust-result.json provider-receipt.json health-after-stop.json provider-ca.pem tls.keys tools.txt; do
    if test -f "$fixture_root/$file"; then cp -- "$fixture_root/$file" "$output/$file" || failed=1; fi
  done
  for log in "$fixture_root/chutney/nodes"/*/notice.log; do
    if test -f "$log"; then tail -n 80 -- "$log" >> "$output/chutney-notices.log"; fi
  done
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
cargo test --manifest-path daemons/nw-netd/Cargo.toml --lib --no-run --message-format=json --locked > "$fixture_root/build.jsonl" 2> "$fixture_root/build.log"
test_binary=$(node scripts/pcap-report.mjs --binary "$fixture_root/build.jsonl")
node_binary=$(command -v node)
{ tor --version; tcpdump --version; tshark --version; } > "$fixture_root/tools.txt" 2>&1

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
sudo ip -n "$client_ns" address add 192.0.2.1/30 dev "$client_if"
sudo ip -n "$relay_ns" address add 192.0.2.2/30 dev "$relay_if"
sudo ip -n "$client_ns" link set lo up
sudo ip -n "$relay_ns" link set lo up
sudo ip -n "$client_ns" link set "$client_if" up
sudo ip -n "$relay_ns" link set "$relay_if" up
sudo ip netns exec "$relay_ns" sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
cat > "$fixture_root/client.nft" <<'RULES'
table inet nymwrap_ci {
  chain output { type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ip daddr 192.0.2.2 tcp dport { 5000-5099, 7000-7099 } accept
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
relay_env=(env -i PATH=/usr/bin:/bin TZ=UTC LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_TEMP="$RUNNER_TEMP" RUNNER_TRACKING_ID="${RUNNER_TRACKING_ID:-}" CHUTNEY_PATH="$chutney" CHUTNEY_DATA_DIR="$fixture_root/chutney" CHUTNEY_LISTEN_ADDRESS=192.0.2.2 CHUTNEY_DNS_CONF="$fixture_root/resolv.conf")
relay() { sudo ip netns exec "$relay_ns" setpriv --reuid "$runner_uid" --regid "$runner_gid" --init-groups "${relay_env[@]}" "$@"; }
relay "$node_binary" "$project_root/scripts/ci/tor-provider.mjs" "$fixture_root" > "$fixture_root/provider.log" 2>&1 &
for attempt in $(seq 1 100); do test -f "$fixture_root/provider-ready" && break; sleep 0.1; done
test -f "$fixture_root/provider-ready"
relay "$chutney/chutney" configure "$chutney/networks/basic-min"
python3 - "$fixture_root" <<'PY'
import json,pathlib,sys,tomllib
root=pathlib.Path(sys.argv[1])
config=tomllib.loads((root/'chutney/nodes/arti.toml').read_text())
config['storage']={'cache_dir':str(root/'mount/private/cache'),'state_dir':str(root/'mount/private/state')}
(root/'arti.json').write_text(json.dumps(config))
PY
relay "$chutney/chutney" start "$chutney/networks/basic-min"
sudo ip netns exec "$client_ns" tcpdump -Z root -i "$client_if" -s 0 -U -w "$fixture_root/client.pcap" > "$fixture_root/tcpdump-client.log" 2>&1 &
capture_client=$!
sudo ip netns exec "$relay_ns" tcpdump -Z root -i lo -s 0 -U -w "$fixture_root/provider.pcap" 'tcp port 443' > "$fixture_root/tcpdump-provider.log" 2>&1 &
capture_provider=$!
sleep 1
sudo ip netns exec "$client_ns" setpriv --reuid "$runner_uid" --regid "$runner_gid" --init-groups env -i PATH=/usr/bin:/bin TZ=UTC LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_TRACKING_ID="${RUNNER_TRACKING_ID:-}" NW_TEST_TOR_FIXTURE="$fixture_root" NW_TEST_NETNS_COOKIE="$netns_cookie" SSLKEYLOGFILE="$fixture_root/tls.keys" "$test_binary" --exact local_tor_tests::actual_local_tor_tls_packets_have_no_hard_canaries_or_direct_fallback --ignored --test-threads 1 > "$fixture_root/test.log" 2>&1 &
test_pid=$!
for attempt in $(seq 1 300); do
  test -f "$fixture_root/ready-to-stop" && break
  if ! ps -p "$test_pid" -o pid= >/dev/null; then wait "$test_pid"; exit 1; fi
  sleep 1
done
test -f "$fixture_root/ready-to-stop"
relay "$chutney/chutney" stop "$chutney/networks/basic-min"
relay "$node_binary" "$project_root/scripts/ci/tor-provider.mjs" --health "$fixture_root"
printf stopped > "$fixture_root/transport-stopped"
wait "$test_pid"
test -f "$fixture_root/rust-result.json"
sudo kill -INT "$capture_client" "$capture_provider"
wait "$capture_client"
wait "$capture_provider"
capture_client=
capture_provider=
sudo chown "$runner_uid:$runner_gid" -- "$fixture_root/client.pcap" "$fixture_root/provider.pcap"
tshark -r "$fixture_root/provider.pcap" -o "tls.keylog_file:$fixture_root/tls.keys" -Y http.request -T pdml > "$fixture_root/provider.pdml"
tshark -r "$fixture_root/client.pcap" -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.dstport -e udp.dstport > "$fixture_root/client.tsv"
node scripts/pcap-report.mjs --fixture "$fixture_root" --out "$output"
