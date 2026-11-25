"""Actual production daemon startup; synthetic workspace, inherited bootstrap only."""
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import subprocess
import sys
import time


def status(pid):
    return dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())


def main():
    assert sys.platform == "linux" and os.geteuid() == 0
    assert os.environ["GITHUB_ACTIONS"] == "true"
    fixture, binary, namespace, user, group = sys.argv[1:]
    fixture, binary, namespace = Path(fixture).resolve(), Path(binary).resolve(), Path(namespace).resolve()
    assert fixture.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve())
    uid, gid = int(user), int(group)
    assert uid > 0 and gid > 0
    # Reject invalid descriptors, the host netns, and root target identities.
    env = dict(PATH="/usr/bin:/bin", HOME=str(fixture), XDG_DATA_HOME=str(fixture / "data"),
               XDG_RUNTIME_DIR=str(fixture / "daemon-runtime"), TZ="UTC", LANG="C.UTF-8")
    for ns, target in [("/etc/hosts", user), ("/proc/self/ns/net", user), (str(namespace), "0")]:
        failed = subprocess.run([str(binary), "--bootstrap-stdin", "--netns", ns, "--uid", target, "--gid", group],
                                stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=10)
        assert failed.returncode != 0
    process = subprocess.Popen([str(binary), "--bootstrap-stdin", "--netns", str(namespace),
                                "--uid", user, "--gid", group],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    children = []
    child_handles = []
    try:
        # Same 45-byte private bootstrap as the desktop. No RPC keys on disk,
        # no vault/keyring, no remote initialization or user data.
        process.stdin.write(b"NWRPC\x00\x01\x00" + b"\x00" + struct.pack("<I", os.getpid()) + os.urandom(32))
        process.stdin.flush()
        api = fixture / "daemon-runtime/nymwrap/api.sock"
        deadline = time.monotonic() + 20
        while not api.exists():
            assert process.poll() is None, "production_core_start_failed"
            assert time.monotonic() < deadline, "production_core_start_timeout"
            time.sleep(0.05)
        assert stat.S_ISSOCK(api.stat().st_mode)
        core_ns = os.readlink(f"/proc/{process.pid}/ns/net")
        host_ns = os.readlink("/proc/self/ns/net")
        transport_ns = subprocess.check_output(["nsenter", f"--net={namespace}", "readlink", "/proc/self/ns/net"], text=True).strip()
        assert len({core_ns, host_ns, transport_ns}) == 3
        # Every core runtime thread has the empty namespace, dropped identity,
        # NNP and the seccomp filter. No privileged runtime thread survives.
        threads = list(Path(f"/proc/{process.pid}/task").iterdir())
        assert len(threads) > 1
        for thread in threads:
            assert os.readlink(thread / "ns/net") == core_ns
            details = dict(line.split(":", 1) for line in (thread / "status").read_text().splitlines())
            assert details["Uid"].split() == [user] * 4
            assert details["Gid"].split() == [group] * 4
            assert not details["Groups"].strip()
            assert details["NoNewPrivs"].strip() == "1"
            assert details["Seccomp"].strip() == "2"
        children = list({int(pid) for thread in threads for pid in (thread / "children").read_text().split()})
        child_handles = [os.pidfd_open(pid) for pid in children]
        images = {Path(os.readlink(f"/proc/{pid}/exe")).name: pid for pid in children}
        assert "nw-netd" in images and "nw-api" in images
        for name, pid in images.items():
            details = status(pid)
            assert details["Uid"].split() == [user] * 4
            assert details["Gid"].split() == [group] * 4
            assert not details["Groups"].strip()
            assert details["NoNewPrivs"].strip() == "1"
            assert os.readlink(f"/proc/{pid}/ns/net") == (transport_ns if name == "nw-netd" else core_ns)
        # Enter the actual core netns from outside, without its seccomp filter:
        # IPv4/IPv6 TCP and UDP cannot reach even our otherwise live relay.
        probe = """
import errno,socket
for family,address in [(socket.AF_INET,('192.0.2.2',5000)),(socket.AF_INET6,('2001:db8::2',5000))]:
 for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
  with socket.socket(family,kind) as sock:
   sock.settimeout(1)
   try: sock.connect(address)
   except OSError as error: assert error.errno == errno.ENETUNREACH, error.errno
   else: raise AssertionError('core_netns_reached_external_address')
"""
        subprocess.run(["nsenter", f"--net=/proc/{process.pid}/ns/net", sys.executable, "-c", probe], check=True, timeout=10)
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        # Core awaits its API. Netd is its retained kill-on-drop child; a short
        # zombie awaiting init's reaper is dead and has no namespace or sockets.
        deadline = time.monotonic() + 5
        while any(not select.select([handle], [], [], 0)[0] for handle in child_handles):
            assert time.monotonic() < deadline, "retained_child_survived_core"
            time.sleep(0.05)
        result = dict(complete=True, actual_production_daemon=True, separate_namespaces=True,
                      core_namespace_unreachable=True, all_threads_dropped=True, api_inherits_core_namespace=True,
                      netd_in_transport_namespace=True, parent_eof_stops_children=True, invalid_setup_rejected=True)
        report = fixture / "daemon-result.json"
        report.write_text(json.dumps(result) + "\n")
        report.chmod(0o600)
        os.chown(report, uid, gid)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        sys.stderr.buffer.write(process.stderr.read(4096))
        for handle in child_handles:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(handle)


if __name__ == "__main__":
    main()
