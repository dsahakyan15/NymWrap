"""CI-only root observer. Inspect and stop only this fixture's isolated PT."""
import json
import os
import pathlib
import signal
import select
import sys

assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() == 0
root = pathlib.Path(sys.argv[1]).resolve()
assert root.is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve())
worker = json.loads((root/'worker-state.json').read_text())
parent = int(worker['pid'])
uid = int(sys.argv[2])
assert uid != 0
proc = pathlib.Path('/proc')

def children(pid):
    found = set()
    try:
        threads = list((proc/str(pid)/'task').iterdir())
    except FileNotFoundError:
        return found
    for thread in threads:
        try:
            found.update(map(int, (thread/'children').read_text().split()))
        except FileNotFoundError:
            pass
    return found

descendants = children(parent)
for _ in range(4):
    descendants.update(child for pid in list(descendants) for child in children(pid))
isolated = []
binary = (root/'bin/lyrebird').stat()
for pid in descendants:
    path = proc/str(pid)
    handle = None
    try:
        # Retain identity before inspecting /proc; PID reuse must never let this
        # observer stop a process other than the inspected fixture child.
        handle = os.pidfd_open(pid)
        executable = (path/'exe').stat()
        if (executable.st_dev, executable.st_ino) != (binary.st_dev, binary.st_ino):
            continue
        if os.readlink(path/'ns/mnt') == os.readlink(proc/str(parent)/'ns/mnt'):
            continue
        assert os.readlink(path/'ns/net') == worker['namespace']
        assert os.readlink(path/'ns/pid') != os.readlink(proc/str(parent)/'ns/pid')
        status = dict(line.split(':', 1) for line in (path/'status').read_text().splitlines())
        assert int(status['Uid'].split()[1]) == uid
        assert int(status['CapEff'].strip(), 16) == 0
        assert int(status['NoNewPrivs'].strip()) == 1
        mounts = [line.split()[4] for line in (path/'mountinfo').read_text().splitlines()]
        assert '/state' in mounts and '/run/pt/transport' in mounts
        assert not any(m == '/home' or m.startswith('/home/') or m == '/root' or m.startswith('/run/user') for m in mounts)
        assert not (path/'root'/str(root/'runtime/net.sock').lstrip('/')).exists()
        assert not (path/'root'/str(root/'mount/private').lstrip('/')).exists()
        assert not select.select([handle], [], [], 0)[0], 'PT exited during inspection'
        isolated.append(handle)
        handle = None
    except (FileNotFoundError, ProcessLookupError):
        pass
    finally:
        if handle is not None:
            os.close(handle)
assert isolated, 'no isolated PT observed'
# Prevent tor-ptmgr from relaunching the test binary after killing this PT.
# The retained verified handle is not replaced; no production retry is added.
(root/'bin/lyrebird').rename(root/'bin/lyrebird.disabled')
for handle in isolated:
    try:
        signal.pidfd_send_signal(handle, signal.SIGKILL)
        assert select.select([handle], [], [], 5)[0], 'PT did not exit after stop'
    finally:
        os.close(handle)
assert (proc/str(parent)).exists()
(root/'bridge-evidence.json').write_text(json.dumps({
    'complete': True, 'transport': 'obfs4', 'port': 9905,
    'separate_mount_and_pid_namespaces': True, 'shared_transport_network_namespace': True,
    'unprivileged': True, 'no_capabilities': True, 'no_new_privs': True,
    'core_storage_and_ipc_absent': True, 'pt_stopped_without_stopping_tor': True,
}))
