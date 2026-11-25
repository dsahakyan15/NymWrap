# NymWrap tor-ptmgr patch

Upstream: tor-ptmgr 0.48.0, crates.io archive SHA-256
`e5a85e68659fc0627daa90cb7c1993461801ace009fc22aec230a62cdef27747`.
Only nw-netd uses this copy. See ADR 0048 and ADR 0085.

`ipc.rs` clears the PT environment, supplies the PT state directory as private
HOME/TEMP and working directory, normalizes public locale/identity variables,
preserves only Windows system-directory variables, discards stderr and hides
the child window. No PATH search or additional command arguments are introduced.

AsyncPtChild now owns the stdin handle and a direct child-process handle.
Dropping it kills and reaps the process even if the stdout reader is blocked
on a quiet transport. EOF/error also kills and reaps. This replaces upstream's
reader-dependent graceful shutdown.

Runtime-managed TransportConfig always sets `isolate=true`; there is no
unconfined retry or application setting to disable it. Linux uses fixed bwrap,
new user/mount/PID/IPC/UTS/cgroup namespaces, no capabilities, die-with-parent,
and the existing transport network namespace. Only public system files, the
pinned binary and this PT's encrypted state are mounted. HOME/TEMP/state/cwd
are normalized to /state. macOS uses fixed sandbox-exec with escaped literal
binary/state paths and a deny-default profile. Unsupported Windows isolation
returns transport_sandbox_unavailable before spawn. Full native macOS runtime
and Windows AppContainer integration remain unverified/unimplemented.

Low-level IPC parameters default to unconfined only for direct library callers
such as the synthetic environment/lifetime regression; the production managed
launcher forces isolation. Raw PT LOG/control-line/error text is not emitted
by the patched handlers or propagated into error Display/Debug. A synthetic
regression checks eight control-error canaries. Linux CI adds actual pinned obfs4 bootstrap, namespace
inspection and PT-stop fail-closed pcap; green CI is still required. Complete
daemon crash-lifetime remains an M6 obligation.
