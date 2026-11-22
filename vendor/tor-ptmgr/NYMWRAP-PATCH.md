# NymWrap tor-ptmgr patch

Upstream: tor-ptmgr 0.48.0, crates.io archive SHA-256
`e5a85e68659fc0627daa90cb7c1993461801ace009fc22aec230a62cdef27747`.
Only nw-netd uses this copy. See ADR 0048.

`ipc.rs` clears the PT environment, supplies the PT state directory as private
HOME/TEMP and working directory, normalizes public locale/identity variables,
preserves only Windows system-directory variables, discards stderr and hides
the child window. No PATH search or additional command arguments are introduced.

AsyncPtChild now owns the stdin handle and a direct child-process handle.
Dropping it kills and reaps the process even if the stdout reader is blocked
on a quiet transport. EOF/error also kills and reaps. This replaces upstream's
reader-dependent graceful shutdown. Killing the complete process group when
nw-netd itself crashes still requires the OS sandbox/lifetime gate in M6.
