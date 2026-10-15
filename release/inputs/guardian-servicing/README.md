# Windows servicing guardian

Derived from `guardian-e862645d`. The source/API/policy hashes remain compiled
release anchors. This successor removes OS-file hash pins: only exact System32
cmd.exe/conhost.exe images may use the existing system-owned, reparse-free,
non-user-writable servicing path authority. Startup job members at those paths
receive the same authority check. All other startup images still need a bundled
manifest pin and matching digest. No task, session, job, key or stop policy changes.
