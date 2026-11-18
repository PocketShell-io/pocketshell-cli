# Login-shell guardian

Derived from `guardian-interactive` by one line (`DERIVATION.diff`): the pinned
aplexer `engines.shell` command is `[bash, "--login", "-i"]` instead of
`[bash, "--noprofile", "--norc", "-i"]`, so durable shell sessions read the
user's `~/.bash_profile` / `~/.bashrc` like Git Bash does. `env_unset` stays
`["BASH_ENV", "ENV", "ZDOTDIR"]`. `native_api.py` and `policy.py` are unchanged
(same hashes as `guardian-interactive`).

The generated endpoint config selects the pinned command from the guardian's
own source digest (`service_agent_endpoint.SHELL_ARGV_BY_GUARDIAN`), so an older
guardian still validates the older command. Older source triples stay trusted
only so the existing tray-repair path can stop and upgrade enrolled installs.
Never modify hashes or installed guardian files manually.
