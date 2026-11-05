# Memory bounds in containers without systemd

`pocketshell sessions create` keeps its existing project/default cap policy.
When a dedicated user scope is unavailable, it can use an already stronger
kernel-enforced cgroup-v2 boundary. This is a shared container limit, not an
independent per-session allocation.

The CLI verifies actual procfs membership and mountinfo, then reads the current
domain's real cgroup2 files through directory FDs. It rejects symlinks, overmounts,
ambiguous mappings, writable mounts and non-cgroup filesystems. `memory.max` must
be finite, positive and no greater than the requested cap. `memory.swap.max`
must equal zero, preserving the existing no-swap policy. An Aplexer system-scope
escape override is incompatible with this mode. Evidence is read again directly
before launch; it is never cached as host configuration.

For example, a Docker server container can use:

```text
--memory 384m --memory-swap 384m --pids-limit 192 --cpus 1
--cap-drop ALL --security-opt no-new-privileges
```

Docker's equal memory/swap settings mean zero additional swap. Its implicit
extra-swap default is intentionally refused. Do not expose a writable cgroup
mount or host runtime directories to the container.

The created response reports `memory_enforcement.mode: inherited_cgroup`, actual
`memory_max_bytes`, `swap_max_bytes: 0`, requested bytes and `shared: true`.
Sibling sessions share that hard bound; they are not each given the requested
default12GiB. A request smaller than the existing limit is refused. Unbounded or
unverifiable hosts never silently start an uncapped session. The explicit
`--mem none` call-site override and rejection of project `mem = "none"` remain
unchanged. Dedicated systemd scope behavior is unchanged where available.

Aplexer's direct worker/workload spawn inherits the caller's domain, and the
read-only mount prevents writing membership controls. The guarantee assumes a
trusted installed Aplexer/runtime and container/host administrator: a privileged
administrator can change limits, just as with a dedicated scope.

CI runs real session creation in separate disposable Docker containers, checks
both worker and workload kernel memberships and cleans up sessions, containers
and its image. Negative cases cover too-small requested limits, nonzero swap
and an unbounded container. No OOM test runs on production or registered hosts.
