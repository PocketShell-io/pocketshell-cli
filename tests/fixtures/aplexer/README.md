# aplexer snapshot fixtures

Hand-captured `a --json snapshot` rows from the #2554 liveness work: each
file is one real registry state that the three review rounds classified
wrongly at least once (mid-create, crashed-start, post-kill window, the
live/dead/failed/zombie mix).

`state` was added to every row when pocketshell started consuming it
(issue #7): the captures pre-date aplexer 0.1.4, which began emitting the
field, and the sessions are long gone, so the values are `observed_state()`
applied to each row's recorded `phase` / `worker_alive` / age-at-capture —
`starting` only for the row captured inside a live `a start` window
(`snapshot-mid-create.json`), `broken` for the worker-died-without-exit
shapes, the phase name otherwise. `snapshot-agent.json` was captured on a
0.1.4-era build and carries aplexer's own values verbatim.
