# Interactive-session guardian

Derived from `guardian-servicing` by allowing an owner-authenticated interactive
WinSta0/Default session to differ from the physical console session. The token
SID, token/process session equality, station visibility and Default desktop are
still measured natively. Session 0 keeps its non-visible station contract.
Private desktop ACLs, pinned images, endpoint/host-key custody, owned jobs and
controlled stop are unchanged.

The policy change has its own new source hash and the guardian embeds that hash.
The tray installer ships this source trio and re-catalogues the complete closure.
The tray uses the explicit `interactive-session` readiness mode tied to its own
caller SID and session. The ordinary CLI still defaults to `active-console`;
S4U tasks still require session 0. Old source triples remain trusted only so the
existing validated tray-repair path can stop and upgrade enrolled installations.
Never modify hashes or installed guardian files manually.
