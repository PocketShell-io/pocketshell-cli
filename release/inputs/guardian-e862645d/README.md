# Guardian e862645d (successor of 6cf7ae85): the agreed full-closure manifest bound

Derived from the reviewed guardian 6cf7ae85 (`../guardian-6cf7ae85`, byte-identical copies) by exactly ONE byte-level change in `guardian.py` (`DERIVATION.diff`):

- the manifest read bound: `st_size>65536` becomes `st_size>8388608` (8 MiB, agreement §16.14);
- this is the agreed bound shared by the native verifier, the installer and Fleet, sized for the whole closure: Python plus endpoint plus the PortableGit/MSYS backend, measured at ~9 777 rows and a ~2.33 MB manifest.

`native_api.py` and `policy.py` are unchanged (cab601e2…, e92bbe02…). guardian.py still verifies them by its embedded pins.

Every other line is byte-identical. The following semantics are unchanged:
- refusals, NoJob/owned-job custody, startup_members (job members ≤ 64);
- path_authority, the servicing roles, STOP/READY/CLOSED.

| file | sha256 |
|---|---|
| guardian.py | e862645ddc374801f1ae921be3bf66afeb0ccff03d82adb909ad1b4ec0bdd877 |
| native_api.py | cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231 |
| policy.py | e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce |

The generic trio compiled once in `ALLOWED_GUARDIAN_SOURCES` is this trio. Catalog v3 lineage is `guardian.abi = "e862645d"`. Catalog v2 keeps 6cf7ae85.

Provenance: the producer (pocketshell-cli) derived it under the root's full-closure bounds decision. It is reviewed through this diff. The guardian owner's receipts must name this trio.
