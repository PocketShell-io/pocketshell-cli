# Vendored guardian source triple (release input, read-only)

These are byte-identical copies of the reviewed Windows guardian sources (ABI 6cf7ae85), taken from
`artifacts/windows-guardian-servicing-controls-6cf7-20261009/`. They are owned by the Windows guardian owner.

- They are never edited here.
- `scripts/release/build_closure.py` refuses any file whose sha256 differs from the pins below (also in SHA256SUMS).

| File | sha256 |
|---|---|
| guardian.py | 6cf7ae85ad21b23496e7187da7e3bb4f171adef5f63edd2fd01f6ce6435bd047 |
| native_api.py | cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231 |
| policy.py | e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce |
