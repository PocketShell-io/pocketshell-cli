# Owned correction: a NULL PATH crash in the daemon entry points (e302fe1)

**Evidence** (CI run 38039287811, job 114176155175, controlled bisection of the guardian's closed environment):
- `sshd -d -D` in the closed manifest environment exits 0xC0000005 with no output.
- The same run with ONLY `PATH` added runs normally.
- Adding any other single variable still crashes: COMPUTERNAME, USERNAME, USERDOMAIN, LOCALAPPDATA, APPDATA, ALLUSERSPROFILE, ProgramFiles, backslashed SystemRoot/WINDIR/ProgramData, or the bin cwd. (`+PROGRAMDATA` and `all extras` are ambiguous observations: they made case-distinct duplicate keys.)

**Source.** In contrib/win32/win32compat/wmain_sshd.c:245/251 and in wmain_sshd-session.c / wmain_sshd-auth.c :92/98:
- `_wdupenv_s(&path_value, …, L"PATH")` leaves `path_value == NULL` when PATH is absent;
- `wcslen(path_value)` then dereferences NULL;
- `swprintf_s(... "%s", path_value)` would too.

The guardian 6cf/e862 policy requires EXACTLY eight environment keys and no PATH, so the guardian's daemon always takes this path.

**Change.** Two expressions per file use `path_value ? path_value : L""`. Nothing else changes:

| file | upstream | overlay |
|---|---|---|
| wmain_sshd.c | 40f0c064… | 7618bc1f… |
| wmain_sshd-session.c | 013c787d… | 48c4b370… |
| wmain_sshd-auth.c | 518b6fec… | af1bd3fd… |
