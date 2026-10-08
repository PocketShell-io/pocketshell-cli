# Account login: `pocketshell login` / `logout` / `whoami`

`pocketshell login` connects this machine to your PocketShell account with a
device-authorization flow, like `gh auth login` or `aws sso login`. It's built
for machines where pasting a token is awkward: an SSH session, a headless box,
or a laptop with no browser session. Gateway commands such as
`pocketshell gateway enroll` then get their short-lived broker token on their
own, so you never handle a token yourself.

```text
pocketshell login [--label TEXT] [--no-open] [--force]
pocketshell whoami [--json]
pocketshell logout
```

## Logging in

```console
$ pocketshell login
To log in, open:  https://app.pocketshell.io/device?code=BCDF-GHJK
Confirm the code shown in the browser matches: BCDF-GHJK
The page will ask you to type its last 4 characters before approving.
Waiting for approval (Ctrl+C to cancel)...
Logged in as you@example.com.
```

1. The CLI asks the broker for a pairing (`POST /auth/device/start`) and
   labels it `user@hostname`, or the value of `--label` (at most 80 printable
   characters). The approval page shows this label so you can tell which
   machine is asking.
2. It prints the code and the verification URL. If a browser is available
   and you didn't pass `--no-open`, it also opens the pre-filled URL. The
   code must have the form `XXXX-XXXX`, using only the letters
   `BCDFGHJKLMNPQRSTVWXZ` and the digits `2`-`9`. `login` refuses any other
   code and doesn't print it.
3. Sign in on the page, check that the code and label match what the
   terminal shows, type the code's last 4 characters when the page asks
   (it asks even when you opened the pre-filled link), and approve.
4. The CLI polls at the interval the broker asks for, and adds 5 seconds
   whenever the broker answers `slow_down`. It stops with a clear message
   when you deny the request or the code expires (10 minutes). Press Ctrl+C
   to cancel cleanly (exit 130).
5. The CLI checks the new session with `GET /cli/session` and then saves it.

You can review and revoke your CLI sessions at
<https://app.pocketshell.io/device/sessions>. `whoami` prints this link too.

If you're already logged in with a session that hasn't expired, `login`
refuses to replace it and exits 1. Run `pocketshell logout` first, or run
`pocketshell login --force`. With `--force`, the old session is revoked
once the new one is saved. You don't need `--force` to replace an expired
session.

## Commands that use the login

The session token never leaves this machine except to talk to the broker
that issued it. That broker's URL is stored with the session at login, and
`whoami`, `logout` and every token mint use only that stored URL.
`POCKETSHELL_BROKER_URL` is ignored for an existing session. If it is set to
a different broker (by accident, or by a hostile `.envrc`), the command
refuses to send the session anywhere and tells you to unset the variable or
run `pocketshell login --force` for that broker. Other commands call
`pocketshell.account.mint_gateway_token()` to exchange it for a broker JWT
(`POST /cli/gateway/token`). That JWT is valid for at most 5 minutes and is
the same token `POST /gateway/token` mints for the app. If the broker answers
401, the commands report "run `pocketshell login`".

## `whoami`

`whoami` prints the account, the session label, the broker and the expiry,
followed by the link where you can review or revoke sessions,
<https://app.pocketshell.io/device/sessions>. It also checks the session with
the broker. If the broker can't be reached, it
shows the local copy and marks it `verified: no`, with a warning on stderr.
`--json` prints:

```json
{"broker_url": "...", "email": "...", "expires_at": 1767225600,
 "label": "you@laptop", "logged_in": true, "token_id": "...", "verified": true}
```

When you're not logged in, `whoami --json` prints `{"logged_in": false}` and
exits 1. When `POCKETSHELL_BROKER_URL` points to a different broker than the
one you logged in to, `whoami` doesn't contact any broker. It shows the local
copy as `verified: no` and prints a warning.

## `logout`

`logout` revokes the session on the broker (`POST /cli/logout`, best effort)
and deletes the credentials file. If the broker can't be reached, the file
is still deleted, and a warning says how long the session stays valid on
the server. The same happens when `POCKETSHELL_BROKER_URL` names a different
broker: the session isn't sent there. A `401` from the broker means the
session is already gone and counts as logged out.

## Credentials file

`${XDG_CONFIG_HOME:-~/.config}/pocketshell/credentials.json`:

```json
{"version": 1, "broker_url": "...", "access_token": "psc_...", "token_id": "...",
 "email": "...", "expires_at": 1767225600, "label": "you@laptop"}
```

- **Written atomically and private from the start.** The directory is created
  with mode 0700, and an existing directory you own is tightened to 0700. The
  file is written to a new temporary name opened with
  `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600, fsynced, and moved into place with
  `os.replace`. The token is never on disk with wider permissions, even for a
  moment. There's no chmod after the write.
- **Checked before every read.** The file is ignored, and treated as "not
  logged in" with a message explaining why, when it is a symlink or not a
  regular file, isn't owned by you, can be read or written by your group or
  other users, or sits in a directory that others can write to. The message
  never includes the file's contents. A file that's only too permissive still
  holds your own token, so `pocketshell logout` revokes it before deleting it.
  For a symlink or a file someone else owns, `logout` just removes the entry
  and doesn't contact the broker.

## Network and trust

- Only HTTPS, with TLS verification always on. Redirects aren't followed,
  because they would replay the `Authorization` header somewhere else. Every
  request has a timeout, and response bodies are capped at 64 KiB.
- Responses must be strict JSON objects: valid UTF-8, no duplicate keys, no
  NaN or Infinity. Every field the CLI uses is type-checked.
- Tokens and the device code go only in the `Authorization` header or the JSON
  body. They never appear in a URL, argv, a child process's environment, logs,
  exception messages, or a `repr`.
- Anything the server sends that the CLI prints (user code, email, label,
  error codes) has control, escape and invisible format characters removed
  first.
- `login` prints or opens a verification URL only when it is plain `https://`
  on the trusted approval origin, `https://app.pocketshell.io`. If the broker
  sends any other URL, `login` doesn't show or open it. It prints a warning,
  shows `https://app.pocketshell.io/device` and the code instead, and keeps
  waiting. A broker, including one an `.envrc` points to, can't send you to a
  look-alike approval page.
- The pre-filled link (`verification_uri_complete`) is printed or opened only
  when it is exactly `<verification_uri>?code=<the printed code>`. Otherwise
  `login` prints the plain verification URL and the code, so a broker can't
  pre-fill a different code on the trusted page than the one your terminal
  shows. The page also makes you type the code's last 4 characters, so
  approving always means comparing it with the terminal.
- The gateway token from `/cli/gateway/token` must look like a JWT (three
  base64url segments with a JSON header). Its `expires_at` must fall within
  300 seconds plus 5 minutes of clock skew from now.

## Configuration

| Variable | Meaning |
| --- | --- |
| `POCKETSHELL_BROKER_URL` | Broker base URL for `login` (default: the production broker). Must be `https://` with no credentials, query or fragment. An existing session always uses the broker stored with it, and the command refuses to run when this variable names a different one. |
| `POCKETSHELL_DEV_WEB_ORIGIN` | Staging and development only: the trusted approval origin, as a bare `https://host[:port]`. It's honored only when `POCKETSHELL_BROKER_URL` is also set. |
| `POCKETSHELL_BROKER_INSECURE_DEV=1` | Development and tests only: also allows `http://` when the host is loopback (`127.0.0.0/8`, `::1`, `localhost`). |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. `logout` also exits 0 when you weren't logged in. |
| 1 | Error, or not logged in. The message goes to stderr as `error: ...`. |
| 130 | `login` was cancelled with Ctrl+C. |
