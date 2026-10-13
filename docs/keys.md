# SSH key vault: `pocketshell keys` and `gateway ssh --key`

The key vault keeps SSH private keys on this device, encrypted with a
**device password**. `pocketshell gateway ssh DEVICE --key NAME` uses a key
from it for one session, through a private ssh-agent that exists only for
that session.

```text
pocketshell keys generate NAME [--type ed25519|ecdsa|rsa] [--comment TEXT]
pocketshell keys add NAME --from FILE|-
pocketshell keys list [--json]
pocketshell keys public NAME
pocketshell keys remove NAME [--yes]
pocketshell keys passwd
pocketshell gateway ssh DEVICE --key NAME [-l USER] [-- SSH_ARGS…]
```

## What is protected, and from whom

**PocketShell's servers never hold a usable private key.** The broker, the
gateway and the sync service have no way into your devices. The vault is a
file on this device and it is never uploaded or synced. The device password
and a key's own OpenSSH passphrase are typed on this device's terminal,
used in this process's memory, and never stored or sent anywhere. During
`gateway ssh` the gateway carries only the encrypted SSH stream between
your OpenSSH client and the host's sshd. It never sees a key or a password.

Two independent secrets can protect a key:

1. the **device password**, which encrypts every key in the vault. It is
   asked for whenever a key is added, used or re-encrypted;
2. the key's **own OpenSSH passphrase**, if it has one. `keys add` stores
   such a key exactly as it is, still encrypted with its passphrase. At
   connect time `ssh-add` asks for that passphrase on your terminal, after
   the device password. Neither PocketShell nor the vault ever sees it.

Someone who copies the vault file has neither secret. They would have to
brute-force the device password through PBKDF2 at 600,000 iterations per
guess, and then the key's passphrase as well, if it has one.

## Typical use

```bash
pocketshell keys generate home-lab          # choose the device password on first use
# → prints "ssh-ed25519 AAAA… home-lab": append it to ~/.ssh/authorized_keys ON THE HOST
pocketshell gateway ssh home-lab -l me --key home-lab
```

To bring an existing key, for example one that already has its own
passphrase:

```bash
pocketshell keys add laptop --from ~/.ssh/id_ed25519
rm ~/.ssh/id_ed25519                        # if the vault should hold the only copy
```

`keys add` never changes or deletes the source file.

## Commands

- **`keys generate NAME`** makes a new key in memory, encrypts it into the
  vault and prints the public key line (stdout) for `authorized_keys`. The
  default type is Ed25519. `--type ecdsa` makes a P-256 key and
  `--type rsa` a 4096-bit RSA key. A generated key has no OpenSSH
  passphrase of its own. If you want both layers, create the key with
  `ssh-keygen -N …` and import it with `keys add`.
- **`keys add NAME --from FILE`** imports an OpenSSH (`openssh-key-v1`) or
  PEM/PKCS#8 private key, byte for byte. `--from -` reads the key from
  stdin. The public half is read from the key file's unencrypted header,
  so a key with its own passphrase can be imported without entering it.
  The one exception is an encrypted *legacy PEM* key, which needs its
  `FILE.pub` next to it. Alternatively, convert it with `ssh-keygen -p -f
  FILE`, which keeps the passphrase. PuTTY `.ppk` files are refused.
- **`keys list`** and **`keys public NAME`** show only public metadata
  (name, type, SHA256 fingerprint, whether the key has its own
  passphrase, the public key line). They need no password.
- **`keys remove NAME`** deletes the entry. It asks for confirmation
  unless you pass `--yes`, and refuses without a terminal. It needs no
  password, because anyone who can write the file can delete it anyway.
- **`keys passwd`** changes the device password. Every key is decrypted
  with the old password and re-encrypted with the new one, and the file
  is replaced in a single atomic write.

**The device password** is chosen when the first key is added (typed
twice, at least 8 characters). After that, every command that adds a key
checks the password against an existing entry, so all keys share one
password. If you forget the password, the keys are lost. There is no
recovery, by design.

The password is read only from the controlling terminal (`/dev/tty`) with
echo off. It is never taken from argv, the environment or a redirected
stdin. Without a terminal, the command fails rather than falling back as
`getpass` would.

## `gateway ssh --key NAME`

1. The vault entry is looked up first, with no password. An unknown name,
   a missing login (exit 3) or a missing pin fails before anything is
   asked or started.
2. The device password is read from the terminal. The key is decrypted
   into a mutable in-memory buffer. A wrong password stops here with
   `wrong device password` and nothing else is started.
3. A fresh directory is created with `mkdtemp` (mode 0700, under
   `$TMPDIR`). It holds the agent socket and the key's **public** half,
   and nothing else.
4. `ssh-agent -D -a <socket> -t 120` starts in its own session, so a
   Ctrl-C on the terminal doesn't reach it.
5. The key goes to `ssh-add` through an anonymous pipe passed as
   `/dev/fd/N`. ssh-add's stdin stays your terminal, so a key with its own
   passphrase is prompted for there. (`ssh-add -` would make the pipe
   ssh-add's stdin, and it could not prompt.) The decrypted buffer is
   zeroed as soon as the pipe has it.
6. `ssh` runs as a child process with the usual hardened argv
   ([gateway.md §9.4](gateway.md)), plus `IdentityAgent=<socket>` and
   `IdentityFile=<the .pub>`. With `IdentitiesOnly=yes`, exactly that key
   is offered, and the agent signs with it. `ForwardAgent=no` still
   applies, so the host never sees the agent.
7. When ssh exits, the agent is killed and the directory is removed. The
   same cleanup runs on Ctrl-C, on `SIGTERM`/`SIGHUP` (forwarded to ssh
   while it runs) and on any error. The exit status is ssh's.

The agent holds the key for at most 120 seconds (`-t 120`). Authentication
happens once, when the connection is set up (bounded by
`ConnectTimeout=30`), so this does not limit the session's length. It
limits how long another process running as **your** user could ask the
agent to sign. It also backs up the cleanup if this process is
`SIGKILL`ed: the agent then lingers, but holds no key after two minutes.

**No implicit default.** `gateway ssh` without `--key` behaves as before:
`-i FILE`, or OpenSSH's default `~/.ssh/id_*` files. OpenSSH prompts for a
file's passphrase itself. A vault key is used only when `--key` names it,
even when the vault holds exactly one key. Plain `gateway ssh` therefore
never prompts for a device password, and a problem with the vault (such
as a permissions refusal) cannot break it. `--key` and `-i` are mutually
exclusive.

`--key` needs OpenSSH's `ssh-agent` and `ssh-add` on `PATH`. It is
POSIX-only for now. On Windows, use `-i FILE`.

## The vault file

The vault lives at `${XDG_CONFIG_HOME:-~/.config}/pocketshell/key-vault.json`,
next to the login session file, and is handled with the same care
([account.md](account.md#credentials-file)):

- The directory is mode 0700 and owned by you. An existing directory you
  own is tightened to 0700 on write. A directory that is not yours, or
  that others can write to, is refused.
- The file is a 0600 regular file owned by you, opened with
  `O_NOFOLLOW`. A symlink, a FIFO, a file someone else owns, or a mode
  with any group or other bits is refused with a message saying how to
  fix it. Such a file is never read.
- Writes go to a fresh `O_EXCL` temporary name, which is fsynced and then
  `os.replace`d into place, and the directory is fsynced. Every
  read-modify-write holds an exclusive `flock` on
  `.key-vault.lock` in the same directory, so concurrent commands cannot
  lose an entry. A failed write leaves the previous vault intact.
- No plaintext key is ever written to disk. Import reads the source into
  memory, generation happens in memory, and `gateway ssh` writes only the
  public key to its temporary directory.

```json
{
  "version": 1,
  "keys": {
    "home-lab": {
      "public_key": "ssh-ed25519 AAAA… home-lab",
      "fingerprint": "SHA256:…",
      "passphrase_protected": false,
      "created_at": 1767225600,
      "envelope": {"v": 1, "kdf": "pbkdf2-sha256", "iter": 600000,
                   "salt": "<b64 16 B>", "iv": "<b64 12 B>", "ct": "<b64 ciphertext + 16 B tag>"}
    }
  }
}
```

Each envelope uses the **same construction and parameters as the
PocketShell web and desktop clients' encrypted sync envelope**:
PBKDF2-HMAC-SHA256 with 600,000 iterations, a 16-byte random salt and a
32-byte key, feeding AES-256-GCM with a 12-byte random IV and a 16-byte tag
appended to the ciphertext, all base64-encoded. The field names are the
same too. Each encryption gets a fresh salt and IV. The iteration count
stored in the file is bounds-checked (1 to 10,000,000) before use, as the
web and desktop clients do.

One addition: every envelope is bound to its entry with GCM associated
data, `"pocketshell-key-vault/v1\0" + name + "\0" + public-key blob`. A
ciphertext moved to another name, or paired with a different public key,
fails authentication, like a wrong password or any flipped bit. GCM cannot
tell those cases apart, and the error message says so.

The public metadata is stored in the clear, so `list` and `public` work
without the password. It reveals which public keys you have, which
`authorized_keys` on your hosts reveals anyway.

Python cannot guarantee that a secret leaves no copy in memory: the
password string and the derived key are immutable objects. The decrypted
key itself is only ever held in a buffer that is zeroed after use.
Treat this as best-effort hygiene, not a guarantee.

## Compared with the web and desktop clients

Like the web client's per-host keys (`useHostsStore`, pocketshell-web
`src/stores/hosts.ts`), CLI keys are encrypted on the device with PBKDF2 at
600,000 iterations and AES-256-GCM, and the server never has the means to
open them. The differences:

| | Web client | CLI vault |
|---|---|---|
| Password | The account's **sync passphrase** | A **device password**, local to this machine and unrelated to the account |
| Where the ciphertext lives | Synced to the account's `keys` slot, plus a `localStorage` cache | This device only. Never synced or uploaded |
| A key's own OpenSSH passphrase | Stored inside the encrypted record (`keyPassphrase`) | Never stored. `ssh-add` asks for it at every connect |
| "Remember on this computer" | Optional (`passphraseVault.ts`: a non-extractable WebCrypto key) | No caching. Every `--key` connect asks for the password |
| Entry binding | None (no AAD) | Name and public key bound as AAD |
| Minimum password length | None enforced | 8 characters |
| Who uses the key | The browser's SSH client (direct relay mode). The legacy Lambda-bridge mode sends it to the bridge for the connection | Local OpenSSH, through a private agent. It never leaves the machine |

Because of the AAD binding, a vault entry cannot be opened by the web's
`decryptEnvelope`. That is intentional: vault entries are never exchanged
with the web or desktop clients.
