# Register a server with the account vault

Run `pocketshell gateway register` on the server. It starts PocketShell's normal
device-flow account sign-in when necessary and continues after approval. Enter
your strong vault passphrase locally; a new account asks you to create and
confirm one. An existing vault must be unlocked and is never reset or replaced.

On Linux, registration enables and starts the supported systemd user daemon.
An existing managed service for the same enrollment is preserved and started
without restarting its active connections. An unrelated service is never replaced.
Container entrypoints without systemd can use `pocketshell gateway register
--foreground`: after successful registration and vault lock, the verified agent
runs as the foreground process. Registration alone does not prove gateway
connectivity; online presence requires its running agent to reach the gateway.

Registration creates a dedicated Ed25519 access key for this server. The private
key goes to the account vault only after encryption on this machine. Only its
public half is added to this machine's private endpoint. There is no system SSH
service, inbound port or remote key-install command. Linux uses the private
inetd endpoint; Windows uses the measured owner-private tray endpoint.

The encrypted trusted server descriptor binds account subject, vault generation,
gateway, device identity, complete SSH host key, username, server name and key.
The phone signs in with Google, unlocks that same vault and connects by tapping
the server. Directory-advertised keys never establish trust.

Windows Gateway Setup performs vault registration automatically after account
authorization and endpoint enrollment. Existing tray installations can choose
**Register this server with vault**. Passphrase entry uses native Windows CredUI
in generic non-persistent mode; it is not your Windows password and is not saved
in Credential Manager.

## Interrupted registration

Encrypted key blob and index writes use optimistic concurrency. The descriptor
is published before local public-key authorization. A failed upload never
authorizes the new key. A refused local authorization leaves an authentic server
entry that cannot connect yet; run registration again to finish it.

A protected local `vault-enrollment-intent.json` contains public registration
facts and key ID only. It lets a retry distinguish its own unfinished enrollment
from an unrelated cloud alias. It contains no passphrase, private key or vault
decryption key. A retry reuses the same encrypted key. Existing aliases or changed
server identities are never silently overwritten or repinned.

The separate owner-private `vault-enrollment-trust.json` records accepted
descriptor revisions and ciphertext digests, scoped to account, vault generation
and exact server route, with the full device/SSH/key identity. Ordinary
registration refuses older, deleted or substituted previously accepted records.
Revocation intent is persisted here **before** the public key is removed, so
failed uploads or replay of valid old cloud ciphertext cannot revive that key
after process restart. A revoked key requires an independently authorized
re-enrollment/rotation operation; ordinary registration has no force-unrevoke flag.
Do not delete or reset this history as an error-recovery step.

New pending enrollment journals use local version2. Legacy identity-only journals
without a trust floor are refused rather than promoted to trusted history, since
they cannot prove that a key was not previously revoked. Unsupported local trust
formats and unsafe file permissions are also refused without modifying the files.

First-vault creation uses the broker's atomic initializer: header and verifier
are created together or neither is changed. If the response is lost, retry with
the same chosen passphrase to unlock the existing vault. Do not reset it.

## Revocation and security boundary

Run `pocketshell gateway register --revoke` locally, or use the tray's revoke
action. It removes this server's actual public-key authorization before
publishing an authenticated revocation tombstone. Unrelated endpoint keys remain
intact. Removing an authorized key prevents new SSH authentication; existing SSH
connections continue until the owner closes or drains them. Deleting a cloud
record alone does not revoke endpoint access.

A strong passphrase is required. Ciphertext stolen from cloud storage permits
offline guessing; Argon2id increases its cost, but a numeric PIN is insufficient.
Google login or account recovery cannot decrypt the vault. Keep your vault
passphrase safely: losing it and all trusted unlocked devices means the
encrypted keys cannot be recovered through Google.
Memory erasure in Python is best effort; registration does not save plaintext
secrets, but cannot protect an already compromised local process or operating
system. The installed application and update chain must remain trusted.

The canonical encryption and descriptor byte contract is
[pocketshell-core/TRUSTED-HOSTS.md](https://github.com/PocketShell-io/pocketshell-core/blob/main/docs/TRUSTED-HOSTS.md).
Public synthetic fixtures in `tests/account/fixtures` pin cross-language
Argon2id normalization, HKDF, AES-GCM, SSH key blobs and trusted host descriptors.
