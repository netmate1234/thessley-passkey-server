# Windows agent ↔ Drupal API

This describes the versioned API in `drupal/thessley_windows_access` and the
matching opt-in Windows helper and Credential Provider. V1 remains available
for existing local-account bindings. New enrollments use v2, which selects a
Windows principal by its SID digest rather than its display name.

## Separate identity and group concepts

- A Windows account binding identifies one principal by machine ID and a
  SHA-256 hash of its SID. It links to one Drupal user. `principal_type` and
  `authority` describe whether the account is local or domain-scoped; the SID
  digest remains the lookup key, so equal names never select each other's key.
- The Windows account agent key authenticates requests from that computer
  account. Its private key stays on the PC. It is separate from the Android
  phone key.
- Drupal roles act as policy groups. They are the source of truth for which
  mapped account can sign in and whether its local account should be a member
  of Windows Administrators.
- Windows local groups are enforcement targets, not Drupal groups. The agent
  must reconcile only Thessley-managed membership and preserve unrelated
  administrators and recovery accounts.

The service returns current Drupal role membership and effective actions to
the agent. Removing the Drupal sign-in grant blocks new sign-ins immediately.
The agent pulls policy at startup and every 15 minutes; local group changes
therefore need the PC to be online for reconciliation.

## Account key and signatures

The Windows account agent's Base64 DER P-256 public key is registered during
pairing. Never submit the private key. V1 phone responses use
`thessley_pam_v1`; v2 uses the separately versioned
`thessley_win_pam_v2` form so account scope and sign-in context are signed.
V1 agent requests use a distinct domain:

    thessley_win_agent_v1|challenge|machine_id|username|client_nonce|timestamp
    thessley_win_agent_v1|poll|machine_id|username|request_id|request_nonce|timestamp
    thessley_win_agent_v1|policy|machine_id|username|timestamp

Sign the exact UTF-8 bytes with ECDSA P-256/SHA-256. Send the Base64 DER ECDSA
signature. Timestamps are Unix seconds; requests outside a 60-second window
are rejected. All endpoints require HTTPS and never accept a public key from
the request body as its own trust anchor.

V2 agent signatures bind the SID digest and scope as well:

    thessley_win_agent_v2|pair|code|machine_id|principal_id|username|scope|authority|public_key_hash
    thessley_win_agent_v2|challenge|machine_id|principal_id|scope|authority|username|context|client_nonce|timestamp
    thessley_win_agent_v2|poll|machine_id|principal_id|request_id|request_nonce|timestamp
    thessley_win_agent_v2|policy|machine_id|principal_id|timestamp
    thessley_win_agent_v2|inventory|machine_id|principal_id|timestamp|payload_sha256

V2 phone signatures bind the same principal and the `enrollment`,
`interactive`, or `unlock` context. The phone still uses the PAM `enroll` and
`login` actions; this is a versioned PAM request format, not a competing
login mechanism. On first v2 enrollment, Android stores the Drupal host, port,
and TLS fingerprint; later requests for that computer account must match all
three before the phone will sign.

## First PC enrollment

An administrator starts enrollment in **Windows Access → Enroll account** by
entering the PC's reachable IPv4 address, account scope/name, and the Drupal
identity to link. Drupal creates an eight-digit code that expires in ten
minutes. The code is stored as a SHA-256 digest and is bound to that account
and exact source IP.

The current form generates `drupal-enroll-v2`. The helper resolves the short
account name to a SID on the PC, creates a protected P-256 key named by the
SID digest, and posts:

    POST /thessley-windows/v2/pair

    {
      "pair_code": "01234567",
      "machine_id": "32-character-machine-id",
      "hostname": "PC-NAME",
      "username": "shortname",
      "principal_type": "domain",
      "authority": "EXAMPLE",
      "principal_id": "sha256-of-windows-sid",
      "public_key_b64_der": "base64-DER-public-key",
      "signature": "base64-DER-ECDSA"
    }

For a local account, `principal_type` is `local`; its authority is resolved
from the computer name on that PC. The phone QR includes the SID digest,
scope, authority, and `pv=2`, and the phone approval signature covers them.

The original `drupal-enroll` and `/v1/pair` contract remains for installed v1
local accounts. Do not use username-only v1 enrollment for new domain
accounts.

The v1 helper used this request shape:

    POST /thessley-windows/v1/pair

    {
      "pair_code": "01234567",
      "machine_id": "32-character-machine-id",
      "hostname": "PC-NAME",
      "username": "localuser",
      "sid_sha256": "64-character-sid-digest",
      "public_key_b64_der": "base64-DER-public-key",
      "signature": "base64-DER-ECDSA"
    }

The v1 signature covers the pairing code, machine ID, account name, SID
digest, and public-key digest. The pairing code's server-side ten-minute expiry avoids
requiring a synchronized Windows clock for initial enrollment. Drupal also
checks the observed client IP, rate limit, active Drupal identity, and one-use
status before creating the pending account and phone enrollment request. The
response contains the phone app link; the Windows helper renders its QR
locally. The agent private key never crosses the network.

## Routes

### Start phone approval

POST /thessley-windows/v1/{machine_id}/{username}/challenge/login

JSON body:

    {
      "client_nonce": "32-to-64-character-base64url-random-value",
      "timestamp": 1793030400,
      "signature": "base64-DER-ECDSA"
    }

A sudo challenge is also accepted for non-screen PAM operations. Drupal
checks the key, active identity, current Windows sign-in grants, timestamp,
rate limit, and one-use client nonce before returning request_id, nonce,
expires_in, and app_link. The Windows client displays that link as the phone
QR and waits for the status route.

### Poll the approval

POST /thessley-windows/v1/{machine_id}/{username}/requests/{request_id}/status

JSON body:

    {
      "timestamp": 1793030400,
      "signature": "base64-DER-ECDSA"
    }

The signature covers the request ID and its server-generated nonce. V2 uses
`POST /thessley-windows/v2/{machine_id}/{principal_id}/challenge/{interactive|unlock}`
and polls
`POST /thessley-windows/v2/{machine_id}/{principal_id}/requests/{request_id}/status`.
The phone link contains `pv=2`, the SID digest, account scope and authority,
and whether this is an interactive sign-in or an unlock. Approved and denied
results are consumed once. The client must treat all errors, timeouts,
revocations, and unknown statuses as refusal.

### Pull current Drupal groups and policy

POST /thessley-windows/v1/{machine_id}/{username}/policy

V2 uses `POST /thessley-windows/v2/{machine_id}/{principal_id}/policy`,
signed over the machine ID and SID digest. Both responses contain the mapped
Drupal user's roles and effective computer actions. The service pulls the
correct endpoint for each binding at startup and every 15 minutes.

JSON body is timestamp plus an agent signature over the policy message. The
response contains the mapped Drupal user's roles and effective computer
actions. `managed_local_groups` may contain only the stable built-in groups
`Administrators`, `Remote Desktop Users`, `Event Log Readers`, and
`Remote Management Users`, each corresponding to its explicit Drupal action:
`windows.local_admin`, `windows.remote_desktop`,
`windows.event_log_readers`, and `windows.remote_management`. The agent rejects
unknown groups or inconsistent action/group responses. The Windows service
pulls this endpoint once after startup and every 15 minutes for each configured
binding. It records ownership before adding a group membership and removes
only memberships it added when Drupal withdraws the grant. Membership that
existed before the grant is never claimed or removed.

### Report Windows local groups

POST /thessley-windows/v1/{machine_id}/{username}/inventory

V2 uses `POST /thessley-windows/v2/{machine_id}/{principal_id}/inventory`.
Both protocols replace only the exact enrolled account's prior snapshot.

The PC sends a Base64-encoded JSON payload and signs its exact decoded bytes
by SHA-256 digest:

    {
      "timestamp": 1793030400,
      "inventory_b64": "base64-of-utf8-json",
      "signature": "base64-DER-ECDSA"
    }

Decoded JSON format:

    {
      "groups": [
        {
          "sid_hash": "sha256-of-the-Windows-group-SID",
          "name": "Remote Desktop Users"
        }
      ]
    }

Drupal stores this as the latest Windows local-group snapshot for the mapped
account. A report replaces that account's previous snapshot. The Windows
service enumerates the account's direct local-group memberships, hashes each
group SID locally, and reports at most 128 groups during the same startup/15
minute sync. Raw SIDs are not stored. This is inventory only: reported Windows
groups never grant Drupal rights.

## Remaining limitations

- The sync is account-scoped. Each Windows binding must be configured with
  `drupal-setup` and enrolled in the Drupal Windows Access module.
- The inventory is account-scoped; machine-wide account discovery is still
  missing. Admin has a read-only view of reported local groups. The UI creates
  account bindings manually.
- `Administrators` membership is reconciled only for the mapped account and
  only when the agent's local ownership record says Thessley added it. Broader
  Windows group policy, offline change acknowledgements, and fleet-wide
  machine/account discovery are not implemented.
- V2 Android enrollment accepts a public Drupal hostname or globally routable
  IPv4 address and stores its exact host, port, and certificate fingerprint
  with that computer binding. Later v2 requests must match the stored origin
  and fingerprint. V1 computer requests remain limited to private IPv4
  addresses; VPN requests retain their separate enrolled-host check.

For the prototype, test only a low-privilege mapped account with the
computer-scoped `windows.login` grant. Granting a local-group action adds the
mapped Windows account to that supported group after a successful policy sync.
Keep the normal PIN/password provider available until deployment rollback and
recovery are integrated and proven.

## Phone-key revocation

An administrator can revoke an enrolled phone credential from the PC
inventory page. The server keeps an audit record and rejects later responses
from that credential. If an approval was already recorded but the agent has
not consumed it yet, polling checks that the approving credential is still
active and returns `denied` when it has been revoked.
