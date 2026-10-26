# Windows agent ↔ Drupal API

This describes the signed API slice in
drupal/thessley_windows_access. The opt-in Windows service prototype in the
separate Windows project calls the challenge and status routes. It is a
development contract, not a released Windows client protocol.

## Separate identity and group concepts

- A Windows account binding identifies one local account by machine ID and a
  SHA-256 hash of its SID. It links to one Drupal user.
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

The enrollment form accepts the Windows account agent's Base64 DER P-256
public key. Never submit the private key. Phone responses use the existing
thessley_pam_v1 canonical signature. Agent requests use a distinct domain:

    thessley_win_agent_v1|challenge|machine_id|username|client_nonce|timestamp
    thessley_win_agent_v1|poll|machine_id|username|request_id|request_nonce|timestamp
    thessley_win_agent_v1|policy|machine_id|username|timestamp

Sign the exact UTF-8 bytes with ECDSA P-256/SHA-256. Send the Base64 DER ECDSA
signature. Timestamps are Unix seconds; requests outside a 60-second window
are rejected. All endpoints require HTTPS and never accept a public key from
the request body as its own trust anchor.

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

The signature covers the request ID and its server-generated nonce. The
server returns pending, approved, denied, expired, or consumed. Approved and
denied results are consumed once. The client must treat all errors, timeouts,
revocations, and unknown statuses as refusal.

### Pull current Drupal groups and policy

POST /thessley-windows/v1/{machine_id}/{username}/policy

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
- Android currently restricts computer PAM links to private IPv4 addresses;
  a public Drupal PAM host requires a separately reviewed Android trust
  change.

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
