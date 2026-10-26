# Thessley distributed Windows login and access — design draft

Status: architecture proposal for review. This document does not change or register the Windows sign-in provider.

## Goal

Use one Thessley identity and policy service for two related jobs:

1. Approve Windows sign-in and unlock through the Thessley phone app.
2. Authorize a signed-in Windows user to access protected resources such as SSH, VPN, and web applications.

The Windows sign-in UI and resource access checks are separate enforcement paths. A successful Windows unlock must not implicitly grant access to every resource.

## What exists today

- The Windows UI is a native C++ Credential Provider and QR viewer. The separate desktop prototype calls the local Python service on `127.0.0.1:47800`.
- The Python service creates phone approval requests using the existing Thessley signed-request protocol. The test app proves phone approval and cancellation, but does not log a user into Windows.
- The experimental provider currently uses a DPAPI-protected saved Windows password after phone approval. It is therefore a QR-gated password vault, not passwordless authentication. The built-in PIN/password providers are recovery paths and must remain available during development.
- The Drupal module already has request, phone-key, signature-validation, and revocation patterns. Its existing API is for Drupal web login; Windows identities and resource authorization need their own records and routes.

## Phone-app compatibility: use the existing PAM protocol

The phone-facing Windows flow should use the existing Thessley PAM protocol,
not the website passkey protocol and not a new Windows-only approval format.
The QR should be a `thessleypam://login?...` request, signed as
`thessley_pam_v1`, and bind the approval to the Windows machine ID and account.
That is the screen-login request type already understood by the Android app.

The Android app stores an enrolled computer account under **Computers**, with
the computer name and account name shown on the card. The enrollment API must
return the same kind of successful enrollment response the app uses today so
it creates that local Computers entry. Later login QR approvals should match
that entry by machine ID and account, then use its Android Keystore key. The
existing PIN/biometric prompt remains the user's confirmation.

For the distributed version, Windows should open a PAM request at the central
Drupal service; the app should post its PAM response to that same service. The
Windows agent can poll the request result using its registered client key.
This preserves the phone's computer/account UX while removing the need for an
incoming phone connection to each Windows PC. Drupal must implement the PAM
enrollment, request, status, and response shapes expected by the app. The
current Drupal website-login API alone does not provide those endpoints.

The Android PAM parser currently accepts private IPv4 hosts for computer
requests and reserves public hosts for explicitly enrolled VPN hosts. A public
Drupal PAM endpoint therefore needs an explicit server-registration/trust
step in the app. Do not simply allow any public hostname from a QR; the QR
must be constrained to a Drupal origin the user has already configured or
verified.

One compatibility detail needs attention: Android currently validates the
PAM account string as a short Unix-style username. Windows domain names such
as `DOMAIN\\user` do not fit that rule. We should extend the PAM model to carry
a display-safe account label while binding signatures to a canonical stable
principal ID, or make a carefully versioned parser/protocol update. Do not
silently truncate the account name, because two accounts could then appear to
be the same in the phone UI.

Windows Credential Providers gather and serialize credentials; Windows authentication packages validate them. The UI tile alone cannot make a remote approval into a Windows credential. See [Microsoft's Credential Providers documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows).

## Identity and key model

### Windows principal identity

Do not identify an account by its display name alone. A computer can have
many Windows accounts, and one Drupal person can be linked to Windows
accounts on many computers. Model each local account as a separate binding:

`Drupal identity ↔ Windows principal binding ↔ enrolled computer`

Use a namespaced stable identifier for each Windows principal:

- Local account: machine registration ID + Windows SID.
- Domain account: domain authority ID + domain SID + user SID.
- Store the current display name separately for the admin UI.

The database must allow many principal bindings per computer and many bindings
per Drupal identity. Enrolling a second account on one computer must not
replace the first account's key or phone-app entry. This avoids collisions
such as two unrelated computers both having a `martin` account. Renaming an
account does not change its identity.

### Key ownership

Each enrolled Windows principal on each computer has a distinct signing key. Generate it on that computer, preferably as a non-exportable TPM-backed CNG key. Drupal stores the public key and key metadata only; it never stores the Windows password or the private key. The private key must be accessible only to the Windows service/provider identity that needs it, with the account SID and machine identity included in the server-side binding.

Keep these keys separate:

- Android phone approval key: signs the person's approval.
- Windows principal key: proves the registered Windows account/computer client is making the request.
- Drupal deployment signing key: signs short-lived authorization tickets; private material stays outside the database and web root.

The server must never treat possession of a Windows client key alone as user approval. It proves which enrolled client is asking; the phone approval and policy decision establish authorization.

## Enrollment flow

1. An administrator or authorized user starts enrollment for a specific Windows account on a named computer.
2. The Windows service creates that principal's key locally and sends the public key, stable principal identifier, machine registration, and proof of possession to Drupal over HTTPS.
3. Drupal creates a short-lived, single-use pending enrollment. Its QR/link identifies the site, operation, account, computer, request ID, and nonce.
4. The phone displays a concise confirmation such as “Add `DOMAIN\\user` on `PC-NAME`?” The enrolled phone signs the exact enrollment challenge.
5. Drupal verifies both the phone signature and the Windows-key proof, then activates the account/computer binding. New enrollments receive no resource access unless a policy grants it.
6. Revocation disables the key immediately and is audited.

First-phone bootstrap and Windows-account enrollment are distinct operations. The QR must make the target account and computer visible before approval.

## Drupal API boundary

Add dedicated versioned routes to the Thessley module (or a companion module), not generic JSON:API writes for authentication decisions. Drupal's JSON:API documentation explicitly reserves business flows such as login for custom logic: [What JSON:API doesn't do](https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/what-jsonapi-doesnt-do).

The phone routes should preserve the existing PAM request/response contract
where possible (including `thessley_pam_v1`, `thessleypam://login`, the
enrollment response that creates a Computers entry, and signed response
fields). Add central-agent routes for request creation/status and policy
evaluation. Initial route families to design:

Use PAM `login` for the Windows sign-in approval. Do not overload the existing
PAM `sudo` request for resource access: fields such as service and tty are
currently display-only and are not covered by the phone signature. Resource
approvals need a separately versioned signed payload that binds the resource
and action, or a server-issued ticket bound to them.

- `POST /thessley/v1/windows/enroll/start`
- `POST /thessley/v1/windows/enroll/{id}/complete`
- `POST /thessley/v1/windows/challenge`
- `POST /thessley/v1/windows/authorize`
- `GET /thessley/v1/windows/requests/{id}/status`
- `POST /thessley/v1/windows/keys/{id}/revoke`
- Admin-only CRUD for groups, resources, and grants.

Exact names and fields are not frozen. Every mutating route needs strict validation, rate limits, expiry, replay protection, audit logging, and per-route authorization. Challenges and grants should be bound to the site, principal, computer, resource, action, and nonce. Use one-use, short-lived server-signed tickets where a resource can verify them locally; otherwise make an authenticated server-side authorization check. Never trust a user ID, group, resource, or permission supplied by the client without resolving it against server records.

The API's server-signing key is deployment-wide and distinct from all per-account public keys. Keep it outside Drupal's database and document a backup/rotation procedure before production use.

## Groups, resources, and drag-and-drop management

Represent authorization as explicit grants:

`identity or group → resource → actions`

Examples of actions could be `connect`, `administer`, or `download-vpn-profile`. Groups organize people; resources represent actual enforcement points, not just labels in the UI. A grant is effective only if the target service checks it.

### Tenant-wide Windows administrator group

Requirement: a person in the Drupal **Windows Administrators** group may sign
in to every enrolled Windows computer in that tenant and retain Windows local
administrator rights on those computers. This is a global group grant, not a
separate assignment on each PC. The computer agent must apply the grant to the
corresponding local Windows account's membership in the built-in
`Administrators` group.

Keep that mapping explicit and auditable: Drupal membership is the source of
authorization; the endpoint reconciles only Thessley-managed memberships and
must never remove unrelated or built-in recovery administrators. Keep a
separate break-glass local administrator outside Thessley control. Removing a
person from the Drupal group revokes new Thessley approvals immediately; local
Windows administrator membership can only be removed when that computer next
checks in, so its offline/revocation delay must be visible in Admin.

The group grant still requires an account Windows can log on as on each PC.
Machine-local accounts have different SIDs on different computers. We must
either use a shared domain/Entra identity or explicitly enroll/provision each
person's local account on each managed computer and bind that local SID to the
Drupal identity. For the promise “any Windows Administrators group member can
sign in to any managed PC,” every such person needs an account binding on each
target PC; the service can provision missing accounts only through a separate,
explicitly approved account-provisioning flow. A matching display name alone
is not a safe mapping. The current Credential Provider's password vault is
keyed to the local SID, so this account-provisioning and credential-validation
path is part of the Windows sign-in proof, not something the Drupal group
checkbox can solve.

The admin UI can provide a drag-and-drop matrix: people/groups on one side, resources on the other, with explicit action chips. Include a keyboard- and mobile-accessible alternative, a review-before-save step for bulk changes, and an audit entry showing who changed which grant. Enforce every rule in the API; hiding a control in the page is not authorization.

## Windows components and trust boundary

- **Credential Provider (C++):** QR display, account context, status, cancel, and recovery choices. Keep its code small and avoid network or secret storage inside LogonUI.
- **Windows service (Python initially):** authenticated HTTPS client, key operations, local IPC, request polling, and response validation. Restrict IPC to the provider/service identities; reject caller-supplied usernames that do not match the Windows token/SID.
- **Drupal:** identity bindings, phone approval verification, policy checks, revocation, ticket issuance, and audit.
- **Resource adapters:** independently validate authorization for SSH, VPN, web apps, or other services.

The local Python service currently listens on loopback TCP. For the distributed design, prefer a Windows named pipe with a restrictive ACL over a TCP listener where practical. Server communication must validate normal TLS certificates; do not ship a trust-all setting or pin a short-lived leaf certificate.

## The Windows sign-in proof-of-concept is a gate

Before building a large admin UI, prove the complete sign-in boundary on a disposable Windows VM:

1. Show a QR on the actual LogonUI tile and approve it from the phone.
2. Demonstrate exactly what credential is passed to Windows and which authentication package validates it.
3. Confirm local and domain-account behavior separately.
4. Confirm sleep/wake, network loss, server outage, expired approval, phone revocation, password change, and recovery-tile behavior.
5. Keep rollback armed until several real sign-in and unlock cycles succeed.

The current provider's saved-password path can be used as a clearly labeled prototype, but it must not be described as passwordless or treated as the final security model. Do not store Windows passwords in Drupal.

For comparison, authentik's current Windows agent combines a server-directed authorization flow and device access groups, but its docs currently state that offline login is unsupported and that it changes the local Windows password to a random value: [authentik Windows local login](https://docs.goauthentik.io/endpoint-devices/authentik-agent/device-authentication/local-device-login/windows/). privacyIDEA is another useful reference: its open-source Credential Provider uses a REST API and documents fallback and provider-filter behavior ([project](https://github.com/privacyidea/privacyidea-credential-provider), [configuration](https://github.com/privacyidea/privacyidea-credential-provider/blob/master/doc/configuration.rst)). These are design references, not dependencies we need to adopt.

## Availability and recovery policy

The design must explicitly choose behavior for unavailable network/server, because the lock screen may run before Wi-Fi or VPN is ready:

- Keep PIN/password recovery available by default.
- Never make a server timeout look like approval.
- QR approval expires quickly and is single-use.
- Resource authorization fails closed when its policy cannot be checked, with carefully defined exceptions for already-issued short-lived tickets.
- Windows offline sign-in behavior must be documented separately from online resource access. Revocation cannot reach a disconnected computer until it reconnects.
- Provide a local recovery procedure and a rollback timer for any provider, filter, or authentication-package change.

## Proposed milestones

1. **Identity/API design:** freeze principal IDs, key records, request signing, ticket format, expiry, and revocation semantics.
2. **Enrollment vertical slice:** one Windows account and one computer enrolled by phone; public key saved in Drupal; revoke and re-enroll.
3. **One resource adapter:** authorize a signed-in Windows user for one resource using groups and a short-lived ticket.
4. **Admin management:** group/resource matrix with audit and accessible drag-and-drop controls.
5. **LogonUI proof:** independently prove which Windows authentication mechanism accepts the QR-approved result, then choose whether to replace the saved-password prototype.
6. **Hardening and rollout:** offline policy, key rotation, backup/restore, monitoring, staged deployment, and tested rollback.

## Decisions to settle before implementation

1. Is the first supported computer a Windows 11 Pro local-account machine, or should domain/Entra accounts be supported from the first release?
2. For a disconnected lock screen, should QR sign-in be unavailable while PIN/password remains available, or is offline QR sign-in a requirement?
3. Should group membership be managed only in Drupal, or imported from Windows/Active Directory when present?
4. Is the initial resource target VPN, SSH, or a web application?

