# Thessley Windows Access

A separate Drupal module for distributed Windows account enrollment, PAM
sign-in approval, Drupal role/group policy, and protected resources. Windows
logic does not belong in the existing `thessley_passkey` website-login module.
This module reuses its standalone QR-rendering library only.

## Data model

- A machine can have many Windows accounts.
- A Drupal user can be linked to Windows accounts on many machines.
- Every local Windows account binding is identified by the machine ID and a
  SHA-256 hash of its Windows SID; the raw SID is not stored.
- Each account binding can have multiple phone public keys. Android stores its
  own private key and adds the successful enrollment to **Computers**.
- Drupal roles provide group membership. Resource grants are separate from
  sign-in approval. The `Windows Administrators` role is seeded with global
  `windows.login` and `windows.local_admin` grants for enrolled computers.

## Current vertical slice

Open **Administration → Windows Access** for the management landing page, or
open **Administration → People → Windows Access** for the account inventory.
The landing page and module tabs link to **Accounts & computers**, **Enroll
account**, **Groups & access**, and **Server settings**. The Groups & access page lets an administrator drag a
Drupal user onto an access group (Drupal role), manage membership with
checkboxes, and assign each group's computer/resource rights. Changes are
audited. Drupal administrator accounts are excluded from that editor so they
cannot accidentally lose site administration access.

Signed-in users see **Your linked data** directly on the Windows Access landing
page. It lists only Windows account bindings owned by their Drupal user, their
role groups and effective resource rights, active enrolled-phone count, and
Windows local groups last reported by their PCs. The same report is available
at `/my-windows-access`, which requires an authenticated Drupal session; it
does not expose another user's account or device records.

The module settings page is `/admin/config/people/thessley-windows-access`.
Set the HTTPS PAM server URL and its SHA-256 leaf-certificate fingerprint.
Role grants are managed separately at the Groups and resources page.
For the current Android PAM parser, use a private IPv4 host reachable by the
phone. Public hostnames require an explicit server trust/registration update
in the app and are intentionally rejected by this first slice.

The **Enroll Windows account** page creates one pending local-account binding
and a `thessleypam://enroll` QR. The phone posts the existing `thessley_pam_v1`
proof to `/thessley-pam/v1/enroll/{id}/respond`; a successful response returns
the credential ID and account name the app needs to add the computer/account
to its local **Computers** list. PAM signatures are independent from website
passkey signatures. Login-answer requests are rejected unless the linked
Drupal identity currently has `windows.login` on `all_windows`; removing the
Drupal role therefore takes effect on the next attempt.

The first pilot should bind a standard, non-administrator Windows account on a
disposable test computer to a low-privilege Drupal test user. Create that active
Drupal user through the site's normal user administration; the module
deliberately does not create Drupal users or set their passwords. Assign it the
`Windows Login Test` role and grant that role only `Windows sign-in` on the
test computer resource. Enrolling a machine creates its own resource named
`computer_<machine-id>`, allowing this limited grant. Do not assign the test
user to `Windows Administrators`. A separate test will verify the global
administrator-role policy and local Administrators membership reconciliation.

## PC communication

The module now defines signed Windows-agent routes for approval creation,
one-time status polling, and pulling the linked Drupal user's roles and
effective computer actions. It also accepts a signed, account-scoped snapshot
of local Windows groups. Those reported Windows groups are inventory only;
Drupal roles and grants remain the source of authorization. The exact request
signatures and response fields are in
docs/windows-agent-drupal-api.md.

The Windows service syncs each configured Drupal binding immediately after
service startup and every 15 minutes. It uploads direct local-group inventory,
pulls current Drupal roles and grants, and reconciles only local
Administrators membership that it previously added for that mapped account.
The first `Windows Access` inventory row should show its group report after the
first successful sync. Sign-in grants are checked directly by Drupal for every
login request, so stale local policy cannot grant a new sign-in.

The PC inventory page lists the phone credentials enrolled for each Windows
account. An administrator can revoke one credential after a confirmation
step; the action is audited and leaves other phones enrolled. If a phone's
approval is revoked before the Windows agent consumes it, the pending result
is returned as denied.

## Prototype limitations

This remains a development prototype. Drupal account bindings are enrolled
separately for each Windows computer; one Drupal identity may link to a local
account with the same name on many computers, but each PC has its own SID,
agent key, and phone enrollment. Drupal role grants can apply to all enrolled
computers. The service currently reconciles only the local Administrators
group, not arbitrary local groups. The phone app also needs a configured
trusted Drupal PAM origin before it can use a public server address. Keep the
existing Windows PIN/password providers available.

Install only on a Drupal development copy while these flows are built out.
