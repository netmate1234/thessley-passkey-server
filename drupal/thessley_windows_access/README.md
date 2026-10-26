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

The first pilot should bind the existing `.190` Windows account `sshuser` to a
low-privilege Drupal test user with the same name. Create that active Drupal
user through the site's normal user administration; the module deliberately
does not create a Drupal user or set its password. Assign it the
`Windows Login Test` role and grant that role only `Windows sign-in` on the
`.190` computer resource. Enrolling a machine creates its own resource named
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

## Not ready for deployment

This is still a local development slice, not a deployable Windows login
service. No Windows agent calls these routes yet; machine-wide account
inventory, local-admin membership reconciliation, audit UI, and
rollback-safe installation remain to be built. The phone app also needs a
configured trusted Drupal PAM origin before it can use a public server
address. Keep the existing Windows PIN/password providers available.

Install only on a Drupal development copy while these flows are built out.
