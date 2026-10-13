# Thessley Passkey protocol (v1)

A BankID-style login: a phone app holding a hardware-backed key approves a
login or an enrolment that the website started. The site shows a QR code (or a
same-device link); the app signs the request; the browser that started it is
logged in. Both server implementations in this repo (WordPress, Drupal) speak
exactly this, and the Android app talks to either unchanged.

## Keys and signatures

* Key: EC **P-256**, generated in the phone's secure hardware (Android
  Keystore / iOS Secure Enclave), private key never leaves it, every signature
  gated by a fresh biometric check.
* Public key on the wire: **base64 (standard, not url-safe) of the DER
  SubjectPublicKeyInfo**.
* Signature: **ECDSA with SHA-256**, **DER-encoded** (r,s), base64 (standard).
* Signed message — UTF-8 bytes of seven fields joined with `|`:

```
thessley_passkey_v1|<type>|<request_id>|<origin>|<nonce>|<timestamp>|<action>
```

| field | value |
|---|---|
| type | `login`, `2fa` or `enroll` (from the link) |
| request_id, nonce | from the link; 43-char base64url |
| origin | the site's own URL exactly as in the link (`origin=`), no trailing slash |
| timestamp | unix seconds; server accepts ±60 s |
| action | `approve` or `deny` (login/2fa); `register` (enroll) |

The server builds the same string using **its own** origin, never a
client-supplied one, so a QR relayed from another site (phishing) can never
verify: the app should show the origin from the link and refuse anything
that is not an origin the user enrolled with.

## The link / QR payload

```
thessleypasskey://auth?type=login&id=<request_id>&nonce=<nonce>&origin=<url>[&ip=<ip>][&country=<label>][&username=<name>]
```

Query-string encoded. `ip`/`country` are the requester's address, shown on the
approval screen so a user can spot a relayed request. `username` is present for
`2fa` (and for a login started with the username prompt) so the app can pick
the right enrolled device for that account.

## Endpoints

Base: `{origin}/thessley/v1/passkey` (Drupal; WordPress with pretty permalinks
is `{origin}/wp-json/thessley/v1/passkey`). Both servers also accept the
WordPress fallback form the Android app uses everywhere:
`{origin}/?rest_route=/thessley/v1/passkey{path}`. Bodies are JSON.

| | Request | Success response |
|---|---|---|
| `POST /login/start` | `{}` (or `{"username": "…"}` when the site asks for one) — **made by the browser, not the app** | `{request_id, nonce, ip, expires_in, url, app_link}` |
| `GET /login/{id}/status` | — (browser polls) | `{status: pending\|approved\|denied\|expired[, redirect_to]}` |
| `POST /login/{id}/respond` | `{credential_id, action, timestamp, signature}` | `{result: "ok"}` |
| `POST /enroll/start` | logged-in browser only | `{request_id, nonce, ip, expires_in, url, app_link}` |
| `POST /enroll/{id}/respond` | `{public_key, algorithm: "ES256", label, timestamp, proof_signature, attestation_chain: [base64 DER certs, leaf first]}` | `{result: "ok", credential_id, username}` |

`2fa` requests use the same `/login/{id}/status` and `/login/{id}/respond`
with `type=2fa` in the signed string.

Browser-side extras the app never sees or needs: the WordPress server also
returns `has_device` from `login/start` in app-only mode (so the login page can
show the password form instead of a QR for an account with no phone yet; an
unknown username looks the same as "no device", so it reveals nothing). A client
should ignore response fields it does not know.

Errors: HTTP status 4xx and a body `{code, message, data: {status}}`. Codes the
app may see: `thessley_expired` (409), `thessley_already_resolved` (409),
`thessley_stale` (401, clock off), `thessley_unknown_device` (401),
`thessley_bad_signature` (401), `thessley_wrong_account` (403),
`thessley_2fa_required` (403), `thessley_bad_request` (400),
`thessley_rate_limited` (429).

## Enrolment

1. Logged-in user starts enrolment in the browser → QR with `type=enroll`.
2. The app generates a **new** key pair and signs the canonical string with
   `type=enroll`, `action=register` using the *new* private key
   (`proof_signature`): proof of possession.
3. The server verifies, stores the public key, answers with the
   server-assigned `credential_id` and the account's `username`. The app must
   store both against this origin — every later `respond` needs `credential_id`.
4. The attestation chain (Android Key Attestation) is verified for visibility
   only (`software` / `tee` / `strongbox`); enrolment is never rejected on it.

## Optional: TPM hardware attestation

A client whose signing key lives in a **TPM 2.0** chip can prove it, and the site then records the device
as `tpm` ("TPM 2.0 hardware") instead of unverified. It adds one endpoint and one optional field; nothing
else changes, and a failed proof **never rejects an enrolment**.

1. `POST /enroll/{id}/tpm-challenge` with
   `{ "ek_certs": [base64 DER, leaf first], "ak_public": base64 TPMT_PUBLIC }`.
   `ek_certs` is the chip's endorsement-key (EK) certificate and its intermediates. `ak_public` is a fresh
   **attestation key** (AK): ECC P-256, ECDSA/SHA-256, restricted signing, fixed to the chip.
   The site verifies the EK chain against its trusted manufacturer roots and answers
   `{ "credential_blob": base64 TPM2B_ID_OBJECT, "secret": base64 TPM2B_ENCRYPTED_SECRET }`:
   a random secret encrypted to the EK and bound to the AK's name (TPM2_MakeCredential).
2. The client runs TPM2_ActivateCredential (only a chip holding both the EK and the AK can) and
   TPM2_Certify: the AK certifies the signing key with qualifying data = the enrolment `nonce` (its UTF-8 bytes).
3. `POST /enroll/{id}/respond` as usual, plus
   ```
   "tpm": { "ak_public": b64 TPMT_PUBLIC, "activated_secret": b64, "certify_info": b64 TPMS_ATTEST,
            "certify_signature": b64 TPMT_SIGNATURE, "key_public": b64 TPMT_PUBLIC of the signing key }
   ```
   The response gains `"attestation": "tpm"` when it verified (otherwise `""`).

The site checks: the EK certificate chains to a trusted root (EK key ECC P-256); the activation secret
comes back (so the AK and the EK are in the same chip); the AK is a restricted, fixed signing key; the
certification signature verifies, is bound to this enrolment's nonce and names the submitted key; and the
certified key is `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, a plain (unrestricted) signing key.

Not checked: revocation lists and firmware security. Trust anchors are PEM files in `tpm-roots/` next to
the module (Intel's On-Die CA root ships; add a maker's root to trust that maker). Reference client:
the Thessley Passkey desktop app for Linux. Reference verifier: `wordpress/passkey-login/class-tpm.php` and
`drupal/thessley_passkey/src/Tpm.php`.

## Login rules the server enforces

* A request is single-use and short-lived (120 s). The first valid
  `respond` wins; the browser that started it collects the session once.
* A request that already names an account (2fa, or a login with the username
  prompt) can only be approved by that account's own devices. An unknown
  username gets an identical-looking request that nothing can approve.
* An anonymous (`login`) approval can never finish a login for an account
  whose mode is "password, then app" — the password step must happen first.
* Only the browser that called `login/start` receives the session (a cookie
  binds it), so a request id forced into someone else's browser is useless.

For an iOS or other client, only the app side is needed: parse the link, show
the origin/IP, sign with the Secure Enclave key after biometrics, `POST` to
`respond`. Reference implementations of the server side are under
`wordpress/passkey-login/` and `drupal/thessley_passkey/`.
