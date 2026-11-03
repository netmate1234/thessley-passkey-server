# Thessley Passkey — server side (PHP)

**Presentation:** [HTML slides](https://netmate1234.github.io/thessley-presentations/passkey-server/) · source [`docs/index.html`](docs/index.html)


The PHP half of **Thessley Passkey Login**: sign in with a phone app (QR code
or tap) instead of, or on top of, a password. Extracted from the Thessley
Security Hardening WordPress plugin and its Drupal port.

| Path | What it is |
|---|---|
| `PROTOCOL.md` | The wire protocol — start here if you are building a client (e.g. iOS). |
| `wordpress/passkey-login/` | The WordPress module (reference implementation). Needs the plugin's helper functions (`thessley_client_ip`, `thessley_log_event`, `Thessley_UI`), so it is read-only reference here, not runnable on its own. |
| `wordpress/assets/` | QR code renderer (SVG) and the bundled MIT-licensed `qrcode-generator`. |
| `drupal/thessley_passkey/` | Standalone Drupal 10.3 / 11 module (see its own README). |
| `tests/` | `passkey-login*-checks.php` (WordPress, run with WP-CLI on a dev site) and `drupal-passkey-checks.php` (end-to-end over HTTP against a Drupal **sandbox**). Never run these against a live site. |

The two servers behave the same for the app. They differ only in the login
page around it: in "app only" mode WordPress asks for the username first and
falls back to the password form for an account with no device, while Drupal
hides the password form and keeps `?thessley_password=1` as the way back to it.

Both servers can also verify that a key lives in a **TPM 2.0 chip** (optional, see the end of
`PROTOCOL.md`); the Intel root certificate for that ships next to each module in `tpm-roots/`.

Start with `PROTOCOL.md`, then `wordpress/passkey-login/class-crypto.php`
(the signed string and verification) and `module.php` (the endpoints). The
Drupal module is the cleaner, self-contained version of the same logic.

## License

GPL-2.0-or-later, like the WordPress plugin they come from. The bundled
QR library keeps its own MIT license (`wordpress/assets/vendor/`).
