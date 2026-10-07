<?php
/**
 * Behavioural checks for the Passkey Login module. Needs a real WordPress
 * (it exercises the live early-gate helpers and DB), so run it on a DEV site:
 *
 *   wp --path=/var/www/<dev-site> eval-file tests/passkey-login-checks.php
 *
 * Safe to run next to a live unwantedip key: the very first thing it does is
 * short-circuit every outbound HTTP request (pre_http_request), so nothing
 * can be reported to unwantedip or Telegram; it uses a throwaway public IP,
 * and it deletes every row and transient it creates.
 *
 * What it pins down:
 *  - passkey-login events are never published to unwantedip (they are about
 *    the site's own users/phones, not hostile traffic), while a genuine
 *    attack signature still is (the control case);
 *  - the device-list HTML survives its wp_kses allow-list unchanged, with the
 *    Revoke button's data-* attributes intact, and active content is stripped;
 *  - the browser-binding cookie check still accepts only the right token.
 */
// FIRST line of defence: nothing may leave this box.
$captured = array();
add_filter( 'pre_http_request', function ( $pre, $args, $url ) use ( &$captured ) { $captured[] = array( $url, $args['body'] ?? '' ); return new WP_Error( 'x', 'blocked in test' ); }, 10, 3 );

global $wpdb; $ev = thessley_events_table();
$ip = '8.8.4.4'; $_SERVER['REMOTE_ADDR'] = $ip;
$bad = 0; $ok = function ( $name, $cond ) use ( &$bad ) { echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . "\n"; if ( ! $cond ) { $bad++; } };

echo "== unwantedip reporting\n";
foreach ( array( 'password_login_blocked', 'signature_invalid', 'anonymous_login_blocked', 'login_csrf_blocked' ) as $e ) {
	$captured = array();
	thessley_log_event( 'passkey-login', $e, 'blocked', 'test' );
	$ok( "passkey-login:$e NOT reported", empty( $captured ) );
}
$captured = array();
thessley_log_event( 'query-guard', 'path_credential_file_probe', 'blocked', 'path: /.aws/credentials' );
$ok( 'control: a real attack signature IS still reported', ! empty( $captured ) );
$ev_rows = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $ev WHERE module='passkey-login' AND ip=%s", $ip ) );
$ok( 'passkey events still land in the Event Log (4 rows)', 4 === $ev_rows );
foreach ( array( 'passkey-login|password_login_blocked', 'passkey-login|signature_invalid', 'passkey-login|anonymous_login_blocked', 'passkey-login|login_csrf_blocked', 'query-guard|path_credential_file_probe' ) as $k ) {
	list( $m, $e ) = explode( '|', $k ); delete_transient( 'thessley_uip_lock_' . md5( $ip . '|' . $m . '|' . $e ) );
}
$wpdb->query( $wpdb->prepare( "DELETE FROM $ev WHERE ip=%s", $ip ) );

echo "== device list markup survives the kses allow-list\n";
wp_set_current_user( 1 ); // the Revoke button only renders for a logged-in viewer
$cred = Thessley_Passkey_Store::add_passkey( 1, 'AAAA', 'ES256', 'Test <b>phone</b>' );
$row  = Thessley_Passkey_Store::get_passkey_row_id( $cred );
Thessley_Passkey_Store::set_attestation_level( $row, 'tee' );
$m = new ReflectionMethod( 'Thessley_Module_Passkey_Login', 'render_devices_list_html' ); $m->setAccessible( true );
$raw = $m->invoke( null, get_userdata( 1 ) );
$am = new ReflectionMethod( 'Thessley_Module_Passkey_Login', 'devices_list_allowed_html' ); $am->setAccessible( true );
$kses = wp_kses( $raw, $am->invoke( null ) );
$norm = function ( $h ) { return preg_replace( '/\s+/', ' ', trim( $h ) ); };
$ok( 'allow-list output is identical to the raw markup (nothing legitimate stripped)', $norm( $raw ) === $norm( $kses ) );
$ok( 'revoke button keeps its data-id / data-user-id / data-nonce', false !== strpos( $kses, 'data-id=' ) && false !== strpos( $kses, 'data-user-id=' ) && false !== strpos( $kses, 'data-nonce=' ) && false !== strpos( $kses, 'thessley-pk-revoke-btn' ) );
$ok( 'badges keep their dashicons spans', false !== strpos( $kses, 'dashicons' ) && false !== strpos( $kses, 'thessley-badge' ) );
$evil = wp_kses( $raw . '<script>alert(1)</script><img src=x onerror=alert(1)><button onclick="x()">b</button>', $am->invoke( null ) );
$ok( 'script/img/onclick are stripped', false === strpos( $evil, '<script' ) && false === strpos( $evil, '<img' ) && false === strpos( $evil, 'onclick' ) );

echo "== moved query\n";
$ok( 'get_credential_string_for_row() round-trips', $cred === Thessley_Passkey_Store::get_credential_string_for_row( $row ) );
$wpdb->delete( Thessley_Passkey_Store::passkeys_table(), array( 'id' => $row ) );

echo "== browser-binding cookie (unslash + sanitize)\n";
$bm = new ReflectionMethod( 'Thessley_Module_Passkey_Login', 'browser_matches_request' ); $bm->setAccessible( true );
$token = bin2hex( random_bytes( 16 ) );
set_transient( 'thessley_pk_bt_testreq', $token, 60 );
$_COOKIE['thessley_pk_bt'] = $token;
$ok( 'matching cookie accepted', $bm->invoke( null, 'testreq' ) );
$_COOKIE['thessley_pk_bt'] = $token . 'x';
$ok( 'wrong cookie rejected', ! $bm->invoke( null, 'testreq' ) );
unset( $_COOKIE['thessley_pk_bt'] );
$ok( 'missing cookie rejected', ! $bm->invoke( null, 'testreq' ) );
delete_transient( 'thessley_pk_bt_testreq' );

echo "== settings sanitising\n";
$ok( "sanitize_key keeps '2fa' and 'required'", '2fa' === sanitize_key( '2fa' ) && 'required' === sanitize_key( 'required' ) );

echo "leftover rows: " . (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $ev WHERE ip=%s", $ip ) ) . "\n";
echo $bad ? "$bad FAILED\n" : "ALL PASS\n";
