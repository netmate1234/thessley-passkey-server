<?php
/**
 * Behavioural checks for Passkey Login's "Username prompt" option
 * (thessley_passkey_identify). Needs a real WordPress — run it on a DEV site:
 *
 *   wp --path=/var/www/<dev-site> eval-file tests/passkey-login-identify-checks.php
 *
 * It signs real approvals with freshly generated EC P-256 keys, so the whole
 * start -> respond path (including signature verification) is exercised.
 *
 * Safe next to a live unwantedip key / Telegram bot: the first thing it does
 * is short-circuit every outbound HTTP request. It creates two throwaway
 * users and removes everything it created (users, devices, request rows,
 * transients) and restores the module's two options at the end.
 */
add_filter( 'pre_http_request', function () { return new WP_Error( 'x', 'blocked in test' ); } ); // nothing may leave this box.

require_once ABSPATH . 'wp-admin/includes/user.php';
global $wpdb;

$ip = '8.8.4.4';
$_SERVER['REMOTE_ADDR'] = $ip;
ob_start(); // the start endpoint sets a cookie; keep the CLI from complaining about headers

$saved_mode     = get_option( 'thessley_passkey_mode', null );
$saved_identify = get_option( 'thessley_passkey_identify', null );

$bad = 0;
$ok  = function ( $name, $cond ) use ( &$bad ) {
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	if ( ! $cond ) {
		++$bad;
	}
};

// --- fixtures ---------------------------------------------------------
$ua = wp_insert_user( array( 'user_login' => 'pkt_a', 'user_pass' => wp_generate_password(), 'user_email' => 'pkt_a@example.invalid', 'role' => 'subscriber' ) );
$ub = wp_insert_user( array( 'user_login' => 'pkt_b', 'user_pass' => wp_generate_password(), 'user_email' => 'pkt_b@example.invalid', 'role' => 'subscriber' ) );

$make_device = function ( $user_id ) {
	$key     = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
	$details = openssl_pkey_get_details( $key );
	$pub_b64 = base64_encode( (string) base64_decode( preg_replace( '/-----(BEGIN|END) PUBLIC KEY-----|\s+/', '', $details['key'] ) ) );
	return array( 'key' => $key, 'cred' => Thessley_Passkey_Store::add_passkey( $user_id, $pub_b64, 'ES256', 'test' ) );
};
$dev_a = $make_device( $ua );
$dev_b = $make_device( $ub );

$request_ids = array();
$start = function ( $username = null ) use ( &$request_ids ) {
	$req = new WP_REST_Request( 'POST', '/thessley/v1/passkey/login/start' );
	if ( null !== $username ) {
		$req->set_param( 'username', $username );
	}
	$res = Thessley_Module_Passkey_Login::rest_login_start( $req );
	if ( ! is_wp_error( $res ) ) {
		$data          = $res->get_data();
		$request_ids[] = $data['request_id'];
		return $data;
	}
	return $res;
};
$respond = function ( $request_id, $dev, $action = 'approve' ) {
	$row = Thessley_Passkey_Store::get_request( $request_id );
	$ts  = time();
	openssl_sign( Thessley_Passkey_Crypto::canonical_string( $row->type, $request_id, home_url(), $row->nonce, $ts, $action ), $sig, $dev['key'], OPENSSL_ALGO_SHA256 );
	$req = new WP_REST_Request( 'POST', '/thessley/v1/passkey/login/' . $request_id . '/respond' );
	$req->set_param( 'id', $request_id );
	$req->set_param( 'credential_id', $dev['cred'] );
	$req->set_param( 'action', $action );
	$req->set_param( 'timestamp', $ts );
	$req->set_param( 'signature', base64_encode( $sig ) );
	return Thessley_Module_Passkey_Login::rest_login_respond( $req );
};
$code     = function ( $res ) { return is_wp_error( $res ) ? $res->get_error_code() : 'ok'; };
$status   = function ( $request_id ) { return Thessley_Passkey_Store::get_request( $request_id )->status; };
$requester = function ( $request_id ) { return Thessley_Passkey_Store::get_request( $request_id )->requester_user_id; };
$param    = function ( $app_link, $name ) { parse_str( (string) wp_parse_url( $app_link, PHP_URL_QUERY ), $q ); return $q[ $name ] ?? null; };

// === optional mode, username prompt ON ==================================
update_option( 'thessley_passkey_mode', 'optional' );
update_option( 'thessley_passkey_identify', 1 );
echo "== optional + username prompt\n";
$ok( 'identify() is on', Thessley_Module_Passkey_Login::identify() );

$res = $start();
$ok( 'start without a username is refused (400)', is_wp_error( $res ) && 400 === $res->get_error_data()['status'] );
$res = $start( '   ' );
$ok( 'start with a blank username is refused', is_wp_error( $res ) );

$known   = $start( 'pkt_a' );
$unknown = $start( 'nobody_here_xyz' );
$ok( 'known username: request is bound to that account', (int) $requester( $known['request_id'] ) === $ua );
$ok( 'unknown username: bound to account 0 (no device can ever match)', '0' === (string) $requester( $unknown['request_id'] ) );
$ok( 'unknown username gets the same response shape as a real one', array_keys( $known ) === array_keys( $unknown ) && $known['expires_in'] === $unknown['expires_in'] );
$ok( 'link carries the typed username (known)', 'pkt_a' === $param( $known['app_link'], 'username' ) );
$ok( 'link carries the typed username (unknown)', 'nobody_here_xyz' === $param( $unknown['app_link'], 'username' ) );
$ok( 'link is still a login-type request (the app understands it unchanged)', 'login' === $param( $known['app_link'], 'type' ) );

$by_email = $start( 'pkt_a@example.invalid' );
$ok( 'an email address resolves to the account', (int) $requester( $by_email['request_id'] ) === $ua );
$ok( 'the email is echoed as typed, not turned into the username (no email -> username leak)', 'pkt_a@example.invalid' === $param( $by_email['app_link'], 'username' ) );

$upper = $start( 'PKT_A' );
$ok( 'username match is case-insensitive like WordPress login', (int) $requester( $upper['request_id'] ) === $ua );

echo "== who may approve\n";
$r = $start( 'pkt_a' );
$mismatch = $respond( $r['request_id'], $dev_b );
$ok( "another account's device is refused (403 wrong account)", 'thessley_wrong_account' === $code( $mismatch ) );
$ok( '...and the request stays pending', 'pending' === $status( $r['request_id'] ) );
$ok( "the account's own device is accepted", 'ok' === $code( $respond( $r['request_id'], $dev_a ) ) );
$ok( '...and the request is approved for that account', 'approved' === $status( $r['request_id'] ) && (int) Thessley_Passkey_Store::get_request( $r['request_id'] )->approver_user_id === $ua );

$r        = $start( 'nobody_here_xyz' );
$unknown_a = $respond( $r['request_id'], $dev_a );
$ok( 'unknown-username request cannot be approved by any device (A)', 'thessley_wrong_account' === $code( $unknown_a ) );
$ok( 'unknown-username request cannot be approved by any device (B)', 'thessley_wrong_account' === $code( $respond( $r['request_id'], $dev_b ) ) );
$ok(
	'a real mismatch and an unknown name get the identical answer (code, message, HTTP status)',
	$mismatch->get_error_code() === $unknown_a->get_error_code()
		&& $mismatch->get_error_message() === $unknown_a->get_error_message()
		&& $mismatch->get_error_data() === $unknown_a->get_error_data()
);

$r = $start( 'pkt_a' );
$ok( "the account's own device can also deny", 'ok' === $code( $respond( $r['request_id'], $dev_a, 'deny' ) ) && 'denied' === $status( $r['request_id'] ) );

// === required mode, username prompt ON ==================================
update_option( 'thessley_passkey_mode', 'required' );
echo "== app only + username prompt\n";
$ok( 'identify() is on in required mode', Thessley_Module_Passkey_Login::identify() );
$r = $start( 'pkt_b' );
$ok( 'bound to pkt_b', (int) $requester( $r['request_id'] ) === $ub );
$ok( "pkt_a's device cannot log in as pkt_b", 'thessley_wrong_account' === $code( $respond( $r['request_id'], $dev_a ) ) );
$ok( "pkt_b's own device can", 'ok' === $code( $respond( $r['request_id'], $dev_b ) ) );

// === username prompt OFF (original anonymous behaviour) =================
update_option( 'thessley_passkey_mode', 'optional' );
update_option( 'thessley_passkey_identify', 0 );
echo "== optional, username prompt OFF (unchanged behaviour)\n";
$ok( 'identify() is off', ! Thessley_Module_Passkey_Login::identify() );
$r = $start( 'pkt_a' ); // a username sent anyway must be ignored
$ok( 'request is anonymous (no requester)', null === $requester( $r['request_id'] ) );
$ok( 'no username in the link', null === $param( $r['app_link'], 'username' ) );
$ok( 'any enrolled device may approve (whichever approves identifies)', 'ok' === $code( $respond( $r['request_id'], $dev_b ) ) && (int) Thessley_Passkey_Store::get_request( $r['request_id'] )->approver_user_id === $ub );
$r = $start();
$ok( 'start without a username works', ! is_wp_error( $r ) );

// === 2fa mode ignores the option ========================================
update_option( 'thessley_passkey_mode', '2fa' );
update_option( 'thessley_passkey_identify', 1 );
echo "== password, then app (option ignored)\n";
$ok( 'identify() is off even though the option is saved', ! Thessley_Module_Passkey_Login::identify() );
$r = $start( 'pkt_a' );
$ok( 'start still makes an anonymous request', ! is_wp_error( $r ) && null === $requester( $r['request_id'] ) );
$ok( 'an anonymous approval is still refused for 2fa accounts', 'thessley_2fa_required' === $code( $respond( $r['request_id'], $dev_a ) ) );

// --- cleanup ------------------------------------------------------------
foreach ( $request_ids as $id ) {
	$wpdb->delete( Thessley_Passkey_Store::requests_table(), array( 'request_id' => $id ) );
	delete_transient( 'thessley_pk_bt_' . $id );
}
$wpdb->delete( Thessley_Passkey_Store::passkeys_table(), array( 'user_id' => $ua ) );
$wpdb->delete( Thessley_Passkey_Store::passkeys_table(), array( 'user_id' => $ub ) );
wp_delete_user( $ua );
wp_delete_user( $ub );
delete_transient( 'thessley_pk_rl_login_start_' . md5( $ip ) );
$ev = thessley_events_table();
$wpdb->query( $wpdb->prepare( "DELETE FROM $ev WHERE ip=%s", $ip ) );
foreach ( array( 'thessley_passkey_mode' => $saved_mode, 'thessley_passkey_identify' => $saved_identify ) as $opt => $val ) {
	null === $val ? delete_option( $opt ) : update_option( $opt, $val );
}
ob_end_flush();

echo 'leftover test users: ' . (int) ( username_exists( 'pkt_a' ) || username_exists( 'pkt_b' ) ) . "\n";
echo 'leftover test devices: ' . (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Thessley_Passkey_Store::passkeys_table() . ' WHERE label=%s', 'test' ) ) . "\n";
echo $bad ? "$bad FAILED\n" : "ALL PASS\n";
