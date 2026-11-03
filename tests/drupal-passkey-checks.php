<?php
/**
 * End-to-end checks for the Drupal module infra/thessley_passkey, driven over
 * real HTTP exactly the way the Android app and a browser talk to it
 * (including the ?rest_route= request shape, real EC P-256 signatures, real
 * cookies and the real login form).
 *
 *   BASE=http://127.0.0.1:10190 SSH_HOST=192.168.1.200 DRUPAL_DIR='~/drupal-sandbox' \
 *     php tests/drupal-passkey-checks.php
 *
 * (BASE is where this machine reaches the sandbox's web server; drush runs on
 * SSH_HOST inside DRUPAL_DIR.)
 *
 * RUN IT AGAINST A SANDBOX, NEVER A LIVE SITE: it creates users pkt_a, pkt_b,
 * pkt_c and a role, flips the module's mode, and removes everything it made
 * (users, role, devices, request rows, flood rows) and restores the settings
 * at the end. The sandbox needs the module enabled and a role
 * "passkey_user" is created/removed by this script.
 */

$base  = rtrim( getenv( 'BASE' ) ?: 'http://127.0.0.1:10190', '/' );
$ssh   = getenv( 'SSH_HOST' ) ?: '192.168.1.200';
$dir   = getenv( 'DRUPAL_DIR' ) ?: '~/drupal-sandbox';

$bad = 0;
function ok( $name, $cond, $extra = '' ) {
	global $bad;
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . ( $cond ? '' : ( $extra !== '' ? "  [$extra]" : '' ) ) . "\n";
	if ( ! $cond ) {
		++$bad;
	}
}
function drush( $args ) {
	global $ssh, $dir;
	// One remote command line, quoted once for the remote shell.
	return trim( (string) shell_exec( 'ssh ' . escapeshellarg( $ssh ) . ' ' . escapeshellarg( 'cd ' . $dir . ' && vendor/bin/drush ' . $args ) . ' 2>&1' ) );
}
/** Runs through Drupal's own database layer (the sqlite sandbox needs its custom collations). SELECT returns the first column of the first row. */
function sql( $q ) {
	$php = '$q = base64_decode("' . base64_encode( $q ) . '"); $r = \\Drupal::database()->query($q); if (preg_match("/^\\s*select/i", $q)) { $v = $r->fetchField(); echo $v === false ? "" : $v; }';
	return drush( 'php:eval ' . escapeshellarg( $php ) );
}
function setcfg( $mode, $identify ) {
	drush( 'config:set thessley_passkey.settings mode ' . $mode . ' -y' );
	drush( 'config:set thessley_passkey.settings identify ' . ( $identify ? 'true' : 'false' ) . ' --input-format=yaml -y' ); // yaml: a real boolean, not the string "false"

}
function clear_flood() {
	sql( "DELETE FROM flood WHERE event LIKE 'thessley_passkey%'" );
}

/** A browser: its own cookie jar. */
class Browser {
	public $jar = array();
	public function request( $method, $url, $headers = array(), $body = null ) {
		$ch = curl_init( $url );
		curl_setopt_array( $ch, array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => true,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_TIMEOUT        => 30,
		) );
		$h = $headers;
		if ( $this->jar ) {
			$pairs = array();
			foreach ( $this->jar as $k => $v ) {
				$pairs[] = $k . '=' . $v;
			}
			$h[] = 'Cookie: ' . implode( '; ', $pairs );
		}
		curl_setopt( $ch, CURLOPT_HTTPHEADER, $h );
		if ( null !== $body ) {
			curl_setopt( $ch, CURLOPT_POSTFIELDS, $body );
		}
		$raw  = curl_exec( $ch );
		$size = curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
		$code = curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
		curl_close( $ch );
		$head = substr( (string) $raw, 0, $size );
		$text = substr( (string) $raw, $size );
		foreach ( preg_split( '/\r\n/', $head ) as $line ) {
			if ( stripos( $line, 'set-cookie:' ) === 0 ) {
				$c = trim( substr( $line, 11 ) );
				list( $pair ) = explode( ';', $c, 2 );
				list( $k, $v ) = array_pad( explode( '=', $pair, 2 ), 2, '' );
				if ( preg_match( '/expires=.*1970|max-age=0/i', $c ) ) {
					unset( $this->jar[ $k ] );
				} else {
					$this->jar[ $k ] = $v;
				}
			}
		}
		$loc = '';
		if ( preg_match( '/^location:\s*(.+)$/mi', $head, $m ) ) {
			$loc = trim( $m[1] );
		}
		return array( 'code' => $code, 'body' => $text, 'json' => json_decode( $text, true ), 'loc' => $loc, 'head' => $head );
	}
	public function logged_in_uid() {
		global $base;
		$r = $this->request( 'GET', $base . '/user' );
		return preg_match( '#/user/(\d+)#', $r['loc'], $m ) ? (int) $m[1] : 0;
	}
	/** Real form login. Returns the response of the POST. */
	public function form_login( $name, $pass ) {
		global $base;
		$page = $this->request( 'GET', $base . '/user/login' );
		preg_match( '/name="form_build_id" value="([^"]+)"/', $page['body'], $b );
		return $this->request( 'POST', $base . '/user/login', array( 'Content-Type: application/x-www-form-urlencoded' ), http_build_query( array(
			'name' => $name, 'pass' => $pass, 'form_build_id' => $b[1] ?? '', 'form_id' => 'user_login_form', 'op' => 'Log in',
		) ) );
	}
}

/** The way the Android app builds a URL. */
function app_url( $path ) {
	global $base;
	return $base . '/?rest_route=' . rawurlencode( '/thessley/v1/passkey' . $path );
}
function app_post( Browser $b, $path, $data ) {
	return $b->request( 'POST', app_url( $path ), array( 'Content-Type: application/json; charset=utf-8' ), json_encode( $data ) );
}
function app_get( Browser $b, $path ) {
	return $b->request( 'GET', app_url( $path ) );
}
/** Straight path form (what a browser's own fetch() uses). */
function web_post( Browser $b, $path, $data, $headers = array() ) {
	global $base;
	return $b->request( 'POST', $base . '/thessley/v1/passkey' . $path, array_merge( array( 'Content-Type: application/json' ), $headers ), json_encode( $data ) );
}

function sign( $key, $type, $id, $origin, $nonce, $ts, $action ) {
	openssl_sign( implode( '|', array( 'thessley_passkey_v1', $type, $id, $origin, $nonce, $ts, $action ) ), $sig, $key, OPENSSL_ALGO_SHA256 );
	return base64_encode( $sig );
}
function new_key() {
	$key = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
	$d   = openssl_pkey_get_details( $key );
	return array( $key, base64_encode( base64_decode( preg_replace( '/-----(BEGIN|END) PUBLIC KEY-----|\s+/', '', $d['key'] ) ) ) );
}
function parse_link( $link ) {
	parse_str( (string) parse_url( $link, PHP_URL_QUERY ), $q );
	return $q;
}

$origin = $base; // no override configured: the module derives it from the request.

// ---- fixtures -------------------------------------------------------------
echo "== setup\n";
drush( 'role:create passkey_user "Passkey user"' );
drush( 'role:perm:add passkey_user "use thessley passkey"' );
$pw = array();
foreach ( array( 'pkt_a', 'pkt_b', 'pkt_c' ) as $u ) {
	$pw[ $u ] = 'Pw-' . bin2hex( random_bytes( 6 ) );
	drush( "user:create $u --mail=$u@example.invalid --password=" . escapeshellarg( $pw[ $u ] ) );
	drush( "user:role:add passkey_user $u" );
}
$uid = array();
foreach ( array( 'pkt_a', 'pkt_b', 'pkt_c' ) as $u ) {
	$uid[ $u ] = (int) sql( "SELECT uid FROM users_field_data WHERE name='$u'" );
}
ok( 'fixture users exist', $uid['pkt_a'] > 1 && $uid['pkt_b'] > 1 && $uid['pkt_c'] > 1 );
setcfg( 'optional', false );
clear_flood();

// Enrol devices for a and b through the real flow.
$dev = array();
foreach ( array( 'pkt_a', 'pkt_b' ) as $u ) {
	$br = new Browser();
	$r  = $br->form_login( $u, $pw[ $u ] );
	ok( "form login works in optional mode ($u)", 303 === $r['code'] && $br->logged_in_uid() === $uid[ $u ], $r['code'] . ' ' . $r['loc'] );

	$tok = trim( $br->request( 'GET', $base . '/session/token' )['body'] );
	$r   = web_post( $br, '/enroll/start', array() );
	ok( "enroll/start without CSRF header is refused ($u)", 403 === $r['code'], (string) $r['code'] );
	$anon = web_post( new Browser(), '/enroll/start', array(), array( 'X-CSRF-Token: ' . $tok ) );
	ok( 'enroll/start anonymous is refused', 403 === $anon['code'], (string) $anon['code'] );
	$r = web_post( $br, '/enroll/start', array(), array( 'X-CSRF-Token: ' . $tok ) );
	ok( "enroll/start ok ($u)", 200 === $r['code'] && ! empty( $r['json']['app_link'] ), (string) $r['code'] );
	$e = $r['json'];
	$q = parse_link( $e['app_link'] );
	ok( 'enroll link has type/id/nonce/origin, origin is the site', 'enroll' === $q['type'] && $e['request_id'] === $q['id'] && $e['nonce'] === $q['nonce'] && $origin === $q['origin'], json_encode( $q ) );

	list( $key, $pub ) = new_key();
	$ts   = time();
	$app  = new Browser(); // the phone: no cookies
	$body = array( 'public_key' => $pub, 'algorithm' => 'ES256', 'label' => "phone-$u", 'timestamp' => $ts, 'proof_signature' => sign( $key, 'enroll', $e['request_id'], $origin, $e['nonce'], $ts, 'register' ), 'attestation_chain' => array() );

	$bad_body = $body;
	$bad_body['proof_signature'] = sign( $key, 'enroll', $e['request_id'], 'https://evil.example', $e['nonce'], $ts, 'register' );
	$r = app_post( $app, '/enroll/' . $e['request_id'] . '/respond', $bad_body );
	ok( "enroll with a proof signed for another origin is refused ($u)", 401 === $r['code'] && 'thessley_bad_signature' === ( $r['json']['code'] ?? '' ), $r['body'] );
	$stale = $body;
	$stale['timestamp'] = $ts - 3600;
	$r = app_post( $app, '/enroll/' . $e['request_id'] . '/respond', $stale );
	ok( 'enroll with a stale timestamp is refused', 401 === $r['code'] && 'thessley_stale' === ( $r['json']['code'] ?? '' ), $r['body'] );

	$r = app_post( $app, '/enroll/' . $e['request_id'] . '/respond', $body );
	ok( "enroll respond (rest_route form) ok ($u)", 200 === $r['code'] && 'ok' === ( $r['json']['result'] ?? '' ) && ! empty( $r['json']['credential_id'] ) && $u === ( $r['json']['username'] ?? '' ), $r['body'] );
	$dev[ $u ] = array( 'key' => $key, 'cred' => $r['json']['credential_id'] ?? '' );
	$r2 = app_post( $app, '/enroll/' . $e['request_id'] . '/respond', $body );
	ok( 'the enroll request is single-use (409)', 409 === $r2['code'], $r2['body'] );

	$st = $br->request( 'GET', $base . '/thessley/v1/passkey/enroll/' . $e['request_id'] . '/status' );
	ok( 'enroll status reports approved + label', 'approved' === ( $st['json']['status'] ?? '' ) && "phone-$u" === ( $st['json']['label'] ?? '' ), $st['body'] );
	$other = new Browser();
	$other->form_login( 'pkt_c', $pw['pkt_c'] );
	$st = $other->request( 'GET', $base . '/thessley/v1/passkey/enroll/' . $e['request_id'] . '/status' );
	ok( "another account cannot read someone's enroll request (404)", 404 === $st['code'], (string) $st['code'] );
}

/** One login round trip. Returns [start-response, respond-response]. */
function login_start( Browser $browser, $username = null ) {
	return app_post( $browser, '/login/start', null === $username ? new stdClass() : array( 'username' => $username ) );
}
function respond( $id, $type, $nonce, $cred, $key, $action = 'approve', $o = null, $ts = null ) {
	global $origin;
	$ts = $ts ?? time();
	return app_post( new Browser(), '/login/' . $id . '/respond', array(
		'credential_id' => $cred, 'action' => $action, 'timestamp' => $ts,
		'signature' => sign( $key, $type, $id, $o ?? $origin, $nonce, $ts, $action ),
	) );
}

// ---- optional mode, anonymous -------------------------------------------------
echo "== optional, anonymous login\n";
$br = new Browser();
$s  = login_start( $br );
ok( 'start returns the fields the app decodes', 200 === $s['code'] && isset( $s['json']['request_id'], $s['json']['nonce'], $s['json']['url'], $s['json']['app_link'], $s['json']['expires_in'] ) && 120 === $s['json']['expires_in'], $s['body'] );
ok( 'start binds the browser with an HttpOnly SameSite=Strict cookie', isset( $br->jar['thessley_pk_bt'] ) && stripos( $s['head'], 'thessley_pk_bt' ) !== false && preg_match( '/thessley_pk_bt=[^\r\n]*HttpOnly/i', $s['head'] ) && preg_match( '/thessley_pk_bt=[^\r\n]*SameSite=Strict/i', $s['head'] ) );
ok( 'start response is not cacheable', preg_match( '/cache-control:[^\r\n]*(no-store|no-cache|private)/i', $s['head'] ) === 1 );
$id = $s['json']['request_id'];
$n  = $s['json']['nonce'];
$q  = parse_link( $s['json']['app_link'] );
ok( 'link: type=login, origin is the site, no username', 'login' === $q['type'] && $origin === $q['origin'] && ! isset( $q['username'] ) && ! empty( $q['ip'] ) );
ok( 'link scheme is thessleypasskey://auth', 0 === strpos( $s['json']['app_link'], 'thessleypasskey://auth?' ) );

$st = app_get( $br, "/login/$id/status" );
ok( 'status pending before approval', 'pending' === ( $st['json']['status'] ?? '' ) );

$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'], 'approve', 'https://evil.example' );
ok( 'approval signed for another origin is refused (401)', 401 === $r['code'] && 'thessley_bad_signature' === $r['json']['code'], $r['body'] );
$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'], 'approve', null, time() - 3600 );
ok( 'stale timestamp refused (401)', 401 === $r['code'] && 'thessley_stale' === $r['json']['code'] );
$r = respond( $id, 'login', $n, 'nope' . str_repeat( 'x', 39 ), $dev['pkt_a']['key'] );
ok( 'unknown device refused (401)', 401 === $r['code'] && 'thessley_unknown_device' === $r['json']['code'] );
$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'], 'banana' );
ok( 'invalid action refused (400)', 400 === $r['code'] && 'thessley_bad_request' === $r['json']['code'] );
$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_b']['key'] );
ok( "signature by another account's key refused (401)", 401 === $r['code'] );
$r = respond( $id, 'login', 'AAAA' . $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'a signature over a different nonce is refused (401)', 401 === $r['code'] );

$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'valid approval accepted', 200 === $r['code'] && 'ok' === ( $r['json']['result'] ?? '' ), $r['body'] );
$r = respond( $id, 'login', $n, $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'replayed approval refused (409)', 409 === $r['code'], $r['body'] );

$thief = new Browser();
$st    = app_get( $thief, "/login/$id/status" );
ok( 'a browser that never started it only ever sees pending (login-CSRF guard)', 'pending' === ( $st['json']['status'] ?? '' ) && 0 === $thief->logged_in_uid(), $st['body'] );
$st = app_get( $br, "/login/$id/status" );
ok( 'the starting browser gets approved + redirect', 'approved' === ( $st['json']['status'] ?? '' ) && ! empty( $st['json']['redirect_to'] ), $st['body'] );
ok( 'that browser is now logged in as the approving account', $br->logged_in_uid() === $uid['pkt_a'] );
$st = app_get( $br, "/login/$id/status" );
ok( 'polling again after consumption gives expired (single use)', 'expired' === ( $st['json']['status'] ?? '' ) );
$replay = app_get( $thief, "/login/$id/status" );
ok( 'a captured copy cannot log in a second time', 0 === $thief->logged_in_uid() && 'approved' !== ( $replay['json']['status'] ?? '' ) );

// deny
$br = new Browser();
$s  = login_start( $br );
$r  = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'], 'deny' );
$st = app_get( $br, '/login/' . $s['json']['request_id'] . '/status' );
ok( 'deny works and status says denied', 200 === $r['code'] && 'denied' === ( $st['json']['status'] ?? '' ) && 0 === $br->logged_in_uid() );

// expiry
$br = new Browser();
$s  = login_start( $br );
sql( "UPDATE thessley_passkey_requests SET expires=1 WHERE request_id='" . $s['json']['request_id'] . "'" );
$r  = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
$st = app_get( $br, '/login/' . $s['json']['request_id'] . '/status' );
ok( 'an expired request cannot be approved (409) and reports expired', 409 === $r['code'] && 'expired' === ( $st['json']['status'] ?? '' ) );
$st = app_get( $br, '/login/' . str_repeat( 'z', 43 ) . '/status' );
ok( 'an unknown request id reports expired (no oracle)', 'expired' === ( $st['json']['status'] ?? '' ) );

// rest_route hardening
echo "== rest_route handling\n";
foreach ( array( '/thessley/v1/passkey/../../admin', '/wp/v2/users', '/thessley/v1/passkey/login/start/../../x', '/thessley/v1/passkeyx/login/start', '//thessley/v1/passkey/login/start' ) as $bad_route ) {
	$r = ( new Browser() )->request( 'POST', $base . '/?rest_route=' . rawurlencode( $bad_route ), array( 'Content-Type: application/json' ), '{}' );
	ok( "rest_route=$bad_route is not routed to the API", ! isset( $r['json']['request_id'] ), (string) $r['code'] );
}
$r = ( new Browser() )->request( 'GET', $base . '/?rest_route=' . rawurlencode( '/thessley/v1/passkey/login/start' ) );
ok( 'GET on a POST-only API route is refused (405)', 405 === $r['code'] || 404 === $r['code'], (string) $r['code'] );
$r = web_post( new Browser(), '/login/start', new stdClass() );
ok( 'the plain /thessley/v1/passkey/... path works too', 200 === $r['code'] && ! empty( $r['json']['app_link'] ) );

// ---- identify (username prompt) -----------------------------------------------
echo "== optional + username prompt\n";
clear_flood();
setcfg( 'optional', true );
$s = login_start( new Browser() );
ok( 'start without a username refused (400)', 400 === $s['code'], $s['body'] );
$s = login_start( new Browser(), '   ' );
ok( 'blank username refused', 400 === $s['code'] );
$bk = new Browser(); $known = login_start( $bk, 'pkt_a' );
$unk = login_start( new Browser(), 'nobody_here_xyz' );
$kq = parse_link( $known['json']['app_link'] ); $uq = parse_link( $unk['json']['app_link'] );
ok( 'known + unknown give the same response shape', array_keys( $known['json'] ) === array_keys( $unk['json'] ) && $known['json']['expires_in'] === $unk['json']['expires_in'] );
ok( 'link carries the typed username (known and unknown)', 'pkt_a' === $kq['username'] && 'nobody_here_xyz' === $uq['username'] && 'login' === $kq['type'] );
$by_email = login_start( new Browser(), 'pkt_a@example.invalid' );
ok( 'email echoed as typed (no email -> username leak)', 'pkt_a@example.invalid' === parse_link( $by_email['json']['app_link'] )['username'] );
$upper = login_start( new Browser(), 'PKT_A' );

$r_wrong = respond( $known['json']['request_id'], 'login', $known['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( "another account's device is refused (403 wrong account)", 403 === $r_wrong['code'] && 'thessley_wrong_account' === $r_wrong['json']['code'], $r_wrong['body'] );
ok( '...and the request stays pending', 'pending' === app_get( $bk, '/login/' . $known['json']['request_id'] . '/status' )['json']['status'] );
$r_unk = respond( $unk['json']['request_id'], 'login', $unk['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'unknown username: no device can approve (A)', 403 === $r_unk['code'] && 'thessley_wrong_account' === $r_unk['json']['code'] );
ok( 'a real mismatch and an unknown name give the identical answer', $r_wrong['body'] === $r_unk['body'] && $r_wrong['code'] === $r_unk['code'] );
$ok_r = respond( $known['json']['request_id'], 'login', $known['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( "the account's own device is accepted", 200 === $ok_r['code'] );
$up = respond( $upper['json']['request_id'], 'login', $upper['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'username match is case-insensitive', 200 === $up['code'], $up['body'] );
ok( 'identified login completes in the starting browser', 'approved' === app_get( $bk, '/login/' . $known['json']['request_id'] . '/status' )['json']['status'] && $bk->logged_in_uid() === $uid['pkt_a'] );

setcfg( 'optional', false );
clear_flood();
$s = login_start( new Browser(), 'pkt_a' ); // sent anyway: ignored
ok( 'prompt OFF: a username sent anyway is ignored, request is anonymous', 200 === $s['code'] && ! isset( parse_link( $s['json']['app_link'] )['username'] ) );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( 'prompt OFF: any enrolled device may approve (BankID style)', 200 === $r['code'] );

// ---- required mode ------------------------------------------------------------
echo "== app only\n";
clear_flood();
setcfg( 'required', false );
$page = ( new Browser() )->request( 'GET', $base . '/user/login' );
ok( 'login page hides the password form (class) and carries the QR box', strpos( $page['body'], 'thessley-pk-hidden' ) !== false && strpos( $page['body'], 'thessley-passkey-box' ) !== false );
$page = ( new Browser() )->request( 'GET', $base . '/user/login?thessley_password=1' );
ok( 'the ?thessley_password=1 hatch shows the form', strpos( $page['body'], 'thessley-pk-hidden' ) === false );
$br = new Browser();
$r  = $br->form_login( 'pkt_a', $pw['pkt_a'] );
ok( 'password login refused for an account WITH a device', 200 === $r['code'] && 0 === $br->logged_in_uid() && stripos( $r['body'], 'Password login is disabled' ) !== false );
$br = new Browser();
$r  = $br->form_login( 'pkt_c', $pw['pkt_c'] );
ok( 'password login still works for an account with NO device', 303 === $r['code'] && $br->logged_in_uid() === $uid['pkt_c'] );
$r = ( new Browser() )->request( 'POST', $base . '/user/login?_format=json', array( 'Content-Type: application/json' ), json_encode( array( 'name' => 'pkt_c', 'pass' => $pw['pkt_c'] ) ) );
ok( 'core JSON password login is closed while the app is required', 403 === $r['code'], (string) $r['code'] );
$bk = new Browser(); $s = login_start( $bk );
respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
app_get( $bk, '/login/' . $s['json']['request_id'] . '/status' );
ok( 'app login works in app-only mode', $bk->logged_in_uid() === $uid['pkt_b'] );

echo "== app only + username prompt\n";
setcfg( 'required', true );
$s = login_start( new Browser(), 'pkt_b' );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( "pkt_a's device cannot log in as pkt_b", 403 === $r['code'] );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( "pkt_b's own device can", 200 === $r['code'] );

// ---- 2fa mode -----------------------------------------------------------------
echo "== password, then app\n";
clear_flood();
setcfg( '2fa', true );
$page = ( new Browser() )->request( 'GET', $base . '/user/login' );
ok( '2fa: login page is the plain password form (no QR box)', strpos( $page['body'], 'thessley-passkey-box' ) === false && strpos( $page['body'], 'thessley-pk-hidden' ) === false );
$s = login_start( new Browser(), 'pkt_a' );
ok( '2fa: start still makes an anonymous request (identify ignored)', 200 === $s['code'] && ! isset( parse_link( $s['json']['app_link'] )['username'] ) );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( '2fa: an anonymous approval is refused for a 2fa account (403 thessley_2fa_required)', 403 === $r['code'] && 'thessley_2fa_required' === $r['json']['code'], $r['body'] );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'], 'deny' );
ok( '2fa: deny is still accepted', 200 === $r['code'] );
$r = ( new Browser() )->request( 'POST', $base . '/user/login?_format=json', array( 'Content-Type: application/json' ), json_encode( array( 'name' => 'pkt_a', 'pass' => $pw['pkt_a'] ) ) );
ok( '2fa: core JSON password login is closed', 403 === $r['code'], (string) $r['code'] );

$br = new Browser();
$r  = $br->form_login( 'pkt_a', 'wrong-password' );
ok( '2fa: a wrong password gets the normal error and no request', 200 === $r['code'] && 0 === $br->logged_in_uid() );
$r = $br->form_login( 'pkt_a', $pw['pkt_a'] );
ok( '2fa: right password redirects to the confirm page, NOT logged in', in_array( $r['code'], array( 302, 303 ), true ) && preg_match( '#/thessley-auth/2fa/([A-Za-z0-9_-]+)#', $r['loc'], $m ) && 0 === $br->logged_in_uid(), $r['code'] . ' ' . $r['loc'] );
$id2 = $m[1] ?? '';
$page = $br->request( 'GET', $base . '/thessley-auth/2fa/' . $id2 );
ok( '2fa: the confirm page renders with the QR container', 200 === $page['code'] && strpos( $page['body'], 'thessley-pk-confirm-qr' ) !== false && strpos( $page['body'], 'thessleypasskey:\\/\\/auth' ) !== false ); // drupalSettings JSON escapes slashes
$nonce2 = sql( "SELECT nonce FROM thessley_passkey_requests WHERE request_id='$id2'" );
$req2   = sql( "SELECT requester_uid FROM thessley_passkey_requests WHERE request_id='$id2'" );
ok( '2fa: the request is bound to the account', (int) $req2 === $uid['pkt_a'] );
$r = respond( $id2, '2fa', $nonce2, $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( "2fa: another account's device cannot confirm (403)", 403 === $r['code'] && 'thessley_wrong_account' === $r['json']['code'] );
$st = app_get( $br, "/login/$id2/status" );
ok( '2fa: still pending, still logged out', 'pending' === $st['json']['status'] && 0 === $br->logged_in_uid() );
$r = respond( $id2, '2fa', $nonce2, $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( '2fa: own device confirms', 200 === $r['code'] );
$stolen = new Browser();
$st = app_get( $stolen, "/login/$id2/status" );
ok( '2fa: another browser cannot collect the session', 'pending' === $st['json']['status'] && 0 === $stolen->logged_in_uid() );
$st = app_get( $br, "/login/$id2/status" );
ok( '2fa: the password browser is logged in after confirmation', 'approved' === $st['json']['status'] && $br->logged_in_uid() === $uid['pkt_a'] );
$page = ( new Browser() )->request( 'GET', $base . '/thessley-auth/2fa/' . $id2 );
ok( '2fa: a used request page is gone (410)', 410 === $page['code'] || 200 !== $page['code'], (string) $page['code'] );
$r = ( new Browser() )->request( 'GET', $base . '/thessley-auth/2fa/' . str_repeat( 'q', 43 ) );
ok( '2fa: an unknown confirm page is 410', 410 === $r['code'], (string) $r['code'] );

$br = new Browser();
$r  = $br->form_login( 'pkt_c', $pw['pkt_c'] );
ok( '2fa: an account with no device still logs in with its password', 303 === $r['code'] && $br->logged_in_uid() === $uid['pkt_c'] );

// ---- devices, revoke, permission, blocked ------------------------------------------
echo "== devices\n";
clear_flood();
setcfg( 'optional', false );
$br  = new Browser();
$br->form_login( 'pkt_a', $pw['pkt_a'] );
$tok = trim( $br->request( 'GET', $base . '/session/token' )['body'] );
$l   = $br->request( 'GET', $base . '/thessley/v1/passkey/devices' );
ok( 'devices lists own device', 200 === $l['code'] && 1 === count( $l['json']['devices'] ) && 'phone-pkt_a' === $l['json']['devices'][0]['label'] && ! $l['json']['devices'][0]['revoked'], $l['body'] );
$l2 = $br->request( 'GET', $base . '/thessley/v1/passkey/devices?uid=' . $uid['pkt_b'] );
ok( "a user cannot list another account's devices (404)", 404 === $l2['code'] );
$page = $br->request( 'GET', $base . '/user/' . $uid['pkt_a'] . '/passkey' );
ok( 'own passkey tab renders', 200 === $page['code'] && strpos( $page['body'], 'thessley-pk-enroll-start' ) !== false );
$page = $br->request( 'GET', $base . '/user/' . $uid['pkt_b'] . '/passkey' );
ok( "someone else's passkey tab is denied (403)", 403 === $page['code'] );

$b_dev_id = (int) sql( "SELECT id FROM thessley_passkeys WHERE uid=" . $uid['pkt_b'] );
$r = $br->request( 'POST', $base . "/thessley/v1/passkey/devices/$b_dev_id/revoke", array( 'X-CSRF-Token: ' . $tok ) );
ok( "revoking another account's device is refused (404)", 404 === $r['code'], $r['body'] );
$a_dev_id = (int) sql( "SELECT id FROM thessley_passkeys WHERE uid=" . $uid['pkt_a'] );
$r = $br->request( 'POST', $base . "/thessley/v1/passkey/devices/$a_dev_id/revoke" );
ok( 'revoke without the CSRF header is refused', 403 === $r['code'] );
$s = login_start( new Browser() );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'before revoke, device a works', 200 === $r['code'] );
$r = $br->request( 'POST', $base . "/thessley/v1/passkey/devices/$a_dev_id/revoke", array( 'X-CSRF-Token: ' . $tok ) );
ok( 'revoke own device', 200 === $r['code'] && 'ok' === $r['json']['result'] );
$s = login_start( new Browser() );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_a']['cred'], $dev['pkt_a']['key'] );
ok( 'a revoked device can no longer approve (401)', 401 === $r['code'] && 'thessley_unknown_device' === $r['json']['code'] );

echo "== permission and blocked accounts\n";
drush( 'user:role:remove passkey_user pkt_b' );
$s = login_start( new Browser() );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( 'an account that lost the permission cannot approve (401)', 401 === $r['code'] );
drush( 'user:role:add passkey_user pkt_b' );
drush( 'user:block pkt_b' );
$s = login_start( new Browser() );
$r = respond( $s['json']['request_id'], 'login', $s['json']['nonce'], $dev['pkt_b']['cred'], $dev['pkt_b']['key'] );
ok( 'a blocked account cannot approve (401)', 401 === $r['code'] );
drush( 'user:unblock pkt_b' );

echo "== rate limit\n";
clear_flood();
$codes = array();
for ( $i = 0; $i < 22; $i++ ) {
	$codes[] = login_start( new Browser() )['code'];
}
ok( 'login/start is limited to 20 per window per IP (429 afterwards)', 200 === $codes[19] && 429 === $codes[20] && 429 === $codes[21], implode( ',', array_slice( $codes, 17 ) ) );

// ---- cleanup ----------------------------------------------------------------
echo "== cleanup\n";
foreach ( array( 'pkt_a', 'pkt_b', 'pkt_c' ) as $u ) {
	drush( "user:cancel -y --delete-content $u" );
}
drush( 'role:delete passkey_user' );
setcfg( 'optional', false );
clear_flood();
sql( "DELETE FROM thessley_passkey_requests" );
ok( 'test users gone', '0' === sql( "SELECT COUNT(*) FROM users_field_data WHERE name LIKE 'pkt\\_%' ESCAPE '\\'" ) );
ok( 'their devices were removed with them (hook_user_delete)', '0' === sql( "SELECT COUNT(*) FROM thessley_passkeys" ) );
echo $bad ? "\n$bad FAILED\n" : "\nALL PASS\n";
exit( $bad ? 1 : 0 );
