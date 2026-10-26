<?php

namespace Drupal\thessley_windows_access;

/**
 * The phone-facing PAM signature format shared with Thessley Passkey Android.
 *
 * This is deliberately separate from the website-login signature protocol.
 */
final class PamProtocol {

  public const SIG_VERSION = 'thessley_pam_v1';
  public const TIMESTAMP_SKEW = 60;

  /**
   * Builds the exact UTF-8 byte string signed by the phone app.
   */
  public function canonical(string $type, string $request_id, string $machine_id, string $username, string $nonce, int $timestamp, string $action): string {
    // The Android PAM app calls SSH, sudo, and other non-screen requests
    // "sudo" on the wire. Screen sign-in uses "login".
    if (!in_array($type, ['enroll', 'sudo', 'login'], TRUE) || !in_array($action, ['register', 'approve', 'deny'], TRUE)) {
      throw new \InvalidArgumentException('Unsupported PAM request type or action.');
    }
    $fields = [self::SIG_VERSION, $type, $request_id, $machine_id, $username, $nonce, (string) $timestamp, $action];
    foreach ($fields as $field) {
      if ($field === '' || preg_match('/[|\s\x00-\x1F\x7F]/u', $field)) {
        throw new \InvalidArgumentException('PAM signed fields must be non-empty and contain no separators or whitespace.');
      }
    }
    return implode('|', $fields);
  }

  public function timestampFresh(int $timestamp, ?int $now = NULL): bool {
    return abs(($now ?? time()) - $timestamp) <= self::TIMESTAMP_SKEW;
  }

  /**
   * Verifies a base64 DER SubjectPublicKeyInfo P-256 key and DER ECDSA signature.
   */
  public function verify(string $public_key_b64, string $message, string $signature_b64): bool {
    if (strlen($public_key_b64) > 1024 || strlen($signature_b64) > 512) {
      return FALSE;
    }
    $der = base64_decode($public_key_b64, TRUE);
    $signature = base64_decode($signature_b64, TRUE);
    if ($der === FALSE || $signature === FALSE) {
      return FALSE;
    }
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = $this->publicKey($pem);
    if ($key === FALSE) {
      return FALSE;
    }
    return openssl_verify($message, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
  }

  /** Validates the Base64 DER SubjectPublicKeyInfo format used by Android/Windows. */
  public function validPublicKey(string $public_key_b64): bool {
    if (strlen($public_key_b64) > 1024) {
      return FALSE;
    }
    $der = base64_decode($public_key_b64, TRUE);
    if ($der === FALSE) {
      return FALSE;
    }
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    return $this->publicKey($pem) !== FALSE;
  }

  private function publicKey(string $pem): mixed {
    $key = openssl_pkey_get_public($pem);
    if ($key === FALSE) {
      return FALSE;
    }
    $details = openssl_pkey_get_details($key);
    if (!is_array($details) || ($details['type'] ?? NULL) !== OPENSSL_KEYTYPE_EC
      || ($details['bits'] ?? 0) !== 256
      || !in_array($details['ec']['curve_name'] ?? '', ['prime256v1', 'secp256r1'], TRUE)) {
      return FALSE;
    }
    return $key;
  }

}
