<?php

namespace Drupal\thessley_windows_access;

/**
 * Proof-of-possession messages from an enrolled Windows account agent.
 *
 * Kept separate from thessley_pam_v1: these signatures authenticate the
 * endpoint service, while PAM signatures represent the person's phone.
 */
final class AgentProtocol {

  public const SIG_VERSION = 'thessley_win_agent_v1';

  public function __construct(protected PamProtocol $crypto) {}

  public function challenge(string $machine_id, string $username, string $client_nonce, int $timestamp): string {
    return $this->canonical(['challenge', $machine_id, $username, $client_nonce, (string) $timestamp]);
  }

  public function poll(string $machine_id, string $username, string $request_id, string $nonce, int $timestamp): string {
    return $this->canonical(['poll', $machine_id, $username, $request_id, $nonce, (string) $timestamp]);
  }

  public function policy(string $machine_id, string $username, int $timestamp): string {
    return $this->canonical(['policy', $machine_id, $username, (string) $timestamp]);
  }

  public function inventory(string $machine_id, string $username, int $timestamp, string $payload_hash): string {
    if (!preg_match('/^[a-f0-9]{64}$/', $payload_hash)) {
      throw new \InvalidArgumentException('Invalid inventory digest.');
    }
    return $this->canonical(['inventory', $machine_id, $username, (string) $timestamp, $payload_hash]);
  }

  public function verify(string $public_key, string $message, string $signature): bool {
    return $this->crypto->verify($public_key, $message, $signature);
  }

  private function canonical(array $fields): string {
    foreach ($fields as $field) {
      if (!is_string($field) || $field === '' || preg_match('/[|\s\x00-\x1F\x7F]/u', $field)) {
        throw new \InvalidArgumentException('Agent message fields must be non-empty and contain no separators or whitespace.');
      }
    }
    return implode('|', array_merge([self::SIG_VERSION], $fields));
  }

}
