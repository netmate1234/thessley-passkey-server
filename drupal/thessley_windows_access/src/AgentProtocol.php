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
  public const SIG_VERSION_V2 = 'thessley_win_agent_v2';

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

  public function pairing(string $pair_code, string $machine_id, string $username, string $sid_hash, string $public_key_hash): string {
    if (!preg_match('/^\d{8}$/', $pair_code) || !preg_match('/^[a-f0-9]{64}$/', $sid_hash)
      || !preg_match('/^[a-f0-9]{64}$/', $public_key_hash)) {
      throw new \InvalidArgumentException('Invalid Windows pairing proof.');
    }
    return $this->canonical(['pair', $pair_code, $machine_id, $username, $sid_hash, $public_key_hash]);
  }

  public function pairingV2(string $pair_code, string $machine_id, string $principal_id, string $username, string $scope, string $authority, string $public_key_hash): string {
    $this->assertPrincipal($principal_id, $username, $scope, $authority);
    if (!preg_match('/^\d{8}$/', $pair_code) || !preg_match('/^[a-f0-9]{64}$/', $public_key_hash)) {
      throw new \InvalidArgumentException('Invalid Windows pairing proof.');
    }
    return $this->canonical(['pair', $pair_code, $machine_id, $principal_id, $username, $scope, $authority, $public_key_hash], self::SIG_VERSION_V2);
  }

  public function challengeV2(string $machine_id, string $principal_id, string $scope, string $authority, string $username, string $context, string $client_nonce, int $timestamp): string {
    $this->assertPrincipal($principal_id, $username, $scope, $authority);
    if (!in_array($context, ['interactive', 'unlock'], TRUE)) {
      throw new \InvalidArgumentException('Invalid Windows logon context.');
    }
    return $this->canonical(['challenge', $machine_id, $principal_id, $scope, $authority, $username, $context, $client_nonce, (string) $timestamp], self::SIG_VERSION_V2);
  }

  public function pollV2(string $machine_id, string $principal_id, string $request_id, string $nonce, int $timestamp): string {
    if (!preg_match('/^[a-f0-9]{64}$/', $principal_id)) {
      throw new \InvalidArgumentException('Invalid Windows principal.');
    }
    return $this->canonical(['poll', $machine_id, $principal_id, $request_id, $nonce, (string) $timestamp], self::SIG_VERSION_V2);
  }

  public function policyV2(string $machine_id, string $principal_id, int $timestamp): string {
    if (!preg_match('/^[a-f0-9]{64}$/', $principal_id)) {
      throw new \InvalidArgumentException('Invalid Windows principal.');
    }
    return $this->canonical(['policy', $machine_id, $principal_id, (string) $timestamp], self::SIG_VERSION_V2);
  }

  public function inventoryV2(string $machine_id, string $principal_id, int $timestamp, string $payload_hash): string {
    if (!preg_match('/^[a-f0-9]{64}$/', $principal_id) || !preg_match('/^[a-f0-9]{64}$/', $payload_hash)) {
      throw new \InvalidArgumentException('Invalid Windows inventory proof.');
    }
    return $this->canonical(['inventory', $machine_id, $principal_id, (string) $timestamp, $payload_hash], self::SIG_VERSION_V2);
  }

  private function assertPrincipal(string $principal_id, string $username, string $scope, string $authority): void {
    if (!preg_match('/^[a-f0-9]{64}$/', $principal_id)
      || !preg_match('/^[A-Za-z0-9_.@\\\\-]{1,128}$/', $username)
      || !in_array($scope, ['local', 'domain'], TRUE)
      || !preg_match('/^[A-Za-z0-9_.@-]{1,128}$/', $authority)) {
      throw new \InvalidArgumentException('Invalid Windows principal identity.');
    }
  }

  public function verify(string $public_key, string $message, string $signature): bool {
    return $this->crypto->verify($public_key, $message, $signature);
  }

  private function canonical(array $fields, string $version = self::SIG_VERSION): string {
    foreach ($fields as $field) {
      if (!is_string($field) || $field === '' || preg_match('/[|\s\x00-\x1F\x7F]/u', $field)) {
        throw new \InvalidArgumentException('Agent message fields must be non-empty and contain no separators or whitespace.');
      }
    }
    return implode('|', array_merge([$version], $fields));
  }

}
