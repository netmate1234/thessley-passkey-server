<?php

namespace Drupal\thessley_windows_access;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;

/**
 * Database access for Windows principal bindings and PAM approvals.
 */
final class WindowsAccessStore {

  public function __construct(
    protected Connection $db,
    protected TimeInterface $time,
  ) {}

  public function randomToken(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
  }

  public function createMachine(string $machine_id, string $hostname): void {
    $existing = $this->db->select('thessley_win_machines', 'm')
      ->fields('m', ['status', 'revoked'])
      ->condition('machine_id', $machine_id)
      ->forUpdate()
      ->execute()
      ->fetchObject();
    if ($existing) {
      if ($existing->status !== 'active' || $existing->revoked !== NULL) {
        throw new \RuntimeException('A revoked or inactive Windows machine cannot be re-enrolled.');
      }
      $this->db->update('thessley_win_machines')
        ->fields(['hostname' => $hostname])
        ->condition('machine_id', $machine_id)
        ->execute();
    }
    else {
      $this->db->insert('thessley_win_machines')
        ->fields([
          'machine_id' => $machine_id,
          'hostname' => $hostname,
          'status' => 'active',
          'created' => $this->time->getRequestTime(),
        ])
        ->execute();
    }
    $this->db->merge('thessley_win_resources')
      ->key('machine_name', 'computer_' . $machine_id)
      ->fields([
        'label' => $hostname,
        'type' => 'computer',
        'machine_id' => $machine_id,
        'status' => 'active',
      ])
      ->insertFields([
        'machine_name' => 'computer_' . $machine_id,
        'label' => $hostname,
        'type' => 'computer',
        'machine_id' => $machine_id,
        'status' => 'active',
        'created' => $this->time->getRequestTime(),
      ])
      ->execute();
  }

  public function createAccount(string $machine_id, string $sid_hash, string $username, string $display_name, int $uid, string $public_key): int {
    $id = $this->db->insert('thessley_win_accounts')
      ->fields([
        'machine_id' => $machine_id,
        'sid_hash' => $sid_hash,
        'username' => $username,
        'display_name' => $display_name,
        'uid' => $uid,
        'public_key' => $public_key,
        'status' => 'pending',
        'created' => $this->time->getRequestTime(),
      ])
      ->execute();
    return (int) $id;
  }

  public function account(int $account_id): ?object {
    $row = $this->db->select('thessley_win_accounts', 'a')
      ->fields('a')
      ->condition('id', $account_id)
      ->execute()
      ->fetchObject();
    return $row ?: NULL;
  }

  public function machine(string $machine_id): ?object {
    $row = $this->db->select('thessley_win_machines', 'm')
      ->fields('m')
      ->condition('machine_id', $machine_id)
      ->condition('status', 'active')
      ->condition('revoked', NULL, 'IS NULL')
      ->execute()
      ->fetchObject();
    return $row ?: NULL;
  }

  public function activateAccount(int $account_id): void {
    $this->db->update('thessley_win_accounts')
      ->fields(['status' => 'active'])
      ->condition('id', $account_id)
      ->condition('revoked', NULL, 'IS NULL')
      ->execute();
  }

  public function accountByMachineUser(string $machine_id, string $username): ?object {
    $row = $this->db->select('thessley_win_accounts', 'a')
      ->fields('a')
      ->condition('machine_id', $machine_id)
      ->condition('username', $username)
      ->condition('status', 'active')
      ->condition('revoked', NULL, 'IS NULL')
      ->execute()
      ->fetchObject();
    return $row ?: NULL;
  }

  public function addPhone(int $account_id, string $public_key, string $algorithm, string $label): string {
    $credential_id = $this->randomToken();
    $this->db->insert('thessley_win_phones')
      ->fields([
        'account_id' => $account_id,
        'credential_id' => $credential_id,
        'public_key' => $public_key,
        'algorithm' => $algorithm,
        'label' => $label,
        'created' => $this->time->getRequestTime(),
      ])
      ->execute();
    return $credential_id;
  }

  public function phoneForAccount(string $credential_id, int $account_id): ?object {
    $row = $this->db->select('thessley_win_phones', 'p')
      ->fields('p')
      ->condition('credential_id', $credential_id)
      ->condition('account_id', $account_id)
      ->condition('revoked', NULL, 'IS NULL')
      ->execute()
      ->fetchObject();
    return $row ?: NULL;
  }

  /**
   * Lists phone credentials for an account without returning public-key data.
   */
  public function phonesForAccount(int $account_id): array {
    return $this->db->select('thessley_win_phones', 'p')
      ->fields('p', ['id', 'credential_id', 'label', 'created', 'last_used', 'revoked'])
      ->condition('account_id', $account_id)
      ->orderBy('created', 'DESC')
      ->execute()
      ->fetchAll();
  }

  /**
   * Revokes one phone credential, scoped to its Windows account.
   */
  public function revokePhone(int $account_id, int $phone_id, int $actor_uid): bool {
    $transaction = $this->db->startTransaction();
    $phone = $this->db->select('thessley_win_phones', 'p')
      ->fields('p', ['id', 'credential_id', 'label', 'revoked'])
      ->condition('id', $phone_id)
      ->condition('account_id', $account_id)
      ->forUpdate()
      ->execute()
      ->fetchObject();
    if (!$phone || $phone->revoked !== NULL) {
      return FALSE;
    }
    $now = $this->time->getRequestTime();
    $changed = $this->db->update('thessley_win_phones')
      ->fields(['revoked' => $now])
      ->condition('id', $phone_id)
      ->condition('account_id', $account_id)
      ->condition('revoked', NULL, 'IS NULL')
      ->execute();
    if (!$changed) {
      return FALSE;
    }
    $this->audit($actor_uid, 'phone_revoked', 'windows_account:' . $account_id, [
      'phone_id' => $phone_id,
      'credential_id_prefix' => substr((string) $phone->credential_id, 0, 10),
      'label' => (string) $phone->label,
    ]);
    unset($transaction);
    return TRUE;
  }

  public function updatePhone(int $phone_id, array $fields): void {
    $allowed = array_intersect_key($fields, array_flip(['last_used', 'revoked']));
    if ($allowed) {
      $this->db->update('thessley_win_phones')->fields($allowed)->condition('id', $phone_id)->execute();
    }
  }

  public function createRequest(int $account_id, string $type, int $ttl, ?string $client_nonce = NULL): array {
    if (!in_array($type, ['enroll', 'login', 'sudo'], TRUE) || $ttl < 30 || $ttl > 600) {
      throw new \InvalidArgumentException('Invalid PAM request parameters.');
    }
    $request_id = $this->randomToken();
    $nonce = $this->randomToken();
    $now = $this->time->getRequestTime();
    $this->db->insert('thessley_win_requests')
      ->fields([
        'request_id' => $request_id,
        'account_id' => $account_id,
        'type' => $type,
        'nonce' => $nonce,
        'client_nonce' => $client_nonce,
        'status' => 'pending',
        'created' => $now,
        'expires' => $now + $ttl,
      ])
      ->execute();
    return ['request_id' => $request_id, 'nonce' => $nonce, 'expires_in' => $ttl];
  }

  /** Atomically returns and consumes an answered login request. */
  public function consumeRequestResult(string $request_id): string {
    $transaction = $this->db->startTransaction();
    $request = $this->db->select('thessley_win_requests', 'r')
      ->fields('r')
      ->condition('request_id', $request_id)
      ->forUpdate()
      ->execute()
      ->fetchObject();
    if (!$request) {
      return 'expired';
    }
    if ((int) $request->expires < $this->time->getRequestTime()) {
      return 'expired';
    }
    if ($request->status === 'consumed') {
      return 'consumed';
    }
    if (!in_array($request->status, ['approved', 'denied'], TRUE)) {
      return 'pending';
    }
    $result = (string) $request->status;
    if ($result === 'approved') {
      // If a phone was revoked after approving but before the agent received
      // the result, consume the approval as a denial. Locking this row makes
      // the check atomic with an administrator's phone-revocation action.
      $phone_active = $this->db->select('thessley_win_phones', 'p')
        ->fields('p', ['id'])
        ->condition('id', (int) $request->phone_id)
        ->condition('account_id', (int) $request->account_id)
        ->condition('revoked', NULL, 'IS NULL')
        ->forUpdate()
        ->execute()
        ->fetchField();
      if (!$phone_active) {
        $result = 'denied';
      }
    }
    $changed = $this->db->update('thessley_win_requests')
      ->fields(['status' => 'consumed'])
      ->condition('request_id', $request_id)
      ->condition('status', $request->status)
      ->execute();
    unset($transaction);
    return $changed ? $result : 'consumed';
  }

  public function request(string $request_id): ?object {
    $row = $this->db->select('thessley_win_requests', 'r')
      ->fields('r')
      ->condition('request_id', $request_id)
      ->execute()
      ->fetchObject();
    return $row ?: NULL;
  }

  public function resolveRequest(string $request_id, string $status, int $phone_id): bool {
    if (!in_array($status, ['approved', 'denied'], TRUE)) {
      return FALSE;
    }
    return (bool) $this->db->update('thessley_win_requests')
      ->fields([
        'status' => $status,
        'phone_id' => $phone_id,
        'resolved' => $this->time->getRequestTime(),
      ])
      ->condition('request_id', $request_id)
      ->condition('status', 'pending')
      ->condition('expires', $this->time->getRequestTime(), '>=')
      ->execute();
  }

  /**
   * Saves a newly-proved phone key and consumes its enrollment request atomically.
   */
  public function completeEnrollment(int $account_id, string $request_id, string $public_key, string $algorithm, string $label): string {
    $transaction = $this->db->startTransaction();
    $request = $this->request($request_id);
    $account = $this->account($account_id);
    if (!$request || $request->type !== 'enroll' || $request->status !== 'pending'
      || (int) $request->account_id !== $account_id || (int) $request->expires < $this->time->getRequestTime()
      || !$account || $account->revoked !== NULL) {
      throw new \RuntimeException('Enrollment request is no longer valid.');
    }

    $credential_id = $this->addPhone($account_id, $public_key, $algorithm, $label);
    $phone_id = (int) $this->db->query('SELECT id FROM {thessley_win_phones} WHERE credential_id = :credential', [':credential' => $credential_id])->fetchField();
    $this->activateAccount($account_id);
    if (!$this->resolveRequest($request_id, 'approved', $phone_id)) {
      throw new \RuntimeException('Enrollment request was already consumed.');
    }
    $this->audit((int) $account->uid, 'phone_enrolled', 'windows_account:' . $account_id, [
      'phone_id' => $phone_id,
      'credential_id' => $credential_id,
    ]);
    unset($transaction);
    return $credential_id;
  }

  public function touchPhone(int $phone_id): void {
    $this->db->update('thessley_win_phones')
      ->fields(['last_used' => $this->time->getRequestTime()])
      ->condition('id', $phone_id)
      ->execute();
  }

  /**
   * Replaces the reported local-group snapshot for an enrolled account.
   */
  public function replaceAccountGroups(int $account_id, array $groups): void {
    $transaction = $this->db->startTransaction();
    $this->db->delete('thessley_win_account_groups')
      ->condition('account_id', $account_id)
      ->execute();
    $now = $this->time->getRequestTime();
    foreach ($groups as $group) {
      $this->db->insert('thessley_win_account_groups')
        ->fields([
          'account_id' => $account_id,
          'group_sid_hash' => $group['sid_hash'],
          'group_name' => $group['name'],
          'observed' => $now,
        ])
        ->execute();
    }
    $this->db->update('thessley_win_accounts')
      ->fields(['last_seen' => $now])
      ->condition('id', $account_id)
      ->execute();
    unset($transaction);
  }

  public function accountGroups(int $account_id): array {
    return $this->db->select('thessley_win_account_groups', 'g')
      ->fields('g', ['group_sid_hash', 'group_name', 'observed'])
      ->condition('account_id', $account_id)
      ->orderBy('group_name')
      ->execute()
      ->fetchAll();
  }

  /**
   * Returns current account and reported Windows-group inventory rows.
   */
  public function accountInventory(): array {
    $query = $this->db->select('thessley_win_accounts', 'a')
      ->fields('a', ['id', 'machine_id', 'username', 'uid', 'status', 'last_seen', 'revoked']);
    $query->addField('m', 'hostname');
    $query->addField('g', 'group_sid_hash');
    $query->addField('g', 'group_name');
    $query->leftJoin('thessley_win_machines', 'm', 'm.machine_id = a.machine_id');
    $query->leftJoin('thessley_win_account_groups', 'g', 'g.account_id = a.id');
    return $query->orderBy('m.hostname')->orderBy('a.username')->orderBy('g.group_name')->execute()->fetchAll();
  }

  /**
   * Returns inventory for one Drupal user, never another user's bindings.
   */
  public function accountInventoryForUser(int $uid): array {
    $query = $this->db->select('thessley_win_accounts', 'a')
      ->fields('a', ['id', 'machine_id', 'username', 'status', 'last_seen', 'revoked'])
      ->condition('a.uid', $uid);
    $query->addField('m', 'hostname');
    $query->addField('g', 'group_sid_hash');
    $query->addField('g', 'group_name');
    $query->leftJoin('thessley_win_machines', 'm', 'm.machine_id = a.machine_id');
    $query->leftJoin('thessley_win_account_groups', 'g', 'g.account_id = a.id');
    return $query->orderBy('m.hostname')->orderBy('a.username')->orderBy('g.group_name')->execute()->fetchAll();
  }

  /**
   * Lists active resources for the policy editor.
   */
  public function resources(): array {
    return $this->db->select('thessley_win_resources', 'r')
      ->fields('r')
      ->condition('status', 'active')
      ->orderBy('label')
      ->execute()
      ->fetchAll();
  }

  /**
   * Returns resource/action grant values for one Drupal role.
   */
  public function roleGrantValues(string $role_id): array {
    $rows = $this->db->select('thessley_win_grants', 'g')
      ->fields('g', ['resource_id', 'action'])
      ->condition('role_id', $role_id)
      ->execute()
      ->fetchAll();
    $values = [];
    foreach ($rows as $row) {
      $values[] = (int) $row->resource_id . ':' . (string) $row->action;
    }
    return $values;
  }

  /**
   * Checks a Drupal identity's current grants for a named resource/action.
   *
   * This is evaluated when a phone answers, so a role removal takes effect
   * immediately and a stale Windows-side challenge cannot bypass Drupal.
   */
  public function userHasGrant(int $uid, string $resource_name, string $action): bool {
    if ($uid <= 0 || !in_array($action, [
      'windows.login',
      'windows.local_admin',
      'windows.remote_desktop',
      'windows.event_log_readers',
      'windows.remote_management',
      'access',
      'connect',
      'download',
    ], TRUE)) {
      return FALSE;
    }
    $query = $this->db->select('thessley_win_grants', 'g')->fields('g', ['id']);
    $query->innerJoin('thessley_win_resources', 'r', 'r.id = g.resource_id');
    $query->innerJoin('user__roles', 'ur', 'ur.roles_target_id = g.role_id');
    return (bool) $query
      ->condition('ur.entity_id', $uid)
      ->condition('ur.deleted', 0)
      ->condition('r.machine_name', $resource_name)
      ->condition('r.status', 'active')
      ->condition('g.action', $action)
      ->range(0, 1)
      ->execute()
      ->fetchField();
  }

  /**
   * Replaces one role's grants in one transaction and audits the change.
   */
  public function replaceRoleGrants(string $role_id, array $grants, int $actor_uid): void {
    $allowed_actions = [
      'windows.login',
      'windows.local_admin',
      'windows.remote_desktop',
      'windows.event_log_readers',
      'windows.remote_management',
      'access',
      'connect',
      'download',
    ];
    $normalized = [];
    foreach ($grants as $grant) {
      if (!is_array($grant) || !isset($grant['resource_id'], $grant['action'])) {
        continue;
      }
      $resource_id = (int) $grant['resource_id'];
      $action = (string) $grant['action'];
      if ($resource_id > 0 && in_array($action, $allowed_actions, TRUE)) {
        $normalized[$resource_id . ':' . $action] = ['resource_id' => $resource_id, 'action' => $action];
      }
    }

    $transaction = $this->db->startTransaction();
    $this->db->delete('thessley_win_grants')->condition('role_id', $role_id)->execute();
    foreach ($normalized as $grant) {
      $this->db->insert('thessley_win_grants')
        ->fields([
          'role_id' => $role_id,
          'resource_id' => $grant['resource_id'],
          'action' => $grant['action'],
          'created' => $this->time->getRequestTime(),
          'changed_by' => $actor_uid,
        ])
        ->execute();
    }
    $this->audit($actor_uid, 'role_grants_changed', $role_id, ['grants' => array_values($normalized)]);
    unset($transaction);
  }

  public function audit(int $actor_uid, string $event, string $target, array $details = []): void {
    $this->db->insert('thessley_win_audit')
      ->fields([
        'actor_uid' => $actor_uid,
        'event' => substr($event, 0, 48),
        'target' => substr($target, 0, 128),
        'details' => json_encode($details, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}',
        'created' => $this->time->getRequestTime(),
      ])
      ->execute();
  }

  /** Returns recent phone login decisions belonging to one Drupal identity. */
  public function recentLoginDecisions(int $uid, int $limit = 20): array {
    if ($uid <= 0) {
      return [];
    }
    $limit = max(1, min(50, $limit));
    return $this->db->select('thessley_win_audit', 'a')
      ->fields('a', ['event', 'details', 'created'])
      ->condition('actor_uid', $uid)
      ->condition('event', ['phone_login_approved', 'phone_login_denied'], 'IN')
      ->orderBy('created', 'DESC')
      ->range(0, $limit)
      ->execute()
      ->fetchAll();
  }

  public function pruneExpiredRequests(): void {
    $this->db->delete('thessley_win_requests')
      ->condition('expires', $this->time->getRequestTime(), '<')
      ->execute();
  }

}
