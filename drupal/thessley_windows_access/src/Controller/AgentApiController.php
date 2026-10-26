<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\thessley_windows_access\AgentProtocol;
use Drupal\thessley_windows_access\PamProtocol;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Signed challenge creation and status polling for the Windows agent.
 */
final class AgentApiController extends ControllerBase {

  public function __construct(
    protected WindowsAccessStore $store,
    protected AgentProtocol $protocol,
    protected PamProtocol $pam,
    protected FloodInterface $flood,
    protected ConfigFactoryInterface $configFactoryService,
    protected TimeInterface $time,
  ) {}

  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('thessley_windows_access.store'),
      $container->get('thessley_windows_access.agent_protocol'),
      $container->get('thessley_windows_access.pam_protocol'),
      $container->get('flood'),
      $container->get('config.factory'),
      $container->get('datetime.time'),
    );
  }

  /**
   * Starts a short-lived, signed phone challenge for an enrolled account.
   */
  public function challenge(Request $request, string $machine_id, string $username, string $type): JsonResponse {
    $body = $this->jsonBody($request);
    if ($body instanceof JsonResponse) {
      return $body;
    }
    $account = $this->store->accountByMachineUser($machine_id, $username);
    if (!$account || !$account->public_key || !$this->store->machine($machine_id)) {
      return $this->reply(['result' => 'error', 'message' => 'This Windows account is not enrolled.'], 403);
    }
    if (!$this->identityCanLogIn($account)) {
      return $this->reply(['result' => 'denied', 'message' => 'This Drupal identity is not allowed to sign in.'], 403);
    }

    $client_nonce = is_string($body['client_nonce'] ?? NULL) ? $body['client_nonce'] : '';
    $timestamp = filter_var($body['timestamp'] ?? NULL, FILTER_VALIDATE_INT);
    $signature = is_string($body['signature'] ?? NULL) ? $body['signature'] : '';
    if (!preg_match('/^[A-Za-z0-9_-]{32,64}$/', $client_nonce)
      || $timestamp === FALSE || !$this->pam->timestampFresh((int) $timestamp)) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid or expired agent challenge.'], 400);
    }
    try {
      $message = $this->protocol->challenge($machine_id, $username, $client_nonce, (int) $timestamp);
    }
    catch (\InvalidArgumentException) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid agent challenge.'], 400);
    }
    if (!$this->protocol->verify((string) $account->public_key, $message, $signature)) {
      return $this->reply(['result' => 'error', 'message' => 'Windows account key proof failed.'], 401);
    }

    $ip = (string) ($request->getClientIp() ?: 'unknown');
    $flood_id = $machine_id . ':' . $username;
    if (!$this->flood->isAllowed('thessley_windows_agent_challenge', 12, 3600, $flood_id . ':' . $ip)) {
      return $this->reply(['result' => 'error', 'message' => 'Too many sign-in requests. Try again later.'], 429);
    }
    $this->flood->register('thessley_windows_agent_challenge', 3600, $flood_id . ':' . $ip);

    try {
      $pending = $this->store->createRequest((int) $account->id, $type, 120, $client_nonce);
    }
    catch (\Throwable) {
      // The unique account/client-nonce constraint makes a replayed start fail closed.
      return $this->reply(['result' => 'error', 'message' => 'This challenge was already used. Start a new one.'], 409);
    }

    $settings = $this->configFactoryService->get('thessley_windows_access.settings');
    $origin = parse_url((string) $settings->get('public_url'));
    $fingerprint = strtolower((string) $settings->get('tls_sha256'));
    $machine = $this->store->machine($machine_id);
    if (!$origin || empty($origin['host']) || !$machine || !$this->validFingerprint($fingerprint)) {
      return $this->reply(['result' => 'error', 'message' => 'The phone approval endpoint is not configured.'], 503);
    }
    $link_type = $type === 'login' ? 'login' : 'sudo';
    $query = [
      'h' => $origin['host'],
      'p' => isset($origin['port']) ? (int) $origin['port'] : 443,
      'fp' => $fingerprint,
      'n' => $pending['nonce'],
      'id' => $pending['request_id'],
      'm' => $machine_id,
      'hn' => $machine->hostname,
      'u' => $username,
    ];
    if ($type === 'sudo') {
      $query['tty'] = 'ssh';
      $query['s'] = 'sshd';
    }
    return $this->reply([
      'result' => 'ok',
      'request_id' => $pending['request_id'],
      'nonce' => $pending['nonce'],
      'expires_in' => $pending['expires_in'],
      'app_link' => 'thessleypam://' . $link_type . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986),
    ]);
  }

  /**
   * Returns an approval once, after verifying a fresh signature from the agent.
   */
  public function status(Request $request, string $machine_id, string $username, string $request_id): JsonResponse {
    $body = $this->jsonBody($request);
    if ($body instanceof JsonResponse) {
      return $body;
    }
    $account = $this->store->accountByMachineUser($machine_id, $username);
    $pending = $this->store->request($request_id);
    if (!$account || !$account->public_key || !$pending || (int) $pending->account_id !== (int) $account->id) {
      return $this->reply(['result' => 'error', 'message' => 'Unknown Windows request.'], 404);
    }
    if (!$this->identityCanLogIn($account)) {
      return $this->reply(['result' => 'denied', 'message' => 'This Drupal identity is no longer allowed to sign in.'], 403);
    }
    $timestamp = filter_var($body['timestamp'] ?? NULL, FILTER_VALIDATE_INT);
    $signature = is_string($body['signature'] ?? NULL) ? $body['signature'] : '';
    if ($timestamp === FALSE || !$this->pam->timestampFresh((int) $timestamp)) {
      return $this->reply(['result' => 'error', 'message' => 'Agent clock is outside the allowed window.'], 401);
    }
    try {
      $message = $this->protocol->poll($machine_id, $username, $request_id, (string) $pending->nonce, (int) $timestamp);
    }
    catch (\InvalidArgumentException) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid status request.'], 400);
    }
    if (!$this->protocol->verify((string) $account->public_key, $message, $signature)) {
      return $this->reply(['result' => 'error', 'message' => 'Windows account key proof failed.'], 401);
    }

    return $this->reply(['result' => $this->store->consumeRequestResult($request_id)]);
  }

  /**
   * Returns Drupal groups and effective Windows actions to the signed-in agent.
   */
  public function policy(Request $request, string $machine_id, string $username): JsonResponse {
    $body = $this->jsonBody($request);
    if ($body instanceof JsonResponse) {
      return $body;
    }
    $account = $this->store->accountByMachineUser($machine_id, $username);
    if (!$account || !$account->public_key || !$this->store->machine($machine_id)) {
      return $this->reply(['result' => 'error', 'message' => 'This Windows account is not enrolled.'], 403);
    }
    $timestamp = filter_var($body['timestamp'] ?? NULL, FILTER_VALIDATE_INT);
    $signature = is_string($body['signature'] ?? NULL) ? $body['signature'] : '';
    if ($timestamp === FALSE || !$this->pam->timestampFresh((int) $timestamp)) {
      return $this->reply(['result' => 'error', 'message' => 'Agent clock is outside the allowed window.'], 401);
    }
    try {
      $message = $this->protocol->policy($machine_id, $username, (int) $timestamp);
    }
    catch (\InvalidArgumentException) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid policy request.'], 400);
    }
    if (!$this->protocol->verify((string) $account->public_key, $message, $signature)) {
      return $this->reply(['result' => 'error', 'message' => 'Windows account key proof failed.'], 401);
    }

    $user = $this->entityTypeManager()->getStorage('user')->load((int) $account->uid);
    if (!$user || !$user->isActive()) {
      return $this->reply([
        'result' => 'ok',
        'identity_active' => FALSE,
        'groups' => [],
        'actions' => [],
        'managed_local_groups' => [],
      ]);
    }
    $roles = [];
    foreach ($user->getRoles() as $role_id) {
      $role = $this->entityTypeManager()->getStorage('user_role')->load($role_id);
      $roles[] = ['id' => $role_id, 'label' => $role ? $role->label() : $role_id];
    }
    $actions = [];
    foreach (['windows.login', 'windows.local_admin'] as $action) {
      if ($this->store->userHasGrant((int) $account->uid, 'computer_' . $machine_id, $action)
        || $this->store->userHasGrant((int) $account->uid, 'all_windows', $action)) {
        $actions[] = $action;
      }
    }
    return $this->reply([
      'result' => 'ok',
      'identity_active' => TRUE,
      'groups' => $roles,
      'actions' => $actions,
      'managed_local_groups' => in_array('windows.local_admin', $actions, TRUE) ? ['Administrators'] : [],
    ]);
  }

  /**
   * Receives a signed snapshot of Windows local groups for one account.
   */
  public function inventory(Request $request, string $machine_id, string $username): JsonResponse {
    // The signed group snapshot is Base64-wrapped in JSON. Allow enough room
    // for the documented 18 KB decoded inventory plus its encoding overhead.
    $body = $this->jsonBody($request, 32768);
    if ($body instanceof JsonResponse) {
      return $body;
    }
    $account = $this->store->accountByMachineUser($machine_id, $username);
    if (!$account || !$account->public_key || !$this->store->machine($machine_id)) {
      return $this->reply(['result' => 'error', 'message' => 'This Windows account is not enrolled.'], 403);
    }
    $timestamp = filter_var($body['timestamp'] ?? NULL, FILTER_VALIDATE_INT);
    $signature = is_string($body['signature'] ?? NULL) ? $body['signature'] : '';
    $encoded = is_string($body['inventory_b64'] ?? NULL) ? $body['inventory_b64'] : '';
    if ($timestamp === FALSE || !$this->pam->timestampFresh((int) $timestamp)
      || $encoded === '' || strlen($encoded) > 24000) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid or expired inventory update.'], 400);
    }
    $payload = base64_decode($encoded, TRUE);
    if ($payload === FALSE || strlen($payload) > 18000) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid inventory encoding.'], 400);
    }
    $inventory = json_decode($payload, TRUE);
    if (!is_array($inventory) || !isset($inventory['groups']) || !is_array($inventory['groups'])
      || count($inventory) !== 1 || count($inventory['groups']) > 128) {
      return $this->reply(['result' => 'error', 'message' => 'Inventory must contain at most 128 groups.'], 400);
    }
    $groups = [];
    foreach ($inventory['groups'] as $group) {
      if (!is_array($group) || !is_string($group['sid_hash'] ?? NULL) || !is_string($group['name'] ?? NULL)) {
        return $this->reply(['result' => 'error', 'message' => 'Invalid Windows group entry.'], 400);
      }
      $sid_hash = strtolower($group['sid_hash']);
      $name = trim($group['name']);
      if (!preg_match('/^[a-f0-9]{64}$/', $sid_hash) || $name === '' || strlen($name) > 128
        || preg_match('/[\x00-\x1F\x7F]/', $name)) {
        return $this->reply(['result' => 'error', 'message' => 'Invalid Windows group name or SID hash.'], 400);
      }
      $groups[$sid_hash] = ['sid_hash' => $sid_hash, 'name' => $name];
    }
    try {
      $message = $this->protocol->inventory(
        $machine_id,
        $username,
        (int) $timestamp,
        hash('sha256', $payload),
      );
    }
    catch (\InvalidArgumentException) {
      return $this->reply(['result' => 'error', 'message' => 'Invalid inventory signature input.'], 400);
    }
    if (!$this->protocol->verify((string) $account->public_key, $message, $signature)) {
      return $this->reply(['result' => 'error', 'message' => 'Windows account key proof failed.'], 401);
    }

    $flood_id = $machine_id . ':' . (int) $account->id . ':' . (string) ($request->getClientIp() ?: 'unknown');
    if (!$this->flood->isAllowed('thessley_windows_agent_inventory', 60, 3600, $flood_id)) {
      return $this->reply(['result' => 'error', 'message' => 'Too many inventory updates. Try again later.'], 429);
    }
    $this->flood->register('thessley_windows_agent_inventory', 3600, $flood_id);
    $this->store->replaceAccountGroups((int) $account->id, array_values($groups));
    return $this->reply([
      'result' => 'ok',
      'groups_received' => count($groups),
      'observed' => $this->time->getRequestTime(),
    ]);
  }

  private function identityCanLogIn(object $account): bool {
    if (!$this->store->userHasGrant((int) $account->uid, 'computer_' . $account->machine_id, 'windows.login')
      && !$this->store->userHasGrant((int) $account->uid, 'all_windows', 'windows.login')) {
      return FALSE;
    }
    $user = $this->entityTypeManager()->getStorage('user')->load((int) $account->uid);
    return $user && $user->isActive();
  }

  private function jsonBody(Request $request, int $max_bytes = 16384): array|JsonResponse {
    if (strlen((string) $request->getContent()) > $max_bytes) {
      return $this->reply(['result' => 'error', 'message' => 'Request body is too large.'], 413);
    }
    $body = json_decode((string) $request->getContent(), TRUE);
    if (!is_array($body)) {
      return $this->reply(['result' => 'error', 'message' => 'Expected a JSON object.'], 400);
    }
    return $body;
  }

  private function validFingerprint(string $fingerprint): bool {
    return (bool) preg_match('/^[a-f0-9]{64}$/', $fingerprint);
  }

  private function reply(array $data, int $status = 200): JsonResponse {
    $response = new JsonResponse($data, $status);
    $response->headers->set('Cache-Control', 'no-store, private');
    return $response;
  }

}
