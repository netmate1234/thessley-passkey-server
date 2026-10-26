<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Flood\FloodInterface;
use Drupal\thessley_windows_access\PamProtocol;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Phone-facing endpoints for the existing Thessley PAM wire protocol.
 */
final class PamApiController extends ControllerBase {

  public function __construct(
    protected WindowsAccessStore $store,
    protected PamProtocol $protocol,
    protected FloodInterface $flood,
  ) {}

  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('thessley_windows_access.store'),
      $container->get('thessley_windows_access.pam_protocol'),
      $container->get('flood'),
    );
  }

  protected function reply(array $data, int $status = 200): JsonResponse {
    $response = new JsonResponse($data, $status);
    $response->headers->set('Cache-Control', 'no-store, private');
    return $response;
  }

  protected function error(string $message, int $status): JsonResponse {
    return $this->reply(['result' => 'error', 'message' => $message], $status);
  }

  /**
   * Handles thessleypam://enroll and thessleypam://login responses.
   */
  public function respond(Request $request, string $type, string $id): JsonResponse {
    $ip = (string) ($request->getClientIp() ?: 'unknown');
    if (!$this->flood->isAllowed('thessley_windows_pam_respond', 40, 3600, $ip)) {
      return $this->error('Too many approval attempts. Try again later.', 429);
    }
    $this->flood->register('thessley_windows_pam_respond', 3600, $ip);

    if (strlen((string) $request->getContent()) > 16384) {
      return $this->error('Request body is too large.', 413);
    }
    $body = json_decode((string) $request->getContent(), TRUE);
    if (!is_array($body)) {
      return $this->error('Expected a JSON object.', 400);
    }

    $row = $this->store->request($id);
    if (!$row || $row->type !== $type || $row->status !== 'pending' || (int) $row->expires < time()) {
      return $this->error('This request is no longer valid.', 409);
    }
    $account = $this->store->account((int) $row->account_id);
    $allowed_enrollment_state = $type === 'enroll' && $account && $account->status === 'pending';
    if (!$account || (!$allowed_enrollment_state && $account->status !== 'active')
      || $account->revoked !== NULL || !$this->store->machine($account->machine_id)) {
      return $this->error('This Windows account is no longer active.', 410);
    }

    $machine_grant = $type !== 'enroll'
      && $this->store->userHasGrant((int) $account->uid, 'computer_' . $account->machine_id, 'windows.login');
    $global_grant = $type !== 'enroll'
      && $this->store->userHasGrant((int) $account->uid, 'all_windows', 'windows.login');
    if ($type !== 'enroll' && !$machine_grant && !$global_grant) {
      return $this->error('This Drupal identity is not allowed to sign in to enrolled Windows computers.', 403);
    }
    if ($type !== 'enroll') {
      $identity = $this->entityTypeManager()->getStorage('user')->load((int) $account->uid);
      if (!$identity || !$identity->isActive()) {
        return $this->error('The Drupal identity linked to this Windows account is inactive.', 403);
      }
    }

    $timestamp = filter_var($body['timestamp'] ?? NULL, FILTER_VALIDATE_INT);
    if ($timestamp === FALSE || !$this->protocol->timestampFresh((int) $timestamp)) {
      return $this->error('Device clock is off by more than a minute.', 401);
    }

    if ($type === 'enroll') {
      return $this->enrollResponse($row, $account, $body, (int) $timestamp);
    }
    return $this->loginResponse($row, $account, $body, (int) $timestamp, $type);
  }

  protected function enrollResponse(object $row, object $account, array $body, int $timestamp): JsonResponse {
    $public_key = is_string($body['public_key'] ?? NULL) ? $body['public_key'] : '';
    $signature = is_string($body['proof_signature'] ?? NULL) ? $body['proof_signature'] : '';
    $algorithm = is_string($body['algorithm'] ?? NULL) ? $body['algorithm'] : 'ES256';
    $label = is_string($body['label'] ?? NULL) ? trim($body['label']) : 'Phone';
    if ($algorithm !== 'ES256' || $public_key === '' || strlen($label) > 100) {
      return $this->error('Invalid phone enrollment fields.', 400);
    }
    $label = $label !== '' ? $label : 'Phone';

    try {
      $message = $this->protocol->canonical(
        'enroll',
        (string) $row->request_id,
        (string) $account->machine_id,
        (string) $account->username,
        (string) $row->nonce,
        $timestamp,
        'register',
      );
    }
    catch (\InvalidArgumentException) {
      return $this->error('Invalid PAM enrollment request.', 400);
    }
    if (!$this->protocol->verify($public_key, $message, $signature)) {
      return $this->error('Signature did not verify.', 401);
    }

    try {
      $credential_id = $this->store->completeEnrollment((int) $row->account_id, (string) $row->request_id, $public_key, $algorithm, $label);
    }
    catch (\Throwable $e) {
      $this->getLogger('thessley_windows_access')->error('Phone enrollment failed for Windows account row @id: @class', [
        '@id' => (int) $row->account_id,
        '@class' => get_class($e),
      ]);
      return $this->error('The server could not save this phone. Check the Windows account enrollment and try again.', 500);
    }

    $machine = $this->store->machine($account->machine_id);
    return $this->reply([
      'result' => 'ok',
      'credential_id' => $credential_id,
      'username' => (string) $account->username,
      'hostname' => (string) ($machine->hostname ?? ''),
    ]);
  }

  protected function loginResponse(object $row, object $account, array $body, int $timestamp, string $type): JsonResponse {
    $credential_id = is_string($body['credential_id'] ?? NULL) ? $body['credential_id'] : '';
    $action = is_string($body['action'] ?? NULL) ? $body['action'] : '';
    $signature = is_string($body['signature'] ?? NULL) ? $body['signature'] : '';
    if (!preg_match('/^[A-Za-z0-9_-]{32,64}$/', $credential_id) || !in_array($action, ['approve', 'deny'], TRUE)) {
      return $this->error('Invalid approval fields.', 400);
    }
    $phone = $this->store->phoneForAccount($credential_id, (int) $row->account_id);
    if (!$phone) {
      return $this->error('This phone is not enrolled for that Windows account.', 403);
    }

    if ($signature !== '') {
      try {
        $message = $this->protocol->canonical(
          $type,
          (string) $row->request_id,
          (string) $account->machine_id,
          (string) $account->username,
          (string) $row->nonce,
          $timestamp,
          $action,
        );
      }
      catch (\InvalidArgumentException) {
        return $this->error('Invalid PAM login request.', 400);
      }
      if (!$this->protocol->verify((string) $phone->public_key, $message, $signature)) {
        return $this->error('Signature did not verify.', 401);
      }
    }
    elseif ($action !== 'deny' || !is_string($body['nonce'] ?? NULL) || !hash_equals((string) $row->nonce, $body['nonce'])) {
      return $this->error('Only a refusal may be sent without a signature.', 400);
    }

    if (!$this->store->resolveRequest((string) $row->request_id, $action === 'approve' ? 'approved' : 'denied', (int) $phone->id)) {
      return $this->error('This request was already answered or expired.', 409);
    }
    if ($action === 'approve') {
      $this->store->touchPhone((int) $phone->id);
    }
    if ($type === 'login') {
      $machine = $this->store->machine((string) $account->machine_id);
      try {
        $this->store->audit(
          (int) $account->uid,
          $action === 'approve' ? 'phone_login_approved' : 'phone_login_denied',
          'windows_account:' . (int) $account->id,
          [
            'computer' => (string) ($machine->hostname ?? $account->machine_id),
            'username' => (string) $account->username,
            'phone' => (string) $phone->label,
          ],
        );
      }
      catch (\Throwable $e) {
        // An audit-storage issue must not turn a recorded phone decision into
        // an ambiguous failure for the phone or the waiting Windows client.
        \Drupal::logger('thessley_windows_access')->error('Could not record a Windows phone-login decision: @message', [
          '@message' => $e->getMessage(),
        ]);
      }
    }
    return $this->reply(['result' => 'ok']);
  }

}
