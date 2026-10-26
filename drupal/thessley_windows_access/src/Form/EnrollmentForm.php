<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;

/**
 * Admin-started first phone enrollment for a Windows account binding.
 *
 * The Windows agent will later start this flow from the sign-in tile. This
 * form provides the first end-to-end enrollment path while that agent API is
 * being built.
 */
final class EnrollmentForm extends FormBase {

  public function getFormId(): string {
    return 'thessley_windows_access_enrollment';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#attached']['library'][] = 'thessley_windows_access/admin';
    $form['intro'] = [
      '#type' => 'item',
      '#markup' => $this->t('Create a test binding for one Windows account on one computer, then add the phone approval key. Windows account names are case-normalized for the current PAM app. Each account on the same computer gets a separate binding.'),
    ];
    $form['machine_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Windows machine ID'),
      '#required' => TRUE,
      '#maxlength' => 32,
      '#description' => $this->t('The 32-character lowercase Thessley machine ID from the Windows agent.'),
    ];
    $form['hostname'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Computer name'),
      '#required' => TRUE,
      '#maxlength' => 64,
    ];
    $form['username'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Windows account name'),
      '#required' => TRUE,
      '#maxlength' => 32,
      '#default_value' => 'sshuser',
      '#description' => $this->t('For the current Android PAM format, use a local account name with letters, digits, underscore, dot, or hyphen. Domain/UPN names need a later protocol update.'),
    ];
    $form['sid_hash'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Windows SID SHA-256'),
      '#required' => TRUE,
      '#maxlength' => 64,
      '#description' => $this->t('SHA-256 of the exact Windows SID, lowercase hex. The raw SID is not stored in Drupal.'),
    ];
    $form['agent_public_key'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Windows account agent public key (Base64 DER)'),
      '#required' => TRUE,
      '#maxlength' => 1024,
      '#description' => $this->t('Paste the public half of the account agent P-256 key. Keep its private key on the Windows computer. This key authenticates challenge and status requests; it is separate from the phone key.'),
    ];
    $users = $this->entityTypeManager()->getStorage('user')->loadByProperties(['status' => 1]);
    $options = [];
    foreach ($users as $user) {
      if ($user instanceof UserInterface && (int) $user->id() > 0) {
        $options[(int) $user->id()] = $user->getAccountName() . ' (uid ' . $user->id() . ')';
      }
    }
    $form['uid'] = [
      '#type' => 'select',
      '#title' => $this->t('Drupal identity to link'),
      '#options' => $options,
      '#empty_option' => $this->t('- Select an active Drupal user -'),
      '#required' => TRUE,
      '#description' => $this->t('For the pilot, select the separate low-privilege Drupal test user named sshuser. Do not give that Drupal user the Windows Administrators role.'),
    ];

    $pending = $form_state->get('pending_enrollment');
    if (is_array($pending)) {
      $form['pending'] = [
        '#type' => 'details',
        '#title' => $this->t('Scan to enroll this phone'),
        '#open' => TRUE,
        '#weight' => -10,
      ];
      $form['pending']['target'] = [
        '#type' => 'item',
        '#title' => $this->t('Target account'),
        '#markup' => '<strong>' . $this->t('@user on @host', ['@user' => $pending['username'], '@host' => $pending['hostname']]) . '</strong>',
      ];
      $form['pending']['qr'] = [
        '#type' => 'container',
        '#attributes' => ['id' => 'thessley-windows-enrollment-qr'],
      ];
      $form['pending']['link'] = [
        '#type' => 'item',
        '#title' => $this->t('Enrollment link'),
        '#markup' => '<code>' . htmlspecialchars($pending['link'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>',
      ];
      $form['pending']['notice'] = [
        '#type' => 'item',
        '#markup' => $this->t('The request expires in five minutes. The phone should add this computer/account to its Computers list after enrollment.'),
      ];
      $form['#attached']['drupalSettings']['thessleyWindowsAccess']['appLink'] = $pending['link'];
    }
    else {
      $form['actions'] = ['#type' => 'actions'];
      $form['actions']['submit'] = [
        '#type' => 'submit',
        '#value' => $this->t('Create enrollment QR'),
        '#button_type' => 'primary',
      ];
    }
    return $form;
  }

  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $machine_id = strtolower(trim((string) $form_state->getValue('machine_id')));
    $hostname = trim((string) $form_state->getValue('hostname'));
    $username = strtolower(trim((string) $form_state->getValue('username')));
    $sid_hash = strtolower(trim((string) $form_state->getValue('sid_hash')));
    $agent_public_key = preg_replace('/\s+/', '', trim((string) $form_state->getValue('agent_public_key')));
    if (!preg_match('/^[a-f0-9]{32}$/', $machine_id)) {
      $form_state->setErrorByName('machine_id', $this->t('Enter a 32-character lowercase hexadecimal machine ID.'));
    }
    if (!preg_match('/^(?=.{1,64}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/', $hostname)) {
      $form_state->setErrorByName('hostname', $this->t('Use a computer name with letters, digits, dots, or hyphens.'));
    }
    if (!preg_match('/^[a-z_][a-z0-9_.-]{0,31}$/', $username)) {
      $form_state->setErrorByName('username', $this->t('The account name is not supported by the current PAM app format.'));
    }
    if (!preg_match('/^[a-f0-9]{64}$/', $sid_hash)) {
      $form_state->setErrorByName('sid_hash', $this->t('Enter a 64-character lowercase SHA-256 hash.'));
    }
    if (!$agent_public_key || !\Drupal::service('thessley_windows_access.pam_protocol')->validPublicKey($agent_public_key)) {
      $form_state->setErrorByName('agent_public_key', $this->t('Enter a Base64 DER P-256 public key. Do not paste a private key.'));
    }
    parent::validateForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $settings = $this->config('thessley_windows_access.settings');
    $base = (string) $settings->get('public_url');
    $fingerprint = strtolower((string) $settings->get('tls_sha256'));
    $parts = parse_url($base);
    if (!$parts || empty($parts['host']) || !preg_match('/^[a-f0-9]{64}$/', $fingerprint)) {
      $this->messenger()->addError($this->t('Set the PAM server URL and TLS fingerprint in Thessley Windows Access settings first.'));
      return;
    }
    $machine_id = strtolower(trim((string) $form_state->getValue('machine_id')));
    $hostname = trim((string) $form_state->getValue('hostname'));
    $username = strtolower(trim((string) $form_state->getValue('username')));
    $uid = (int) $form_state->getValue('uid');
    $transaction = NULL;
    try {
      $transaction = \Drupal::database()->startTransaction();
      $store = \Drupal::service('thessley_windows_access.store');
      $store->createMachine($machine_id, $hostname);
      $account_id = $store->createAccount(
        $machine_id,
        strtolower(trim((string) $form_state->getValue('sid_hash'))),
        $username,
        $username,
        $uid,
        preg_replace('/\s+/', '', trim((string) $form_state->getValue('agent_public_key'))),
      );
      $request = $store->createRequest($account_id, 'enroll', 300);
      unset($transaction);
    }
    catch (\Throwable $e) {
      if ($transaction) {
        $transaction->rollBack();
      }
      $this->getLogger('thessley_windows_access')->warning('Could not create a Windows account enrollment: @type', ['@type' => get_class($e)]);
      $this->messenger()->addError($this->t('That Windows account binding could not be created. Check whether the machine and SID are already enrolled.'));
      return;
    }
    $port = isset($parts['port']) ? (int) $parts['port'] : 443;
    $link = 'thessleypam://enroll?' . http_build_query([
      'h' => $parts['host'],
      'p' => $port,
      'fp' => $fingerprint,
      'id' => $request['request_id'],
      'n' => $request['nonce'],
      'm' => $machine_id,
      'hn' => $hostname,
      'u' => $username,
    ], '', '&', PHP_QUERY_RFC3986);
    $form_state->set('pending_enrollment', [
      'link' => $link,
      'username' => $username,
      'hostname' => $hostname,
    ]);
    $form_state->setRebuild();
  }

}
