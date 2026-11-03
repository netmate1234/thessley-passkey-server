<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\user\UserInterface;

/**
 * Starts an IP-bound enrollment from the target Windows PC.
 */
final class EnrollmentForm extends FormBase {

  public function getFormId(): string {
    return 'thessley_windows_access_enrollment';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#attached']['library'][] = 'thessley_windows_access/admin';
    $form['intro'] = [
      '#type' => 'item',
      '#markup' => $this->t('Choose whether this is a local or domain account. The Windows helper identifies it by its SID, not by its display name, then sends its public key directly to Drupal. A one-time command binds enrollment to this PC’s address. The private key stays on the PC.'),
    ];
    $form['client_ip'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Windows PC IP address'),
      '#required' => TRUE,
      '#maxlength' => 45,
      '#default_value' => '',
      '#description' => $this->t('Use the address the PC will connect from. The pairing expires in 10 minutes and only works from this exact IP.'),
    ];
    $form['username'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Windows account name'),
      '#required' => TRUE,
      '#maxlength' => 32,
      '#default_value' => 'sshuser',
      '#description' => $this->t('Enter the account’s short Windows name, such as martin. The SID and account scope distinguish matching names.'),
    ];
    $form['principal_type'] = [
      '#type' => 'select',
      '#title' => $this->t('Account scope'),
      '#options' => ['local' => $this->t('Local account on this PC'), 'domain' => $this->t('Domain account')],
      '#default_value' => 'local',
      '#required' => TRUE,
      '#description' => $this->t('A local martin and DOMAIN\martin are treated as different Windows principals.'),
    ];
    $form['authority'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Domain name'),
      '#maxlength' => 128,
      '#description' => $this->t('Required for a domain account. Use its NetBIOS domain name, for example EXAMPLE.'),
    ];
    $users = \Drupal::entityTypeManager()->getStorage('user')->loadByProperties(['status' => 1]);
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
    ];

    $pairing = $form_state->get('pending_pairing');
    if (is_array($pairing)) {
      $settings = $this->config('thessley_windows_access.settings');
      $server = rtrim((string) $settings->get('public_url'), '/');
      $fingerprint = strtolower((string) $settings->get('tls_sha256'));
      $ps_quote = static fn (string $value): string => "'" . str_replace("'", "''", $value) . "'";
      $command = "& 'C:\\ProgramData\\ThessleyPamWin\\thessley-pam-win.cmd' drupal-enroll-v2 --user "
        . $ps_quote($pairing['username']) . ' --server ' . $ps_quote($server)
        . ' --tls-sha256 ' . $ps_quote($fingerprint)
        . ' --pair-code ' . $ps_quote($pairing['code'])
        . ' --scope ' . $ps_quote($pairing['principal_type']);
      if ($pairing['authority'] !== '') {
        $command .= ' --authority ' . $ps_quote($pairing['authority']);
      }
      $form['pairing'] = [
        '#type' => 'details',
        '#title' => $this->t('Run this on the Windows PC'),
        '#open' => TRUE,
        '#weight' => -10,
        'summary' => [
          '#type' => 'item',
          '#markup' => $this->t('Target: @scope account @user on @ip. This code expires after 10 minutes and is accepted only from that IP.', [
            '@user' => $pairing['username'],
            '@scope' => $pairing['principal_type'] === 'domain' ? $this->t('domain') : $this->t('local'),
            '@ip' => $pairing['client_ip'],
          ]),
        ],
        'code' => [
          '#type' => 'item',
          '#title' => $this->t('One-time pairing code'),
          '#markup' => '<strong>' . htmlspecialchars($pairing['code'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</strong>',
        ],
        'command' => [
          '#type' => 'textarea',
          '#title' => $this->t('Elevated PowerShell command'),
          '#default_value' => $command,
          '#rows' => 3,
          '#attributes' => ['readonly' => 'readonly', 'class' => ['thessley-copy-command']],
          '#description' => $this->t('Copy this complete command into PowerShell opened as Administrator on the target PC. After it registers, the helper displays the phone enrollment QR.'),
        ],
      ];
    }
    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Create PC pairing command'),
      '#button_type' => 'primary',
    ];
    return $form;
  }

  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $ip = trim((string) $form_state->getValue('client_ip'));
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      $form_state->setErrorByName('client_ip', $this->t('Enter the PC’s IPv4 address.'));
    }
    $username = strtolower(trim((string) $form_state->getValue('username')));
    if (!preg_match('/^[a-z_][a-z0-9_.-]{0,31}$/', $username)) {
      $form_state->setErrorByName('username', $this->t('Use a local Windows account name with letters, digits, underscore, dot, or hyphen.'));
    }
    $scope = (string) $form_state->getValue('principal_type');
    if (!in_array($scope, ['local', 'domain'], TRUE)) {
      $form_state->setErrorByName('principal_type', $this->t('Choose a local or domain account.'));
    }
    $authority = strtolower(trim((string) $form_state->getValue('authority')));
    if ($scope === 'domain' && !preg_match('/^[a-z0-9][a-z0-9_.@-]{0,127}$/', $authority)) {
      $form_state->setErrorByName('authority', $this->t('Enter the domain’s NetBIOS name, for example EXAMPLE.'));
    }
    elseif ($scope === 'local' && $authority !== '') {
      $form_state->setErrorByName('authority', $this->t('Leave Domain name blank for a local account.'));
    }
    if (!(int) $form_state->getValue('uid')) {
      $form_state->setErrorByName('uid', $this->t('Choose the Drupal identity that should own this Windows account.'));
    }
    $settings = $this->config('thessley_windows_access.settings');
    if (!preg_match('/^https:\/\//i', (string) $settings->get('public_url'))
      || !preg_match('/^[a-f0-9]{64}$/i', (string) $settings->get('tls_sha256'))) {
      $form_state->setErrorByName('client_ip', $this->t('Configure the PAM HTTPS URL and TLS fingerprint in Windows Access → Server settings first.'));
    }
    parent::validateForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    try {
      $code = \Drupal::service('thessley_windows_access.store')->createPairing(
        trim((string) $form_state->getValue('client_ip')),
        strtolower(trim((string) $form_state->getValue('username'))),
        (int) $form_state->getValue('uid'),
        (string) $form_state->getValue('principal_type'),
        strtolower(trim((string) $form_state->getValue('authority'))),
      );
      \Drupal::service('thessley_windows_access.store')->audit(
        (int) $this->currentUser()->id(),
        'windows_pairing_created',
        trim((string) $form_state->getValue('client_ip')) . ':' . strtolower(trim((string) $form_state->getValue('username'))),
        ['uid' => (int) $form_state->getValue('uid')],
      );
    }
    catch (\Throwable $e) {
      $this->getLogger('thessley_windows_access')->error('Could not create a PC pairing code: @type', ['@type' => get_class($e)]);
      $this->messenger()->addError($this->t('The PC pairing command could not be created. Try again.'));
      return;
    }
    $form_state->set('pending_pairing', [
      'code' => $code,
      'client_ip' => trim((string) $form_state->getValue('client_ip')),
      'username' => strtolower(trim((string) $form_state->getValue('username'))),
      'principal_type' => (string) $form_state->getValue('principal_type'),
      'authority' => strtolower(trim((string) $form_state->getValue('authority'))),
    ]);
    $form_state->setRebuild();
  }

}
