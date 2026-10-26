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
      '#markup' => $this->t('Enter the Windows PC address and choose the Drupal identity. Drupal creates a one-time pairing command. Run it in an elevated PowerShell window on that PC; the helper collects its machine ID, account SID hash, and public key and sends them directly to this server. No private key leaves the PC.'),
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
      '#description' => $this->t('Local Windows account name. Domain and UPN accounts are not supported by this prototype.'),
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
      $command = "& 'C:\\ProgramData\\ThessleyPamWin\\thessley-pam-win.cmd' drupal-enroll --user "
        . $ps_quote($pairing['username']) . ' --server ' . $ps_quote($server)
        . ' --tls-sha256 ' . $ps_quote($fingerprint)
        . ' --pair-code ' . $ps_quote($pairing['code']);
      $form['pairing'] = [
        '#type' => 'details',
        '#title' => $this->t('Run this on the Windows PC'),
        '#open' => TRUE,
        '#weight' => -10,
        'summary' => [
          '#type' => 'item',
          '#markup' => $this->t('Target: @user on @ip. This code expires after 10 minutes and is accepted only from that IP.', [
            '@user' => $pairing['username'],
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
    ]);
    $form_state->setRebuild();
  }

}
