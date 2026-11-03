<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Settings for the separate Windows Access module.
 */
final class SettingsForm extends ConfigFormBase {

  protected function getEditableConfigNames(): array {
    return ['thessley_windows_access.settings'];
  }

  public function getFormId(): string {
    return 'thessley_windows_access_settings';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('thessley_windows_access.settings');
    $form['endpoint'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Phone app connection'),
    ];
    $form['endpoint']['public_url'] = [
      '#type' => 'url',
      '#title' => $this->t('PAM server URL'),
      '#default_value' => $config->get('public_url') ?? '',
      '#required' => TRUE,
      '#description' => $this->t('Use the HTTPS address the phone can reach, such as https://192.168.1.200:10443. The current app accepts private IPv4 addresses for computer PAM requests; public server registration will be added with the Android trust update.'),
    ];
    $form['endpoint']['tls_sha256'] = [
      '#type' => 'textfield',
      '#title' => $this->t('TLS certificate SHA-256 fingerprint'),
      '#default_value' => $config->get('tls_sha256') ?? '',
      '#required' => TRUE,
      '#maxlength' => 64,
      '#description' => $this->t('64 hexadecimal characters for the leaf certificate served at the PAM server URL. The phone pins this value from each QR request.'),
    ];

    $form['policy_notice'] = [
      '#type' => 'item',
      '#title' => $this->t('Access policy'),
      '#markup' => $this->t('Drupal roles and their Windows/resource grants are managed on the Groups and resources page. The Windows Administrators role is seeded with global Windows sign-in and local-administrator grants, but local-group enforcement requires the endpoint agent, which is not included in this development slice.'),
    ];

    return parent::buildForm($form, $form_state);
  }

  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $url = trim((string) $form_state->getValue('public_url'));
    $parts = parse_url($url);
    if (!$parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
      || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
      || (isset($parts['path']) && $parts['path'] !== '')) {
      $form_state->setErrorByName('public_url', $this->t('Enter an HTTPS origin only, such as https://192.168.1.200:10443, with no path or credentials.'));
    }
    elseif (!filter_var($parts['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !$this->privateIpv4($parts['host'])) {
      $form_state->setErrorByName('public_url', $this->t('For this first PAM integration, use a private IPv4 address accepted by the current Android app.'));
    }
    $fingerprint = strtolower(trim((string) $form_state->getValue('tls_sha256')));
    if (!preg_match('/^[a-f0-9]{64}$/', $fingerprint)) {
      $form_state->setErrorByName('tls_sha256', $this->t('Enter exactly 64 hexadecimal characters.'));
    }
    parent::validateForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('thessley_windows_access.settings')
      ->set('public_url', rtrim(trim((string) $form_state->getValue('public_url')), '/'))
      ->set('tls_sha256', strtolower(trim((string) $form_state->getValue('tls_sha256'))))
      ->save();
    parent::submitForm($form, $form_state);
  }

  private function privateIpv4(string $host): bool {
    $parts = array_map('intval', explode('.', $host));
    if (count($parts) !== 4 || max($parts) > 255 || min($parts) < 0) {
      return FALSE;
    }
    return $parts[0] === 10
      || ($parts[0] === 172 && $parts[1] >= 16 && $parts[1] <= 31)
      || ($parts[0] === 192 && $parts[1] === 168);
  }

}
