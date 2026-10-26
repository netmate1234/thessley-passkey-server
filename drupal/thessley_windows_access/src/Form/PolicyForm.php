<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\user\RoleInterface;

/**
 * Maps Drupal roles to Windows computers and protected resources.
 */
final class PolicyForm extends FormBase {

  public function getFormId(): string {
    return 'thessley_windows_access_policy';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $roles = $this->entityTypeManager()->getStorage('user_role')->loadMultiple();
    $resources = \Drupal::service('thessley_windows_access.store')->resources();
    $form['intro'] = [
      '#type' => 'item',
      '#markup' => $this->t('Grant access to a Drupal role. Members inherit these rights on matching enrolled resources. Drupal administrators do not automatically become Windows administrators. Computer sign-in and local Windows administrator membership are separate actions.'),
    ];
    $form['roles'] = ['#type' => 'container', '#tree' => TRUE];
    foreach ($roles as $role_id => $role) {
      if (!$role instanceof RoleInterface || $role->isAdmin()) {
        continue;
      }
      $options = [];
      foreach ($resources as $resource) {
        $actions = $this->actionsForResource($resource->type);
        foreach ($actions as $action => $label) {
          $options[(int) $resource->id . ':' . $action] = $resource->label . ' — ' . $label;
        }
      }
      $form['roles'][$role_id] = [
        '#type' => 'details',
        '#title' => $role->label() . ' (' . $role_id . ')',
        '#open' => $role_id === 'windows_administrators',
      ];
      $form['roles'][$role_id]['grants'] = [
        '#type' => 'checkboxes',
        '#title' => $this->t('Allowed actions'),
        '#options' => $options,
        '#default_value' => \Drupal::service('thessley_windows_access.store')->roleGrantValues((string) $role_id),
        '#description' => $this->t('For “All enrolled Windows computers,” sign-in authorizes the mapped Windows account. Local administrator adds that account to the computer’s Windows Administrators group when the endpoint agent is available.'),
      ];
    }
    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save access policy'),
      '#button_type' => 'primary',
    ];
    return $form;
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $roles = $this->entityTypeManager()->getStorage('user_role')->loadMultiple();
    foreach ($roles as $role_id => $role) {
      if (!$role instanceof RoleInterface || $role->isAdmin()) {
        continue;
      }
      $selected = $form_state->getValue(['roles', $role_id, 'grants']) ?? [];
      $grants = [];
      foreach (array_filter($selected) as $value) {
        if (is_string($value) && preg_match('/^(\d+):([a-z._-]+)$/', $value, $matches)) {
          $grants[] = ['resource_id' => (int) $matches[1], 'action' => $matches[2]];
        }
      }
      \Drupal::service('thessley_windows_access.store')->replaceRoleGrants(
        (string) $role_id,
        $grants,
        (int) $this->currentUser()->id(),
      );
    }
    $this->messenger()->addStatus($this->t('Windows resource access policy saved and audited.'));
  }

  private function actionsForResource(string $type): array {
    if (in_array($type, ['computer', 'computer_group'], TRUE)) {
      return [
        'windows.login' => $this->t('Windows sign-in'),
        'windows.local_admin' => $this->t('Windows local administrator'),
      ];
    }
    if ($type === 'vpn') {
      return ['connect' => $this->t('Connect to VPN'), 'download' => $this->t('Download VPN profile')];
    }
    if ($type === 'ssh') {
      return ['connect' => $this->t('Connect with SSH')];
    }
    return ['access' => $this->t('Access resource')];
  }

}
