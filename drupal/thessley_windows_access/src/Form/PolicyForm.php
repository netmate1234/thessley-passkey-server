<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\user\RoleInterface;
use Drupal\user\UserInterface;

/**
 * Maps Drupal roles to Windows computers and protected resources.
 */
final class PolicyForm extends FormBase {

  public function getFormId(): string {
    return 'thessley_windows_access_policy';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $roles = \Drupal::entityTypeManager()->getStorage('user_role')->loadMultiple();
    $store = \Drupal::service('thessley_windows_access.store');
    $resources = $store->resources();
    $managed_roles = [];
    foreach ($roles as $role_id => $role) {
      if ($role instanceof RoleInterface && !$role->isAdmin() && !in_array((string) $role_id, ['anonymous', 'authenticated'], TRUE)) {
        $managed_roles[$role_id] = $role;
      }
    }

    // Drupal roles are the access groups. Let an administrator manage group
    // membership here without having to open each Drupal user profile.
    $users = [];
    foreach (\Drupal::entityTypeManager()->getStorage('user')->loadByProperties(['status' => 1]) as $user) {
      if (!$user instanceof UserInterface || (int) $user->id() <= 1 || in_array('administrator', $user->getRoles(), TRUE)) {
        continue;
      }
      $users[(int) $user->id()] = $user;
    }
    uasort($users, static fn (UserInterface $a, UserInterface $b): int => strnatcasecmp($a->getAccountName(), $b->getAccountName()));

    $form['#attached']['library'][] = 'thessley_windows_access/admin';
    $form['#attributes']['class'][] = 'thessley-policy-editor';
    $form['intro'] = [
      '#type' => 'item',
      '#markup' => $this->t('Manage people, access groups, and resource rights in one place. Groups are Drupal roles. Drag a person onto a group, or use the checkboxes. Then choose what each group can do on each computer or resource. Changes take effect on the next sign-in check.'),
    ];

    $form['group_memberships'] = [
      '#type' => 'details',
      '#tree' => TRUE,
      '#title' => $this->t('People and access groups'),
      '#open' => TRUE,
      '#attributes' => ['class' => ['thessley-membership-editor']],
      'help' => [
        '#type' => 'item',
        '#markup' => $this->t('Drag a person from the list onto a group to add them. Clear their checkbox to remove them. Drupal administrator accounts are protected and are not listed here.'),
      ],
      'people' => [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-people-pool']],
      ],
    ];
    $form['group_memberships']['people']['title'] = [
      '#type' => 'item',
      '#title' => $this->t('People'),
    ];
    $form['group_memberships']['people']['list'] = [
      '#theme' => 'item_list',
      '#items' => [],
      '#attributes' => ['class' => ['thessley-draggable-people']],
      '#empty' => $this->t('No active Drupal users are available.'),
    ];
    foreach ($users as $uid => $user) {
      $form['group_memberships']['people']['list']['#items'][] = [
        '#type' => 'html_tag',
        '#tag' => 'button',
        '#value' => $user->getAccountName() . ' · ' . $user->getDisplayName(),
        '#attributes' => [
          'type' => 'button',
          'draggable' => 'true',
          'class' => ['thessley-draggable-person'],
          'data-thessley-uid' => (string) $uid,
          'aria-label' => $this->t('Drag @name to an access group', ['@name' => $user->getAccountName()]),
        ],
      ];
    }
    $form['group_memberships']['groups'] = [
      '#type' => 'container',
      '#tree' => TRUE,
      '#attributes' => ['class' => ['thessley-access-groups']],
    ];
    foreach ($managed_roles as $role_id => $role) {
      $members = [];
      foreach ($users as $uid => $user) {
        if (in_array((string) $role_id, $user->getRoles(), TRUE)) {
          $members[] = (string) $uid;
        }
      }
      $form['group_memberships']['groups'][$role_id] = [
        '#type' => 'fieldset',
        '#tree' => TRUE,
        '#title' => $role->label(),
        '#attributes' => [
          'class' => ['thessley-access-group', 'draggable'],
          'data-thessley-role' => (string) $role_id,
        ],
        'members' => [
          '#type' => 'checkboxes',
          '#title' => $this->t('Members'),
          '#title_display' => 'invisible',
          '#options' => array_map(static fn (UserInterface $account): string => $account->getAccountName(), $users),
          '#default_value' => $members,
          '#attributes' => ['class' => ['thessley-group-members']],
          '#empty_value' => [],
          '#description' => $this->t('Drop people here or select them by name.'),
        ],
      ];
    }
    $form['group_memberships']['announcement'] = [
      '#type' => 'html_tag',
      '#tag' => 'div',
      '#attributes' => ['class' => ['visually-hidden'], 'aria-live' => 'polite', 'data-thessley-announcement' => ''],
    ];

    $form['access_rights'] = [
      '#type' => 'details',
      '#tree' => TRUE,
      '#title' => $this->t('Group access to computers and resources'),
      '#open' => TRUE,
      'help' => [
        '#type' => 'item',
        '#markup' => $this->t('Drag a resource right onto a group to grant it, or use the checkboxes. Windows sign-in, local administrator, Remote Desktop, Remote Management, and Event Log Readers are separate rights. Changes take effect on the next sign-in check.'),
      ],
    ];
    $grant_options = [];
    foreach ($resources as $resource) {
      foreach ($this->actionsForResource($resource->type) as $action => $label) {
        $grant_options[(int) $resource->id . ':' . $action] = $resource->label . ' — ' . $label;
      }
    }
    $form['access_rights']['grant_palette'] = [
      '#type' => 'container',
      '#attributes' => ['class' => ['thessley-grant-palette']],
      'title' => [
        '#type' => 'item',
        '#title' => $this->t('Available resource rights'),
      ],
      'items' => [
        '#theme' => 'item_list',
        '#items' => [],
        '#attributes' => ['class' => ['thessley-draggable-grants']],
        '#empty' => $this->t('Add a computer or resource first.'),
      ],
    ];
    foreach ($grant_options as $grant_id => $grant_label) {
      $form['access_rights']['grant_palette']['items']['#items'][] = [
        '#type' => 'html_tag',
        '#tag' => 'button',
        '#value' => $grant_label,
        '#attributes' => [
          'type' => 'button',
          'draggable' => 'true',
          'class' => ['thessley-draggable-grant'],
          'data-thessley-grant' => $grant_id,
          'aria-label' => $this->t('Drag @right onto a group to grant it', ['@right' => $grant_label]),
        ],
      ];
    }
    $form['access_rights']['roles'] = ['#type' => 'container', '#tree' => TRUE];
    foreach ($managed_roles as $role_id => $role) {
      $form['access_rights']['roles'][$role_id] = [
        '#type' => 'details',
        '#tree' => TRUE,
        '#title' => $role->label() . ' (' . $role_id . ')',
        '#open' => $role_id === 'windows_administrators',
        '#attributes' => ['class' => ['thessley-grant-target'], 'data-thessley-grant-role' => (string) $role_id],
      ];
      $form['access_rights']['roles'][$role_id]['grants'] = [
        '#type' => 'checkboxes',
        '#title' => $this->t('Allowed actions'),
        '#options' => $grant_options,
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
    $roles = \Drupal::entityTypeManager()->getStorage('user_role')->loadMultiple();
    $managed_roles = [];
    foreach ($roles as $role_id => $role) {
      if (!$role instanceof RoleInterface || $role->isAdmin() || in_array((string) $role_id, ['anonymous', 'authenticated'], TRUE)) {
        continue;
      }
      $managed_roles[] = (string) $role_id;
    }

    // Preserve administrator and any role not managed by this module. The
    // account list excludes administrator users in buildForm(), and is checked
    // again here rather than trusting posted values.
    $submitted_memberships = $form_state->getValue(['group_memberships', 'groups']) ?? [];
    $user_storage = \Drupal::entityTypeManager()->getStorage('user');
    $store = \Drupal::service('thessley_windows_access.store');
    $actor_uid = (int) $this->currentUser()->id();
    foreach ($user_storage->loadByProperties(['status' => 1]) as $user) {
      if (!$user instanceof UserInterface || (int) $user->id() <= 1 || in_array('administrator', $user->getRoles(), TRUE)) {
        continue;
      }
      $before = $user->getRoles();
      foreach ($managed_roles as $role_id) {
        $values = $submitted_memberships[$role_id]['members'] ?? [];
        $checked = is_array($values) && in_array((string) $user->id(), $values, TRUE);
        if ($checked && !$user->hasRole($role_id)) {
          $user->addRole($role_id);
        }
        elseif (!$checked && $user->hasRole($role_id)) {
          $user->removeRole($role_id);
        }
      }
      if ($user->getRoles() !== $before) {
        $user->save();
        $store->audit($actor_uid, 'user_group_membership_changed', 'uid:' . $user->id(), [
          'account' => $user->getAccountName(),
          'roles_before' => $before,
          'roles_after' => $user->getRoles(),
        ]);
      }
    }

    foreach ($roles as $role_id => $role) {
      if (!$role instanceof RoleInterface || $role->isAdmin() || in_array((string) $role_id, ['anonymous', 'authenticated'], TRUE)) {
        continue;
      }
      $selected = $form_state->getValue(['access_rights', 'roles', $role_id, 'grants']) ?? [];
      $grants = [];
      foreach (array_filter($selected) as $value) {
        if (is_string($value) && preg_match('/^(\d+):([a-z._-]+)$/', $value, $matches)) {
          $grants[] = ['resource_id' => (int) $matches[1], 'action' => $matches[2]];
        }
      }
      $store->replaceRoleGrants(
        (string) $role_id,
        $grants,
        $actor_uid,
      );
    }
    $this->messenger()->addStatus($this->t('Group membership and Windows resource access policy saved and audited.'));
  }

  private function actionsForResource(string $type): array {
    if (in_array($type, ['computer', 'computer_group'], TRUE)) {
      return [
        'windows.login' => $this->t('Windows sign-in'),
        'windows.local_admin' => $this->t('Windows local administrator'),
        'windows.remote_desktop' => $this->t('Remote Desktop Users'),
        'windows.remote_management' => $this->t('Remote Management Users'),
        'windows.event_log_readers' => $this->t('Event Log Readers'),
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
